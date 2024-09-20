//
// Copyright 2022 Linaro Ltd. All Rights Reserved.
// Mathieu Poirier <mathieu.poirier@linaro.org>
//
// SPDX-License-Identifier: Apache-2.0 or BSD-3-Clause
mod vhu_rng;

use log::error;
use std::fs::File;
use std::path::PathBuf;
use std::process::exit;
use std::sync::{Arc, Mutex, RwLock};
use std::thread::{self, JoinHandle};

use clap::Parser;
use thiserror::Error as ThisError;
use vhost_user_backend::VhostUserDaemon;
use vm_memory::{GuestMemoryAtomic, GuestMemoryMmap};

use vhu_rng::VuRngBackend;

// Chosen to replicate the max period found in QEMU's vhost-user-rng
// and virtio-rng implementations.
const VHU_RNG_MAX_PERIOD_MS: u128 = 65536;

type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, ThisError)]
/// Errors related to vhost-device-rng daemon.
pub(crate) enum Error {
    #[error("RNG source file doesn't exists or can't be accessed")]
    AccessRngSourceFile,
    #[error("Period is too big: {0}")]
    InvalidPeriodInput(u128),
    #[error("Wrong socket count: {0}")]
    InvalidSocketCount(u32),
    #[error("Could not create backend: {0}")]
    CouldNotCreateBackend(std::io::Error),
    #[error("Could not create daemon: {0}")]
    CouldNotCreateDaemon(vhost_user_backend::Error),
    #[error("Fatal error: {0}")]
    ServeFailed(vhost_user_backend::Error),
}

#[derive(Clone, Parser, Debug, PartialEq)]
#[clap(author, version, about, long_about = None)]
struct RngArgs {
    // Time needed (in ms) to transfer max-bytes amount of byte.
    #[clap(short, long, default_value_t = VHU_RNG_MAX_PERIOD_MS)]
    period: u128,

    // Maximum amount of byte that can be transferred in a period.
    #[clap(short, long, default_value_t = usize::MAX)]
    max_bytes: usize,

    // Number of guests (sockets) to connect to.
    #[clap(short = 'c', long, default_value_t = 1)]
    socket_count: u32,

    // Location of vhost-user Unix domain socket. This is suffixed by 0,1,2..socket_count-1.
    #[clap(short, long, value_name = "SOCKET")]
    socket_path: PathBuf,

    // Where to get the RNG data from. Defaults to /dev/urandom.
    #[clap(short = 'f', long, default_value = "/dev/urandom")]
    rng_source: PathBuf,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct VuRngConfig {
    pub period_ms: u128,
    pub max_bytes: usize,
    pub count: u32,
    pub socket_path: PathBuf,
    pub rng_source: PathBuf,
}

impl TryFrom<RngArgs> for VuRngConfig {
    type Error = Error;

    fn try_from(args: RngArgs) -> Result<Self> {
        let RngArgs {
            period,
            max_bytes,
            socket_count,
            socket_path,
            rng_source,
        } = args;

        if period == 0 || period > VHU_RNG_MAX_PERIOD_MS {
            return Err(Error::InvalidPeriodInput(period));
        }

        if socket_count == 0 {
            return Err(Error::InvalidSocketCount(socket_count));
        }

        // Divide available bandwidth by the number of threads in order
        // to avoid overwhelming the HW.
        let max_bytes = max_bytes / socket_count as usize;

        Ok(Self {
            period_ms: period,
            max_bytes,
            count: socket_count,
            socket_path,
            rng_source,
        })
    }
}

impl VuRngConfig {
    pub fn generate_socket_paths(&self) -> Vec<PathBuf> {
        let socket_file_name = self
            .socket_path
            .file_name()
            .expect("socket_path has no filename.");
        let socket_file_parent = self
            .socket_path
            .parent()
            .expect("socket_path has no parent directory.");

        let make_socket_path = |i: u32| -> PathBuf {
            let mut file_name = socket_file_name.to_os_string();
            file_name.push(std::ffi::OsStr::new(&i.to_string()));
            socket_file_parent.join(&file_name)
        };
        (0..self.count).map(make_socket_path).collect()
    }
}

pub(crate) fn start_backend(config: VuRngConfig) -> Result<()> {
    let mut handles = Vec::new();
    let file = File::open(&config.rng_source).map_err(|_| Error::AccessRngSourceFile)?;
    let random_file = Arc::new(Mutex::new(file));
    for socket in config.generate_socket_paths() {
        let period_ms = config.period_ms;
        let max_bytes = config.max_bytes;
        let random = Arc::clone(&random_file);

        let handle: JoinHandle<Result<()>> = thread::spawn(move || loop {
            // If creating the VuRngBackend isn't successull there isn't much else to do than
            // killing the thread, which .unwrap() does.  When that happens an error code is
            // generated and displayed by the runtime mechanic.  Killing a thread doesn't affect
            // the other threads spun-off by the daemon.
            let vu_rng_backend = Arc::new(RwLock::new(
                VuRngBackend::new(random.clone(), period_ms, max_bytes)
                    .map_err(Error::CouldNotCreateBackend)?,
            ));

            let mut daemon = VhostUserDaemon::new(
                String::from("vhost-device-rng-backend"),
                Arc::clone(&vu_rng_backend),
                GuestMemoryAtomic::new(GuestMemoryMmap::new()),
            )
            .map_err(Error::CouldNotCreateDaemon)?;

            daemon.serve(&socket).map_err(Error::ServeFailed)?;
        });

        handles.push(handle);
    }

    for handle in handles {
        handle.join().map_err(std::panic::resume_unwind).unwrap()?;
    }

    Ok(())
}

fn main() {
    env_logger::init();

    if let Err(e) = VuRngConfig::try_from(RngArgs::parse()).and_then(start_backend) {
        error!("{e}");
        exit(1);
    }
}

#[cfg(test)]
mod tests {
    use assert_matches::assert_matches;
    use std::path::Path;
    use tempfile::tempdir;

    use super::*;

    #[test]
    fn verify_cmd_line_arguments() {
        // All parameters have default values, except for the socket path.
        let default_args: RngArgs = Parser::parse_from(["", "-s", "/some/socket_path"]);

        // A valid configuration that should be equal to the above default configuration.
        let args = RngArgs {
            period: VHU_RNG_MAX_PERIOD_MS,
            max_bytes: usize::MAX,
            socket_count: 1,
            socket_path: "/some/socket_path".into(),
            rng_source: "/dev/urandom".into(),
        };

        // All configuration elements should be what we expect them to be.
        assert_eq!(
            VuRngConfig::try_from(default_args).unwrap(),
            VuRngConfig::try_from(args.clone()).unwrap()
        );

        // Socket paths are what we expect them to be.
        assert_eq!(
            VuRngConfig::try_from(args.clone())
                .unwrap()
                .generate_socket_paths(),
            vec![Path::new("/some/socket_path0").to_path_buf()]
        );

        let mut many_socket_count_args = args.clone();
        many_socket_count_args.socket_count = 3;

        assert_eq!(
            VuRngConfig::try_from(many_socket_count_args)
                .unwrap()
                .generate_socket_paths(),
            vec![
                Path::new("/some/socket_path0").to_path_buf(),
                Path::new("/some/socket_path1").to_path_buf(),
                Path::new("/some/socket_path2").to_path_buf(),
            ]
        );

        // Setting a invalid period should trigger an InvalidPeriodInput error.
        let mut invalid_period_args = args.clone();
        invalid_period_args.period = VHU_RNG_MAX_PERIOD_MS + 1;
        assert_matches!(
            VuRngConfig::try_from(invalid_period_args),
            Err(Error::InvalidPeriodInput(p)) if p == VHU_RNG_MAX_PERIOD_MS + 1
        );

        // Setting the socket count to 0 should trigger an InvalidSocketCount error.
        let mut invalid_socket_count_args = args;
        invalid_socket_count_args.socket_count = 0;
        assert_matches!(
            VuRngConfig::try_from(invalid_socket_count_args),
            Err(Error::InvalidSocketCount(0))
        );
    }

    #[test]
    fn verify_start_backend() {
        let dir = tempdir().unwrap();
        let random_path = dir.path().join("urandom");
        let _random_file = File::create(random_path.clone());

        let mut config = VuRngConfig {
            period_ms: 1000,
            max_bytes: 512,
            count: 1,
            socket_path: "/invalid/path".into(),
            rng_source: "/invalid/path".into(),
        };

        // An invalid RNG source file should trigger an AccessRngSourceFile error.
        assert_matches!(
            start_backend(config.clone()).unwrap_err(),
            Error::AccessRngSourceFile
        );

        // Set the RNG source to something valid, forcing the code to check the validity
        // of the socket file.  Since the latter is invalid, serving will throw
        // an error, forcing the thread to exit and the call to handle.join()
        // to fail.
        config.rng_source = random_path;
        assert_matches!(start_backend(config).unwrap_err(), Error::ServeFailed(_));
    }
}
