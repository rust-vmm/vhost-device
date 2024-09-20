// VIRTIO FOO Emulation via vhost-user
//
// Copyright 2023 Linaro Ltd. All Rights Reserved.
//          Viresh Kumar <viresh.kumar@linaro.org>
//
// SPDX-License-Identifier: Apache-2.0 or BSD-3-Clause

mod vhu_foo;

use log::error;
use std::path::PathBuf;
use std::process::exit;
use std::sync::{Arc, RwLock};
use std::thread::{spawn, JoinHandle};

use clap::Parser;
use thiserror::Error as ThisError;
use vhost_user_backend::VhostUserDaemon;
use vm_memory::{GuestMemoryAtomic, GuestMemoryMmap};

use vhu_foo::VhostUserFooBackend;

type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, ThisError)]
/// Errors related to low level foo helpers
pub(crate) enum Error {
    #[error("Could not create backend: {0}")]
    CouldNotCreateBackend(vhu_foo::Error),
    #[error("Could not create daemon: {0}")]
    CouldNotCreateDaemon(vhost_user_backend::Error),
    #[error("Fatal error: {0}")]
    ServeFailed(vhost_user_backend::Error),
}

#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
struct FooArgs {
    /// Location of vhost-user Unix domain socket.
    #[clap(short, long, value_name = "SOCKET")]
    socket_path: PathBuf,
}

#[derive(PartialEq, Debug)]
struct FooConfiguration {
    socket_path: PathBuf,
}

impl TryFrom<FooArgs> for FooConfiguration {
    type Error = Error;

    fn try_from(args: FooArgs) -> Result<Self> {
        // Even though this try_from() conversion always succeeds, in cases where the device's
        // configuration type needs to validate arguments and/or make operations that can fail a
        // TryFrom<_> implementation will be necessary.
        Ok(Self {
            socket_path: args.socket_path,
        })
    }
}

#[derive(Copy, Clone)]
pub(crate) struct FooInfo {
    counter: u32,
}

impl FooInfo {
    pub const fn new() -> Self {
        Self { counter: 0 }
    }

    pub fn counter(&mut self) -> u32 {
        self.counter += 1;
        self.counter
    }
}

fn start_backend(args: FooArgs) -> Result<()> {
    let config = FooConfiguration::try_from(args).unwrap();

    let socket_path = config.socket_path;
    let info = FooInfo::new();

    let handle: JoinHandle<Result<()>> = spawn(move || loop {
        // There isn't much value in complicating code here to return an error from the threads,
        // and so the code uses unwrap() instead. The panic on a thread won't cause trouble to the
        // main() function and should be safe for the daemon.
        let backend = Arc::new(RwLock::new(
            VhostUserFooBackend::new(info).map_err(Error::CouldNotCreateBackend)?,
        ));

        let mut daemon = VhostUserDaemon::new(
            String::from("vhost-device-template-backend"),
            backend,
            GuestMemoryAtomic::new(GuestMemoryMmap::new()),
        )
        .map_err(Error::CouldNotCreateDaemon)?;

        daemon.serve(&socket_path).map_err(Error::ServeFailed)?;
    });

    handle.join().map_err(std::panic::resume_unwind).unwrap()
}

fn main() {
    env_logger::init();

    if let Err(e) = start_backend(FooArgs::parse()) {
        error!("{e}");
        exit(1);
    }
}

#[cfg(test)]
mod tests {
    use assert_matches::assert_matches;
    use std::path::Path;

    use super::*;

    impl FooArgs {
        pub(crate) fn from_args(path: &Path) -> Self {
            Self {
                socket_path: path.to_path_buf(),
            }
        }
    }

    #[test]
    fn test_parse_successful() {
        let socket_name = Path::new("vfoo.sock");

        let cmd_args = FooArgs::from_args(socket_name);
        let config = FooConfiguration::try_from(cmd_args).unwrap();

        let expected_config = FooConfiguration {
            socket_path: socket_name.into(),
        };

        assert_eq!(config, expected_config);
    }

    #[test]
    fn test_fail_listener() {
        // This will fail the listeners and thread will panic.
        let socket_name = Path::new("~/path/not/present/foo");
        let cmd_args = FooArgs::from_args(socket_name);

        assert_matches!(start_backend(cmd_args).unwrap_err(), Error::ServeFailed(_));
    }
}
