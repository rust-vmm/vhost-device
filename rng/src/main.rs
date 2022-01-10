//
// Copyright 2022 Linaro Ltd. All Rights Reserved.
// Mathieu Poirier <mathieu.poirier@linaro.org>
//
// SPDX-License-Identifier: Apache-2.0
mod vhu_rng;

use clap::{load_yaml, App};
use std::fs::File;
use std::path::Path;
use std::sync::{Arc, Mutex, RwLock};
use std::thread;
use thiserror::Error as ThisError;
use vhost::{vhost_user, vhost_user::Listener};
use vhost_user_backend::VhostUserDaemon;
use vhu_rng::VuRngBackend;
use vm_memory::{GuestMemoryAtomic, GuestMemoryMmap};

// Chosen to replicate the max period found in QEMU's vhost-user-rng
// and virtio-rng implementations.
const VHU_RNG_MAX_PERIOD_MS: u128 = 65536;

type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, PartialEq, ThisError)]
/// Errors related to vhost-device-rng daemon.
pub enum Error {
    #[error("RNG source file doesn't exists or can't be accessed")]
    AccessRngSourceFile,
    #[error("Max byte input can't be parsed")]
    InvalidMaxByteInput,
    #[error("Period malformed")]
    InvalidPeriodFormat,
    #[error("Period is too big")]
    InvalidPeriodInput,
    #[error("Socket path can't be found")]
    InvalidSocketPath,
    #[error("Wrong socket count")]
    InvalidSocketCount,
    #[error("Socket input can't be parsed")]
    InvalidSocketInput,
    #[error("Threads can't be joined")]
    FailedJoiningThreads,
}

#[derive(Debug)]
pub struct VuRngConfig {
    pub period_ms: u128,
    pub max_bytes: usize,
    pub count: u32,
    pub socket_path: String,
    pub rng_source: String,
}

pub fn parse_cmd_line(cmd_args: clap::ArgMatches) -> Result<VuRngConfig> {
    let socket_path = match cmd_args.value_of("socket_path") {
        Some(path) => path.to_string(),
        None => {
            return Err(Error::InvalidSocketPath);
        }
    };

    let count = cmd_args
        .value_of("socket_count")
        .unwrap_or("1")
        .parse::<u32>()
        .map_err(|_| Error::InvalidSocketInput)?;

    if count == 0 {
        return Err(Error::InvalidSocketCount);
    }

    let rng_source = match cmd_args.value_of("rng_source") {
        Some(source) => {
            if Path::new(source).is_file() {
                source.to_string()
            } else {
                return Err(Error::AccessRngSourceFile);
            }
        }
        None => "/dev/urandom".to_string(),
    };

    let period_ms: u128 = match cmd_args.value_of("period") {
        Some(period_ms) => match period_ms.parse::<u128>() {
            Ok(value) => {
                if value > (VHU_RNG_MAX_PERIOD_MS) {
                    return Err(Error::InvalidPeriodInput);
                }
                value
            }
            Err(_) => {
                return Err(Error::InvalidPeriodFormat);
            }
        },
        None => VHU_RNG_MAX_PERIOD_MS,
    };

    let mut max_bytes: usize = match cmd_args.value_of("max_bytes") {
        Some(max_bytes) => match max_bytes.parse::<usize>() {
            // No point in checking for a maximum value like above,
            // the library parsing code will do that for us.
            Ok(value) => value,
            Err(_) => {
                return Err(Error::InvalidMaxByteInput);
            }
        },
        None => usize::MAX,
    };

    // Divide available bandwidth by the number of threads in order
    // to avoid overwhelming the HW.
    max_bytes /= count as usize;

    Ok(VuRngConfig {
        period_ms,
        max_bytes,
        count,
        socket_path,
        rng_source,
    })
}

pub fn start_backend(config: VuRngConfig) -> Result<()> {
    let mut handles = Vec::new();
    let random_file = Arc::new(Mutex::new(File::open(&config.rng_source).unwrap()));

    for i in 0..config.count {
        let socket_path = config.socket_path.clone();
        let socket = format!("{}{}", socket_path, i.to_string());
        let period_ms = config.period_ms;
        let max_bytes = config.max_bytes;
        let random = Arc::clone(&random_file);

        let handle = thread::spawn(move || loop {
            let vu_rng_backend = Arc::new(RwLock::new(
                VuRngBackend::new(random.clone(), period_ms, max_bytes).unwrap(),
            ));

            let mut daemon = VhostUserDaemon::new(
                String::from("vhost-user-RNG-daemon"),
                vu_rng_backend.clone(),
                GuestMemoryAtomic::new(GuestMemoryMmap::new()),
            )
            .unwrap();

            let listener = Listener::new(socket.clone(), true).unwrap();
            daemon.start(listener).unwrap();

            match daemon.wait() {
                Ok(()) => {
                    println!("Stopping cleanly.");
                }
                Err(vhost_user_backend::Error::HandleRequest(
                    vhost_user::Error::PartialMessage,
                )) => {
                    println!("vhost-user connection closed with partial message. If the VM is shutting down, this is expected behavior; otherwise, it might be a bug.");
                }
                Err(e) => {
                    println!("Error running daemon: {:?}", e);
                }
            }

            // No matter the result, we need to shut down the worker thread.
            vu_rng_backend
                .read()
                .unwrap()
                .exit_event
                .write(1)
                .expect("Shutting down worker thread");
        });

        handles.push(handle);
    }

    for handle in handles {
        handle.join().map_err(|_| Error::FailedJoiningThreads)?;
    }

    Ok(())
}

fn main() -> Result<()> {
    let yaml = load_yaml!("cli.yaml");
    let cmd_args = App::from(yaml).get_matches();

    start_backend(parse_cmd_line(cmd_args).unwrap())
}
