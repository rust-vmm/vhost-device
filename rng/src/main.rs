//
// Copyright 2022 Linaro Ltd. All Rights Reserved.
// Mathieu Poirier <mathieu.poirier@linaro.org>
//
// SPDX-License-Identifier: Apache-2.0
mod vhu_rng;

use log::{info, warn};
use std::convert::TryFrom;
use std::fs::File;
use std::sync::{Arc, Mutex, RwLock};
use std::thread;

use clap::Parser;
use thiserror::Error as ThisError;
use vhost::{vhost_user, vhost_user::Listener};
use vhost_user_backend::VhostUserDaemon;
use vm_memory::{GuestMemoryAtomic, GuestMemoryMmap};

use vhu_rng::VuRngBackend;

// Chosen to replicate the max period found in QEMU's vhost-user-rng
// and virtio-rng implementations.
const VHU_RNG_MAX_PERIOD_MS: u128 = 65536;

type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, PartialEq, ThisError)]
/// Errors related to vhost-device-rng daemon.
pub enum Error {
    #[error("RNG source file doesn't exists or can't be accessed")]
    AccessRngSourceFile,
    #[error("Period is too big: {0}")]
    InvalidPeriodInput(u128),
    #[error("Wrong socket count: {0}")]
    InvalidSocketCount(u32),
    #[error("Threads can't be joined")]
    FailedJoiningThreads,
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
    #[clap(short, long)]
    socket_path: String,

    // Where to get the RNG data from. Defaults to /dev/urandom.
    #[clap(short = 'f', long, default_value = "/dev/urandom")]
    rng_source: String,
}

#[derive(Clone, Debug, PartialEq)]
pub struct VuRngConfig {
    pub period_ms: u128,
    pub max_bytes: usize,
    pub count: u32,
    pub socket_path: String,
    pub rng_source: String,
}

impl TryFrom<RngArgs> for VuRngConfig {
    type Error = Error;

    fn try_from(args: RngArgs) -> Result<Self> {
        if args.period == 0 || args.period > VHU_RNG_MAX_PERIOD_MS {
            return Err(Error::InvalidPeriodInput(args.period));
        }

        if args.socket_count == 0 {
            return Err(Error::InvalidSocketCount(args.socket_count));
        }

        // Divide available bandwidth by the number of threads in order
        // to avoid overwhelming the HW.
        let max_bytes = args.max_bytes / args.socket_count as usize;

        Ok(VuRngConfig {
            period_ms: args.period,
            max_bytes,
            count: args.socket_count,
            socket_path: args.socket_path,
            rng_source: args.rng_source,
        })
    }
}

pub fn start_backend(config: VuRngConfig) -> Result<()> {
    let mut handles = Vec::new();
    let random_file = Arc::new(Mutex::new(
        File::open(&config.rng_source).map_err(|_| Error::AccessRngSourceFile)?,
    ));

    for i in 0..config.count {
        let socket = format!("{}{}", config.socket_path.to_owned(), i);
        let period_ms = config.period_ms;
        let max_bytes = config.max_bytes;
        let random = Arc::clone(&random_file);

        let handle = thread::spawn(move || loop {
            // If creating the VuRngBackend isn't successull there isn't much else to do than
            // killing the thread, which .unwrap() does.  When that happens an error code is
            // generated and displayed by the runtime mechanic.  Killing a thread doesn't affect
            // the other threads spun-off by the daemon.
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
                    info!("Stopping cleanly.");
                }
                Err(vhost_user_backend::Error::HandleRequest(
                    vhost_user::Error::PartialMessage,
                )) => {
                    info!("vhost-user connection closed with partial message. If the VM is shutting down, this is expected behavior; otherwise, it might be a bug.");
                }
                Err(e) => {
                    warn!("Error running daemon: {:?}", e);
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
    env_logger::init();

    start_backend(VuRngConfig::try_from(RngArgs::parse()).unwrap())
}

