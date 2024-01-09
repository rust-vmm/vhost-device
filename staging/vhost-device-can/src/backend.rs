// VIRTIO CAN Emulation via vhost-user
//
// Copyright 2023 VIRTUAL OPEN SYSTEMS SAS. All Rights Reserved.
//          Timos Ampelikiotis <t.ampelikiotis@virtualopensystems.com>
//
// SPDX-License-Identifier: Apache-2.0 or BSD-3-Clause

use log::{error, info, warn};
use std::process::exit;
use std::sync::{Arc, RwLock};
use std::thread::{spawn, JoinHandle};

use clap::Parser;
use thiserror::Error as ThisError;
use vhost::{vhost_user, vhost_user::Listener};
use vhost_user_backend::VhostUserDaemon;
use vm_memory::{GuestMemoryAtomic, GuestMemoryMmap};

use crate::can::CanController;
use crate::vhu_can::VhostUserCanBackend;

pub(crate) type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, ThisError)]
/// Errors related to low level CAN helpers
pub(crate) enum Error {
    #[error("Invalid socket count: {0}")]
    SocketCountInvalid(usize),
    #[error("Failed to join threads")]
    FailedJoiningThreads,
    #[error("Could not create can controller: {0}")]
    CouldNotCreateCanController(crate::can::Error),
    #[error("Could not create can controller output socket: {0}")]
    FailCreateCanControllerSocket(crate::can::Error),
    #[error("Could not create can backend: {0}")]
    CouldNotCreateBackend(crate::vhu_can::Error),
    #[error("Could not create daemon: {0}")]
    CouldNotCreateDaemon(vhost_user_backend::Error),
}

#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
struct CanArgs {
    /// Location of vhost-user Unix domain socket. This is suffixed by 0,1,2..socket_count-1.
    #[clap(short, long)]
    socket_path: String,

    /// A can device name to be used for reading (ex. vcan, can0, can1, ... etc.)
    #[clap(short = 'i', long)]
    can_in: String,

    /// A can device name to be used for writing (ex. vcan, can0, can1, ... etc.)
    #[clap(short = 'o', long)]
    can_out: String,

    /// Number of guests (sockets) to connect to.
    #[clap(short = 'c', long, default_value_t = 1)]
    socket_count: u32,
}

#[derive(PartialEq, Debug)]
struct CanConfiguration {
    socket_path: String,
    socket_count: u32,
    can_in: String,
    can_out: String,
}

impl TryFrom<CanArgs> for CanConfiguration {
    type Error = Error;

    fn try_from(args: CanArgs) -> Result<Self> {
        if args.socket_count == 0 {
            return Err(Error::SocketCountInvalid(0));
        }

        let can_in = args.can_in.trim().to_string();
        let can_out = args.can_out.trim().to_string();

        Ok(CanConfiguration {
            socket_path: args.socket_path,
            socket_count: args.socket_count,
            can_in,
            can_out,
        })
    }
}

fn start_backend(args: CanArgs) -> Result<()> {
    let config = CanConfiguration::try_from(args).unwrap();
    let mut handles = Vec::new();

    for _ in 0..config.socket_count {
        let socket = config.socket_path.to_owned();
        let can_in = config.can_in.to_owned();
        let can_out = config.can_out.to_owned();

        let handle: JoinHandle<Result<()>> = spawn(move || loop {
            // A separate thread is spawned for each socket and can connect to a separate guest.
            // These are run in an infinite loop to not require the daemon to be restarted once a
            // guest exits.
            //
            // There isn't much value in complicating code here to return an error from the
            // threads, and so the code uses unwrap() instead. The panic on a thread won't cause
            // trouble to other threads/guests or the main() function and should be safe for the
            // daemon.

            let controller = CanController::new(can_in.clone(), can_out.clone())
                .map_err(Error::CouldNotCreateCanController)?;
            let lockable_controller = Arc::new(RwLock::new(controller));
            let vu_can_backend = Arc::new(RwLock::new(
                VhostUserCanBackend::new(lockable_controller.clone())
                    .map_err(Error::CouldNotCreateBackend)?,
            ));
            lockable_controller
                .write()
                .unwrap()
                .open_can_out_socket()
                .map_err(Error::FailCreateCanControllerSocket)?;

            let read_handle = CanController::start_read_thread(lockable_controller.clone());

            let mut daemon = VhostUserDaemon::new(
                String::from("vhost-device-can-backend"),
                vu_can_backend.clone(),
                GuestMemoryAtomic::new(GuestMemoryMmap::new()),
            )
            .map_err(Error::CouldNotCreateDaemon)?;

            /* Start the read thread -- need to handle it after termination */
            let vring_workers = daemon.get_epoll_handlers();
            vu_can_backend
                .read()
                .unwrap()
                .set_vring_worker(&vring_workers[0]);

            let listener = Listener::new(socket.clone(), true).unwrap();
            daemon.start(listener).unwrap();

            match daemon.wait() {
                Ok(()) => {
                    info!("Stopping cleanly.");
                }
                Err(vhost_user_backend::Error::HandleRequest(
                    vhost_user::Error::PartialMessage | vhost_user::Error::Disconnected,
                )) => {
                    info!("vhost-user connection closed with partial message. If the VM is shutting down, this is expected behavior; otherwise, it might be a bug.");
                }
                Err(e) => {
                    warn!("Error running daemon: {:?}", e);
                }
            }

            // No matter the result, we need to shut down the worker thread.
            vu_can_backend.read().unwrap().exit_event.write(1).unwrap();

            // Terminate the thread which reads CAN messages from "can_in"
            lockable_controller.write().unwrap().exit_read_thread();

            // Wait for read thread to exit
            match read_handle.join() {
                Ok(_) => info!("The read thread returned successfully"),
                Err(e) => warn!("The read thread returned the error: {:?}", e),
            }
        });

        handles.push(handle);
    }

    for handle in handles {
        handle.join().map_err(|_| Error::FailedJoiningThreads)??;
    }

    Ok(())
}

pub(crate) fn can_init() {
    env_logger::init();
    if let Err(e) = start_backend(CanArgs::parse()) {
        error!("{e}");
        exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_can_configuration_try_from() {
        // Test valid configuration
        let valid_args = CanArgs {
            socket_path: "/tmp/vhost.sock".to_string(),
            can_in: "vcan0".to_string(),
            can_out: "vcan1".to_string(),
            socket_count: 1,
        };

        let result = CanConfiguration::try_from(valid_args);
        assert!(result.is_ok());

        let config = result.unwrap();
        assert_eq!(config.socket_path, "/tmp/vhost.sock");
        assert_eq!(config.can_in, "vcan0");
        assert_eq!(config.can_out, "vcan1");
        assert_eq!(config.socket_count, 1);

        // Test invalid socket count
        let invalid_args = CanArgs {
            socket_path: "/tmp/vhost.sock".to_string(),
            can_in: "vcan0".to_string(),
            can_out: "vcan1".to_string(),
            socket_count: 0,
        };

        let result = CanConfiguration::try_from(invalid_args);
        assert!(result.is_err());
    }
}
