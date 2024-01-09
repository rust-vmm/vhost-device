// VIRTIO CAN Emulation via vhost-user
//
// Copyright 2023-2024 VIRTUAL OPEN SYSTEMS SAS. All Rights Reserved.
//          Timos Ampelikiotis <t.ampelikiotis@virtualopensystems.com>
//
// SPDX-License-Identifier: Apache-2.0 or BSD-3-Clause

use log::{error, info, warn};
use std::any::Any;
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, RwLock};
use std::thread;

use thiserror::Error as ThisError;
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
    #[error("Could not find can devices")]
    CouldNotFindCANDevs,
    #[error("Could not create can controller: {0}")]
    CouldNotCreateCanController(crate::can::Error),
    #[error("Could not create can controller output socket: {0}")]
    FailCreateCanControllerSocket(crate::can::Error),
    #[error("Could not create can backend: {0}")]
    CouldNotCreateBackend(crate::vhu_can::Error),
    #[error("Could not create daemon: {0}")]
    CouldNotCreateDaemon(vhost_user_backend::Error),
    #[error("Fatal error: {0}")]
    ServeFailed(vhost_user_backend::Error),
    #[error("Thread `{0}` panicked")]
    ThreadPanic(String, Box<dyn Any + Send>),
}

#[derive(PartialEq, Debug)]
pub struct VuCanConfig {
    pub socket_path: PathBuf,
    pub socket_count: u32,
    pub can_devices: Vec<String>,
}

impl VuCanConfig {
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

        (0..self.socket_count).map(make_socket_path).collect()
    }
}

/// This is the public API through which an external program starts the
/// vhost-device-can backend server.
pub(crate) fn start_backend_server(socket: PathBuf, can_devs: String) -> Result<()> {
    loop {
        let controller =
            CanController::new(can_devs.clone()).map_err(Error::CouldNotCreateCanController)?;
        let lockable_controller = Arc::new(RwLock::new(controller));
        let vu_can_backend = Arc::new(RwLock::new(
            VhostUserCanBackend::new(lockable_controller.clone())
                .map_err(Error::CouldNotCreateBackend)?,
        ));
        lockable_controller
            .write()
            .unwrap()
            .open_can_socket()
            .map_err(Error::FailCreateCanControllerSocket)?;

        let read_handle = CanController::start_read_thread(lockable_controller.clone());

        let mut daemon = VhostUserDaemon::new(
            String::from("vhost-device-can-backend"),
            vu_can_backend.clone(),
            GuestMemoryAtomic::new(GuestMemoryMmap::new()),
        )
        .map_err(Error::CouldNotCreateDaemon)?;

        // Start the read thread -- need to handle it after termination
        let vring_workers = daemon.get_epoll_handlers();
        vu_can_backend
            .read()
            .unwrap()
            .set_vring_worker(&vring_workers[0]);

        daemon.serve(&socket).map_err(Error::ServeFailed)?;

        // Terminate the thread which reads CAN messages from "can_devs"
        lockable_controller.write().unwrap().exit_read_thread();

        // Wait for read thread to exit
        match read_handle.join() {
            Ok(_) => info!("The read thread returned successfully"),
            Err(e) => warn!("The read thread returned the error: {:?}", e),
        }
    }
}

pub fn start_backend(config: VuCanConfig) -> Result<()> {
    let mut handles = HashMap::new();
    let (senders, receiver) = std::sync::mpsc::channel();

    for (thread_id, (socket, can_devs)) in config
        .generate_socket_paths()
        .into_iter()
        .zip(config.can_devices.iter().cloned())
        .map(|(a, b)| (a, b.to_string()))
        .enumerate()
    {
        println!(
            "thread_id: {}, socket: {:?}, can_devs: {:?}",
            thread_id, socket, can_devs,
        );

        let name = format!("vhu-can-{}", can_devs);
        let sender = senders.clone();
        let handle = thread::Builder::new()
            .name(name.clone())
            .spawn(move || {
                let result =
                    std::panic::catch_unwind(move || start_backend_server(socket, can_devs));

                // Notify the main thread that we are done.
                sender.send(thread_id).unwrap();

                result.map_err(|e| Error::ThreadPanic(name, e))?
            })
            .unwrap();
        handles.insert(thread_id, handle);
    }

    while !handles.is_empty() {
        let thread_id = receiver.recv().unwrap();
        handles
            .remove(&thread_id)
            .unwrap()
            .join()
            .map_err(std::panic::resume_unwind)
            .unwrap()?;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backend::Error::FailCreateCanControllerSocket;
    use crate::can::Error::SocketOpen;
    use crate::CanArgs;
    use assert_matches::assert_matches;

    #[test]
    fn test_can_valid_configuration() {
        let valid_args = CanArgs {
            socket_path: "/tmp/vhost.sock".to_string().into(),
            can_devices: "can0".to_string(),
            socket_count: 1,
        };

        assert_matches!(
            VuCanConfig::try_from(valid_args),
            Err(Error::CouldNotFindCANDevs)
        );
    }

    #[test]
    fn test_can_valid_mult_device_configuration() {
        let valid_args = CanArgs {
            socket_path: "/tmp/vhost.sock".to_string().into(),
            can_devices: "can0 can1".to_string(),
            socket_count: 2,
        };

        assert_matches!(
            VuCanConfig::try_from(valid_args),
            Err(Error::CouldNotFindCANDevs)
        );
    }

    #[test]
    fn test_can_invalid_socket_configuration() {
        let invalid_args = CanArgs {
            socket_path: "/tmp/vhost.sock".to_string().into(),
            can_devices: "can0".to_string(),
            socket_count: 0,
        };

        assert_matches!(
            VuCanConfig::try_from(invalid_args),
            Err(Error::SocketCountInvalid(0))
        );
    }

    #[test]
    fn test_can_invalid_mult_socket_configuration_1() {
        let invalid_args = CanArgs {
            socket_path: "/tmp/vhost.sock".to_string().into(),
            can_devices: "can0".to_string(),
            socket_count: 2,
        };

        assert_matches!(
            VuCanConfig::try_from(invalid_args),
            Err(Error::SocketCountInvalid(2))
        );
    }

    #[test]
    fn test_can_invalid_mult_socket_configuration_2() {
        let invalid_args = CanArgs {
            socket_path: "/tmp/vhost.sock".to_string().into(),
            can_devices: "can0 can1".to_string(),
            socket_count: 1,
        };

        assert_matches!(
            VuCanConfig::try_from(invalid_args),
            Err(Error::SocketCountInvalid(1))
        );
    }

    #[test]
    fn test_can_valid_configuration_start_backend_fail() {
        // Instantiate the struct with the provided values
        let config = VuCanConfig {
            socket_path: PathBuf::from("/tmp/vhost.sock"),
            socket_count: 1,
            can_devices: vec!["can0".to_string()],
        };

        assert_matches!(
            start_backend(config),
            Err(FailCreateCanControllerSocket(SocketOpen))
        );
    }

    #[test]
    fn test_can_valid_configuration_start_backend_server_fail() {
        let socket_path = PathBuf::from("/tmp/vhost.sock");
        let can_devs = "can0".to_string();

        assert_matches!(
            start_backend_server(socket_path, can_devs),
            Err(FailCreateCanControllerSocket(SocketOpen))
        );
    }
}
