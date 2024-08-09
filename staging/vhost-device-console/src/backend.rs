// VIRTIO CONSOLE Emulation via vhost-user
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
use std::thread::Builder;

use thiserror::Error as ThisError;
use vhost_user_backend::VhostUserDaemon;
use vm_memory::{GuestMemoryAtomic, GuestMemoryMmap};

use crate::console::{BackendType, ConsoleController};
use crate::vhu_console::VhostUserConsoleBackend;

pub(crate) type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, ThisError)]
/// Errors related to low level Console helpers
pub(crate) enum Error {
    #[error("Invalid socket count: {0}")]
    SocketCountInvalid(usize),
    #[error("Could not create console backend: {0}")]
    CouldNotCreateBackend(crate::vhu_console::Error),
    #[error("Could not create daemon: {0}")]
    CouldNotCreateDaemon(vhost_user_backend::Error),
    #[error("Fatal error: {0}")]
    ServeFailed(vhost_user_backend::Error),
    #[error("Thread `{0}` panicked")]
    ThreadPanic(String, Box<dyn Any + Send>),
    #[error("Error using multiple sockets with Nested backend")]
    WrongBackendSocket,
}

#[derive(PartialEq, Debug)]
pub struct VuConsoleConfig {
    pub(crate) socket_path: PathBuf,
    pub(crate) backend: BackendType,
    pub(crate) tcp_port: String,
    pub(crate) socket_count: u32,
}

impl VuConsoleConfig {
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

    pub fn generate_tcp_addrs(&self) -> Vec<String> {
        let tcp_port_base = self.tcp_port.clone();

        let make_tcp_port = |i: u32| -> String {
            let port_num: u32 = tcp_port_base.clone().parse().unwrap();
            "127.0.0.1:".to_owned() + &(port_num + i).to_string()
        };

        (0..self.socket_count).map(make_tcp_port).collect()
    }
}

// This is the public API through which an external program starts the
/// vhost-device-console backend server.
pub(crate) fn start_backend_server(
    socket: PathBuf,
    tcp_addr: String,
    backend: BackendType,
) -> Result<()> {
    loop {
        let controller = ConsoleController::new(backend);
        let arc_controller = Arc::new(RwLock::new(controller));
        let vu_console_backend = Arc::new(RwLock::new(
            VhostUserConsoleBackend::new(arc_controller).map_err(Error::CouldNotCreateBackend)?,
        ));

        let mut daemon = VhostUserDaemon::new(
            String::from("vhost-device-console-backend"),
            vu_console_backend.clone(),
            GuestMemoryAtomic::new(GuestMemoryMmap::new()),
        )
        .map_err(Error::CouldNotCreateDaemon)?;

        let vring_workers = daemon.get_epoll_handlers();
        vu_console_backend
            .read()
            .unwrap()
            .set_vring_worker(&vring_workers[0]);

        // Start the corresponding console thread
        let read_handle = if backend == BackendType::Nested {
            VhostUserConsoleBackend::start_console_thread(&vu_console_backend)
        } else {
            VhostUserConsoleBackend::start_tcp_console_thread(&vu_console_backend, tcp_addr.clone())
        };

        daemon.serve(&socket).map_err(Error::ServeFailed)?;

        // Kill console input thread
        vu_console_backend.read().unwrap().kill_console_thread();

        // Wait for read thread to exit
        match read_handle.join() {
            Ok(_) => info!("The read thread returned successfully"),
            Err(e) => warn!("The read thread returned the error: {:?}", e),
        }
    }
}

pub fn start_backend(config: VuConsoleConfig) -> Result<()> {
    let mut handles = HashMap::new();
    let (senders, receiver) = std::sync::mpsc::channel();
    let tcp_addrs = config.generate_tcp_addrs();
    let backend = config.backend;

    for (thread_id, (socket, tcp_addr)) in config
        .generate_socket_paths()
        .into_iter()
        .zip(tcp_addrs.iter())
        .enumerate()
    {
        let tcp_addr = tcp_addr.clone();
        info!("thread_id: {}, socket: {:?}", thread_id, socket);

        let name = format!("vhu-console-{}", tcp_addr);
        let sender = senders.clone();
        let handle = Builder::new()
            .name(name.clone())
            .spawn(move || {
                let result = std::panic::catch_unwind(move || {
                    start_backend_server(socket, tcp_addr.to_string(), backend)
                });

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
    use crate::ConsoleArgs;
    use assert_matches::assert_matches;

    #[test]
    fn test_console_valid_configuration_nested() {
        let args = ConsoleArgs {
            socket_path: String::from("/tmp/vhost.sock").into(),
            backend: BackendType::Nested,
            tcp_port: String::from("12345"),
            socket_count: 1,
        };

        assert!(VuConsoleConfig::try_from(args).is_ok());
    }

    #[test]
    fn test_console_invalid_configuration_nested_1() {
        let args = ConsoleArgs {
            socket_path: String::from("/tmp/vhost.sock").into(),
            backend: BackendType::Nested,
            tcp_port: String::from("12345"),
            socket_count: 0,
        };

        assert_matches!(
            VuConsoleConfig::try_from(args),
            Err(Error::SocketCountInvalid(0))
        );
    }

    #[test]
    fn test_console_invalid_configuration_nested_2() {
        let args = ConsoleArgs {
            socket_path: String::from("/tmp/vhost.sock").into(),
            backend: BackendType::Nested,
            tcp_port: String::from("12345"),
            socket_count: 2,
        };

        assert_matches!(
            VuConsoleConfig::try_from(args),
            Err(Error::WrongBackendSocket)
        );
    }

    #[test]
    fn test_console_valid_configuration_network_1() {
        let args = ConsoleArgs {
            socket_path: String::from("/tmp/vhost.sock").into(),
            backend: BackendType::Network,
            tcp_port: String::from("12345"),
            socket_count: 1,
        };

        assert!(VuConsoleConfig::try_from(args).is_ok());
    }

    #[test]
    fn test_console_valid_configuration_network_2() {
        let args = ConsoleArgs {
            socket_path: String::from("/tmp/vhost.sock").into(),
            backend: BackendType::Network,
            tcp_port: String::from("12345"),
            socket_count: 2,
        };

        assert!(VuConsoleConfig::try_from(args).is_ok());
    }

    fn test_backend_start_and_stop(args: ConsoleArgs) {
        let config = VuConsoleConfig::try_from(args).expect("Wrong config");

        let tcp_addrs = config.generate_tcp_addrs();
        let backend = config.backend;

        for (_socket, tcp_addr) in config
            .generate_socket_paths()
            .into_iter()
            .zip(tcp_addrs.iter())
        {
            let controller = ConsoleController::new(backend);
            let arc_controller = Arc::new(RwLock::new(controller));
            let vu_console_backend = Arc::new(RwLock::new(
                VhostUserConsoleBackend::new(arc_controller)
                    .map_err(Error::CouldNotCreateBackend)
                    .expect("Fail create vhuconsole backend"),
            ));

            let mut _daemon = VhostUserDaemon::new(
                String::from("vhost-device-console-backend"),
                vu_console_backend.clone(),
                GuestMemoryAtomic::new(GuestMemoryMmap::new()),
            )
            .map_err(Error::CouldNotCreateDaemon)
            .expect("Failed create daemon");

            // Start the corresponinding console thread
            let read_handle = if backend == BackendType::Nested {
                VhostUserConsoleBackend::start_console_thread(&vu_console_backend)
            } else {
                VhostUserConsoleBackend::start_tcp_console_thread(
                    &vu_console_backend,
                    tcp_addr.clone(),
                )
            };

            // Kill console input thread
            vu_console_backend.read().unwrap().kill_console_thread();

            // Wait for read thread to exit
            assert_matches!(read_handle.join(), Ok(_));
        }
    }
    #[test]
    fn test_start_net_backend_success() {
        let args = ConsoleArgs {
            socket_path: String::from("/tmp/vhost.sock").into(),
            backend: BackendType::Network,
            tcp_port: String::from("12345"),
            socket_count: 1,
        };

        test_backend_start_and_stop(args);
    }

    #[test]
    fn test_start_nested_backend_success() {
        let args = ConsoleArgs {
            socket_path: String::from("/tmp/vhost.sock").into(),
            backend: BackendType::Nested,
            tcp_port: String::from("12345"),
            socket_count: 1,
        };

        test_backend_start_and_stop(args);
    }
}
