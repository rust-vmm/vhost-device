// VIRTIO CONSOLE Emulation via vhost-user
//
// Copyright 2023-2024 VIRTUAL OPEN SYSTEMS SAS. All Rights Reserved.
//          Timos Ampelikiotis <t.ampelikiotis@virtualopensystems.com>
//
// SPDX-License-Identifier: Apache-2.0 or BSD-3-Clause

use std::{
    any::Any,
    collections::HashMap,
    path::PathBuf,
    sync::{Arc, RwLock},
    thread::Builder,
};

use log::{error, info};
use thiserror::Error as ThisError;
use vhost_user_backend::VhostUserDaemon;
use vm_memory::{GuestMemoryAtomic, GuestMemoryMmap};

use crate::{
    console::{BackendType, ConsoleController},
    vhu_console::VhostUserConsoleBackend,
};

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, ThisError)]
/// Errors related to low level Console helpers
pub enum Error {
    #[error("Invalid socket count: {0}")]
    SocketCountInvalid(usize),
    #[error("Could not create console backend: {0}")]
    CouldNotCreateBackend(crate::vhu_console::Error),
    #[error("Could not initialize console backend: {0}")]
    CouldNotInitBackend(crate::vhu_console::Error),
    #[error("Could not create daemon: {0}")]
    CouldNotCreateDaemon(vhost_user_backend::Error),
    #[error("Fatal error: {0}")]
    ServeFailed(vhost_user_backend::Error),
    #[error("Thread `{0}` panicked")]
    ThreadPanic(String, Box<dyn Any + Send>),
    #[error("Error using multiple sockets with Nested backend")]
    WrongBackendSocket,
    #[error("Invalid uds file")]
    InvalidUdsFile,
}

#[derive(PartialEq, Eq, Debug)]
pub struct VuConsoleConfig {
    pub socket_path: PathBuf,
    pub uds_path: PathBuf,
    pub backend: BackendType,
    pub tcp_port: String,
    pub socket_count: u32,
    pub max_queue_size: usize,
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

    pub fn generate_vm_socks(&self) -> Vec<String> {
        match self.backend {
            // if type is Nested, result will be dropped.
            BackendType::Nested => {
                vec![String::new()]
            }

            BackendType::Network => {
                let port_base: u32 = self.tcp_port.parse().unwrap();
                let make_tcp_port =
                    |i: u32| -> String { "127.0.0.1:".to_owned() + &(port_base + i).to_string() };
                (0..self.socket_count).map(make_tcp_port).collect()
            }

            BackendType::Uds => {
                let uds_filename = self.uds_path.file_name().expect("uds has no filename.");
                let uds_parent = self
                    .uds_path
                    .parent()
                    .expect("uds has no parent directory.");

                let make_uds_path = |i: u32| -> String {
                    let mut filename = uds_filename.to_os_string();
                    filename.push(std::ffi::OsStr::new(&i.to_string()));
                    uds_parent
                        .join(&filename)
                        .to_str()
                        .expect("Path contains invalid UTF-8 characters")
                        .to_string()
                };

                (0..self.socket_count).map(make_uds_path).collect()
            }
        }
    }
}

/// This is the public API through which an external program starts the
/// vhost-device-console backend server.
pub fn start_backend_server(
    socket: PathBuf,
    vm_sock: String,
    backend: BackendType,
    max_queue_size: usize,
) -> Result<()> {
    loop {
        let controller = ConsoleController::new(backend);
        let arc_controller = Arc::new(RwLock::new(controller));
        let vu_console_backend = Arc::new(RwLock::new(
            VhostUserConsoleBackend::new(max_queue_size, arc_controller)
                .map_err(Error::CouldNotCreateBackend)?,
        ));

        vu_console_backend
            .write()
            .unwrap()
            .assign_input_method(vm_sock.clone())
            .map_err(Error::CouldNotInitBackend)?;

        let mut daemon = VhostUserDaemon::new(
            String::from("vhost-device-console-backend"),
            vu_console_backend.clone(),
            GuestMemoryAtomic::new(GuestMemoryMmap::new()),
        )
        .map_err(Error::CouldNotCreateDaemon)?;

        let vring_workers = daemon.get_epoll_handlers();
        vu_console_backend
            .read()
            .expect("Cannot unlock console backend with read-only access.")
            .set_vring_worker(vring_workers[0].clone());

        daemon.serve(&socket).map_err(|e| {
            // Even if daemon stops unexpectedly, the backend should
            // be terminated properly (disable raw mode).
            vu_console_backend.read().unwrap().prepare_exit();
            Error::ServeFailed(e)
        })?;
    }
}

pub fn start_backend(config: VuConsoleConfig) -> Result<()> {
    let mut handles = HashMap::new();
    let (senders, receiver) = std::sync::mpsc::channel();
    let vm_socks = config.generate_vm_socks();
    let backend = config.backend;
    let max_queue_size = config.max_queue_size;

    for (thread_id, (socket, vm_sock)) in config
        .generate_socket_paths()
        .into_iter()
        .zip(vm_socks.iter())
        .enumerate()
    {
        let vm_sock = vm_sock.clone();
        info!("thread_id: {}, socket: {:?}", thread_id, socket);

        let name = format!("vhu-console-{}", vm_sock);
        let sender = senders.clone();
        let handle = Builder::new()
            .name(name.clone())
            .spawn(move || {
                let result = std::panic::catch_unwind(move || {
                    start_backend_server(socket, vm_sock.to_string(), backend, max_queue_size)
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
    use assert_matches::assert_matches;

    use super::*;
    use crate::{ConsoleArgs, DEFAULT_QUEUE_SIZE};

    #[test]
    fn test_console_valid_configuration_nested() {
        let args = ConsoleArgs {
            socket_path: String::from("/tmp/vhost.sock").into(),
            uds_path: None,
            backend: BackendType::Nested,
            tcp_port: String::from("12345"),
            socket_count: 1,
            max_queue_size: DEFAULT_QUEUE_SIZE,
        };

        VuConsoleConfig::try_from(args).unwrap();
    }

    #[test]
    fn test_console_invalid_configuration_nested_1() {
        let args = ConsoleArgs {
            socket_path: String::from("/tmp/vhost.sock").into(),
            uds_path: None,
            backend: BackendType::Nested,
            tcp_port: String::from("12345"),
            socket_count: 0,
            max_queue_size: DEFAULT_QUEUE_SIZE,
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
            uds_path: None,
            backend: BackendType::Nested,
            tcp_port: String::from("12345"),
            socket_count: 2,
            max_queue_size: DEFAULT_QUEUE_SIZE,
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
            uds_path: None,
            backend: BackendType::Network,
            tcp_port: String::from("12345"),
            socket_count: 1,
            max_queue_size: DEFAULT_QUEUE_SIZE,
        };

        VuConsoleConfig::try_from(args).unwrap();
    }

    #[test]
    fn test_console_valid_configuration_network_2() {
        let args = ConsoleArgs {
            socket_path: String::from("/tmp/vhost.sock").into(),
            uds_path: None,
            backend: BackendType::Network,
            tcp_port: String::from("12345"),
            socket_count: 2,
            max_queue_size: DEFAULT_QUEUE_SIZE,
        };

        VuConsoleConfig::try_from(args).unwrap();
    }

    fn test_backend_start_and_stop(args: ConsoleArgs) -> Result<()> {
        let config = VuConsoleConfig::try_from(args).expect("Wrong config");

        let vm_socks = config.generate_vm_socks();
        let backend = config.backend;
        let max_queue_size = config.max_queue_size;

        for (socket, vm_sock) in config
            .generate_socket_paths()
            .into_iter()
            .zip(vm_socks.iter())
        {
            start_backend_server(socket, vm_sock.to_string(), backend, max_queue_size)?;
        }
        Ok(())
    }

    #[test]
    fn test_start_backend_server_success() {
        let args = ConsoleArgs {
            socket_path: String::from("/not_a_dir/vhost.sock").into(),
            uds_path: None,
            backend: BackendType::Network,
            tcp_port: String::from("12345"),
            socket_count: 1,
            max_queue_size: DEFAULT_QUEUE_SIZE,
        };

        assert!(test_backend_start_and_stop(args).is_err());
    }

    #[test]
    fn test_start_backend_success() {
        let config = VuConsoleConfig {
            socket_path: String::from("/not_a_dir/vhost.sock").into(),
            uds_path: PathBuf::new(),
            backend: BackendType::Network,
            tcp_port: String::from("12346"),
            socket_count: 1,
            max_queue_size: DEFAULT_QUEUE_SIZE,
        };

        assert!(start_backend(config).is_err());
    }
}
