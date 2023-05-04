// SPDX-License-Identifier: Apache-2.0 or BSD-3-Clause

mod rxops;
mod rxqueue;
mod thread_backend;
mod txbuf;
mod vhu_vsock;
mod vhu_vsock_thread;
mod vsock_conn;

use std::{convert::TryFrom, sync::Arc};

use crate::vhu_vsock::{Error, Result, VhostUserVsockBackend, VsockConfig};
use clap::{Args, Parser};
use log::{info, warn};
use serde::Deserialize;
use vhost::{vhost_user, vhost_user::Listener};
use vhost_user_backend::VhostUserDaemon;
use vm_memory::{GuestMemoryAtomic, GuestMemoryMmap};

#[derive(Args, Debug, Deserialize)]
struct VsockParam {
    /// Context identifier of the guest which uniquely identifies the device for its lifetime.
    #[arg(long, default_value_t = 3, conflicts_with = "config")]
    guest_cid: u64,

    /// Unix socket to which a hypervisor connects to and sets up the control path with the device.
    #[arg(long, conflicts_with = "config")]
    socket: String,

    /// Unix socket to which a host-side application connects to.
    #[arg(long, conflicts_with = "config")]
    uds_path: String,

    /// The size of the buffer used for the TX virtqueue
    #[clap(long, default_value_t = 64 * 1024, conflicts_with = "config")]
    tx_buffer_size: u32,
}

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct VsockArgs {
    #[command(flatten)]
    param: Option<VsockParam>,

    /// Load from a given configuration file
    #[arg(long)]
    config: Option<String>,
}

impl VsockArgs {
    pub fn parse_config(&self) -> Option<VsockConfig> {
        if let Some(c) = &self.config {
            let b = config::Config::builder()
                .add_source(config::File::new(c.as_str(), config::FileFormat::Yaml))
                .build();
            if let Ok(s) = b {
                let mut v = s.get::<Vec<VsockParam>>("vms").unwrap();
                if v.len() == 1 {
                    return v.pop().map(|vm| {
                        VsockConfig::new(vm.guest_cid, vm.socket, vm.uds_path, vm.tx_buffer_size)
                    });
                }
            }
        }
        None
    }
}

impl TryFrom<VsockArgs> for VsockConfig {
    type Error = Error;

    fn try_from(cmd_args: VsockArgs) -> Result<Self> {
        // we try to use the configuration first, if failed,  then fall back to the manual settings.
        match cmd_args.parse_config() {
            Some(c) => Ok(c),
            _ => cmd_args.param.map_or(Err(Error::ConfigParse), |p| {
                Ok(Self::new(
                    p.guest_cid,
                    p.socket.trim().to_string(),
                    p.uds_path.trim().to_string(),
                    p.tx_buffer_size,
                ))
            }),
        }
    }
}

/// This is the public API through which an external program starts the
/// vhost-user-vsock backend server.
pub(crate) fn start_backend_server(config: VsockConfig) {
    loop {
        let backend = Arc::new(VhostUserVsockBackend::new(config.clone()).unwrap());

        let listener = Listener::new(config.get_socket_path(), true).unwrap();

        let mut daemon = VhostUserDaemon::new(
            String::from("vhost-user-vsock"),
            backend.clone(),
            GuestMemoryAtomic::new(GuestMemoryMmap::new()),
        )
        .unwrap();

        let mut vring_workers = daemon.get_epoll_handlers();

        for thread in backend.threads.iter() {
            thread
                .lock()
                .unwrap()
                .set_vring_worker(Some(vring_workers.remove(0)));
        }

        daemon.start(listener).unwrap();

        match daemon.wait() {
            Ok(()) => {
                info!("Stopping cleanly");
            }
            Err(vhost_user_backend::Error::HandleRequest(vhost_user::Error::PartialMessage)) => {
                info!("vhost-user connection closed with partial message. If the VM is shutting down, this is expected behavior; otherwise, it might be a bug.");
            }
            Err(e) => {
                warn!("Error running daemon: {:?}", e);
            }
        }

        // No matter the result, we need to shut down the worker thread.
        backend.exit_event.write(1).unwrap();
    }
}

fn main() {
    env_logger::init();

    let config = VsockConfig::try_from(VsockArgs::parse()).unwrap();
    start_backend_server(config);
}

#[cfg(test)]
mod tests {
    use super::*;
    use serial_test::serial;
    use std::fs::File;
    use std::io::Write;

    impl VsockArgs {
        fn from_args(guest_cid: u64, socket: &str, uds_path: &str, tx_buffer_size: u32) -> Self {
            VsockArgs {
                param: Some(VsockParam {
                    guest_cid,
                    socket: socket.to_string(),
                    uds_path: uds_path.to_string(),
                    tx_buffer_size,
                }),
                config: None,
            }
        }
        fn from_file(config: &str) -> Self {
            VsockArgs {
                param: None,
                config: Some(config.to_string()),
            }
        }
    }

    #[test]
    #[serial]
    fn test_vsock_config_setup() {
        let args = VsockArgs::from_args(3, "/tmp/vhost4.socket", "/tmp/vm4.vsock", 64 * 1024);

        let config = VsockConfig::try_from(args);
        assert!(config.is_ok());

        let config = config.unwrap();
        assert_eq!(config.get_guest_cid(), 3);
        assert_eq!(config.get_socket_path(), "/tmp/vhost4.socket");
        assert_eq!(config.get_uds_path(), "/tmp/vm4.vsock");
        assert_eq!(config.get_tx_buffer_size(), 64 * 1024);
    }

    #[test]
    #[serial]
    fn test_vsock_config_setup_from_file() {
        let mut yaml = File::create("./config.yaml").unwrap();
        yaml.write_all(
            b"vms:
    - guest_cid: 4
      socket: /tmp/vhost4.socket
      uds_path: /tmp/vm4.vsock
      tx_buffer_size: 65536",
        )
        .unwrap();
        let args = VsockArgs::from_file("./config.yaml");
        let config = VsockConfig::try_from(args).unwrap();
        assert_eq!(config.get_guest_cid(), 4);
        assert_eq!(config.get_socket_path(), "/tmp/vhost4.socket");
        assert_eq!(config.get_uds_path(), "/tmp/vm4.vsock");
        std::fs::remove_file("./config.yaml").unwrap();
    }

    #[test]
    #[serial]
    fn test_vsock_server() {
        const CID: u64 = 3;
        const VHOST_SOCKET_PATH: &str = "test_vsock_server.socket";
        const VSOCK_SOCKET_PATH: &str = "test_vsock_server.vsock";
        const CONN_TX_BUF_SIZE: u32 = 64 * 1024;

        let config = VsockConfig::new(
            CID,
            VHOST_SOCKET_PATH.to_string(),
            VSOCK_SOCKET_PATH.to_string(),
            CONN_TX_BUF_SIZE,
        );

        let backend = Arc::new(VhostUserVsockBackend::new(config).unwrap());

        let daemon = VhostUserDaemon::new(
            String::from("vhost-user-vsock"),
            backend.clone(),
            GuestMemoryAtomic::new(GuestMemoryMmap::new()),
        )
        .unwrap();

        let vring_workers = daemon.get_epoll_handlers();

        // VhostUserVsockBackend support a single thread that handles the TX and RX queues
        assert_eq!(backend.threads.len(), 1);

        assert_eq!(vring_workers.len(), backend.threads.len());
    }
}
