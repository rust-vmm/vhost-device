// SPDX-License-Identifier: Apache-2.0 or BSD-3-Clause

mod rxops;
mod rxqueue;
mod thread_backend;
mod txbuf;
mod vhu_vsock;
mod vhu_vsock_thread;
mod vsock_conn;

use std::{
    convert::TryFrom,
    sync::{Arc, RwLock},
};

use clap::Parser;
use log::{info, warn};
use vhost::{vhost_user, vhost_user::Listener};
use vhost_user_backend::VhostUserDaemon;
use vm_memory::{GuestMemoryAtomic, GuestMemoryMmap};

use crate::vhu_vsock::{Error, Result, VhostUserVsockBackend, VsockConfig};

#[derive(Parser, Debug)]
#[clap(version, about, long_about = None)]
struct VsockArgs {
    /// Context identifier of the guest which uniquely identifies the device for its lifetime.
    #[clap(long, default_value_t = 3)]
    guest_cid: u64,

    /// Unix socket to which a hypervisor connects to and sets up the control path with the device.
    #[clap(long)]
    socket: String,

    /// Unix socket to which a host-side application connects to.
    #[clap(long)]
    uds_path: String,
}

impl TryFrom<VsockArgs> for VsockConfig {
    type Error = Error;

    fn try_from(cmd_args: VsockArgs) -> Result<Self> {
        let socket = cmd_args.socket.trim().to_string();
        let uds_path = cmd_args.uds_path.trim().to_string();

        Ok(VsockConfig::new(cmd_args.guest_cid, socket, uds_path))
    }
}

/// This is the public API through which an external program starts the
/// vhost-user-vsock backend server.
pub(crate) fn start_backend_server(config: VsockConfig) {
    loop {
        let backend = Arc::new(RwLock::new(
            VhostUserVsockBackend::new(config.clone()).unwrap(),
        ));

        let listener = Listener::new(config.get_socket_path(), true).unwrap();

        let mut daemon = VhostUserDaemon::new(
            String::from("vhost-user-vsock"),
            backend.clone(),
            GuestMemoryAtomic::new(GuestMemoryMmap::new()),
        )
        .unwrap();

        let mut vring_workers = daemon.get_epoll_handlers();

        for thread in backend.read().unwrap().threads.iter() {
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
        backend.read().unwrap().exit_event.write(1).unwrap();
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

    impl VsockArgs {
        fn from_args(guest_cid: u64, socket: &str, uds_path: &str) -> Self {
            VsockArgs {
                guest_cid,
                socket: socket.to_string(),
                uds_path: uds_path.to_string(),
            }
        }
    }

    #[test]
    #[serial]
    fn test_vsock_config_setup() {
        let args = VsockArgs::from_args(3, "/tmp/vhost4.socket", "/tmp/vm4.vsock");

        let config = VsockConfig::try_from(args);
        assert!(config.is_ok());

        let config = config.unwrap();
        assert_eq!(config.get_guest_cid(), 3);
        assert_eq!(config.get_socket_path(), "/tmp/vhost4.socket");
        assert_eq!(config.get_uds_path(), "/tmp/vm4.vsock");
    }

    #[test]
    #[serial]
    fn test_vsock_server() {
        const CID: u64 = 3;
        const VHOST_SOCKET_PATH: &str = "test_vsock_server.socket";
        const VSOCK_SOCKET_PATH: &str = "test_vsock_server.vsock";

        let config = VsockConfig::new(
            CID,
            VHOST_SOCKET_PATH.to_string(),
            VSOCK_SOCKET_PATH.to_string(),
        );

        let backend = Arc::new(RwLock::new(VhostUserVsockBackend::new(config).unwrap()));

        let daemon = VhostUserDaemon::new(
            String::from("vhost-user-vsock"),
            backend.clone(),
            GuestMemoryAtomic::new(GuestMemoryMmap::new()),
        )
        .unwrap();

        let vring_workers = daemon.get_epoll_handlers();

        // VhostUserVsockBackend support a single thread that handles the TX and RX queues
        assert_eq!(backend.read().unwrap().threads.len(), 1);

        assert_eq!(vring_workers.len(), backend.read().unwrap().threads.len());
    }
}
