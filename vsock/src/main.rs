// SPDX-License-Identifier: Apache-2.0 or BSD-3-Clause

mod rxops;
mod rxqueue;
mod thread_backend;
mod txbuf;
mod vhu_vsock;
mod vhu_vsock_thread;
mod vsock_conn;

use clap::Parser;
use log::{info, warn};
use std::{
    convert::TryFrom,
    sync::{Arc, RwLock},
};
use vhost::{vhost_user, vhost_user::Listener};
use vhost_user_backend::VhostUserDaemon;
use vhu_vsock::{VhostUserVsockBackend, VsockArgs, VsockConfig};
use vm_memory::{GuestMemoryAtomic, GuestMemoryMmap};

/// This is the public API through which an external program starts the
/// vhost-user-vsock backend server.
pub(crate) fn start_backend_server(vsock_config: VsockConfig) {
    loop {
        let vsock_backend = Arc::new(RwLock::new(
            VhostUserVsockBackend::new(vsock_config.clone()).unwrap(),
        ));

        let listener = Listener::new(vsock_config.get_socket_path(), true).unwrap();

        let mut vsock_daemon = VhostUserDaemon::new(
            String::from("vhost-user-vsock"),
            vsock_backend.clone(),
            GuestMemoryAtomic::new(GuestMemoryMmap::new()),
        )
        .unwrap();

        let mut vring_workers = vsock_daemon.get_epoll_handlers();

        for thread in vsock_backend.read().unwrap().threads.iter() {
            thread
                .lock()
                .unwrap()
                .set_vring_worker(Some(vring_workers.remove(0)));
        }

        vsock_daemon.start(listener).unwrap();

        match vsock_daemon.wait() {
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
        vsock_backend.read().unwrap().exit_event.write(1).unwrap();
    }
}

fn main() {
    env_logger::init();

    let vsock_config = VsockConfig::try_from(VsockArgs::parse()).unwrap();
    start_backend_server(vsock_config);
}
