mod packet;
mod rxops;
mod rxqueue;
mod thread_backend;
mod txbuf;
mod vhu_vsock;
mod vhu_vsock_thread;
mod vsock_conn;

use clap::{load_yaml, App};
use std::{
    convert::TryFrom,
    process,
    sync::{Arc, RwLock},
};
use vhost::{vhost_user, vhost_user::Listener};
use vhost_user_backend::VhostUserDaemon;
use vhu_vsock::{VhostUserVsockBackend, VsockConfig};
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

        if vring_workers.len() != vsock_backend.read().unwrap().threads.len() {
            println!("Number of vring workers must be identical to number of backend threads");
        }

        for thread in vsock_backend.read().unwrap().threads.iter() {
            thread
                .lock()
                .unwrap()
                .set_vring_worker(Some(vring_workers.remove(0)));
        }
        if let Err(e) = vsock_daemon.start(listener) {
            dbg!("Failed to start vsock daemon: {:?}", e);
            process::exit(1);
        }

        match vsock_daemon.wait() {
            Ok(()) => {
                println!("Stopping cleanly");
                process::exit(0);
            }
            Err(vhost_user_backend::Error::HandleRequest(vhost_user::Error::PartialMessage)) => {
                println!("vhost-user connection closed with partial message. If the VM is shutting down, this is expected behavior; otherwise, it might be a bug.");
                continue;
            }
            Err(e) => {
                println!("Error running daemon: {:?}", e);
            }
        }

        vsock_backend
            .read()
            .unwrap()
            .exit_event
            .write(1)
            .expect("Shutting down worker thread");

        println!("Vsock daemon is finished");
    }
}

fn main() {
    let yaml = load_yaml!("cli.yaml");
    let vsock_args = App::from_yaml(yaml).get_matches();

    let vsock_config = VsockConfig::try_from(vsock_args).unwrap();

    start_backend_server(vsock_config);
}
