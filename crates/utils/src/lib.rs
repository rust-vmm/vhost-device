use log::{info, warn};
use std::{os::fd::FromRawFd, path::Path, sync::Arc};

use vhost::vhost_user::{self, Listener};
use vhost_user_backend::{VhostUserBackend, VhostUserDaemon, VringT};
use vm_memory::{mmap::NewBitmap, GuestMemoryAtomic, GuestMemoryMmap};

#[cfg(not(feature = "systemd"))]
fn create_listener<P: AsRef<Path>>(socket_path: P) -> vhost_user::Result<Listener> {
    Listener::new(socket_path, true)
}

#[cfg(feature = "systemd")]
fn create_listener<P: AsRef<Path>>(socket_path: P) -> vhost_user::Result<Listener> {
    use log::error;

    let fds = systemd::daemon::listen_fds(false).unwrap();
    let suitable_socket_fd = fds.iter().find(|&fd| {
        let socket_path = Some(
            socket_path
                .as_ref()
                .to_str()
                .expect("socket_path should be valid utf-8 string"),
        );

        systemd::daemon::is_socket_unix(
            fd,
            Some(systemd::daemon::SocketType::Stream),
            systemd::daemon::Listening::IsListening,
            socket_path,
        )
        .unwrap()
    });

    if let Some(fd) = suitable_socket_fd {
        unsafe { Ok(Listener::from_raw_fd(fd)) }
    } else {
        if !fds.is_empty() {
            let socket_path = socket_path.as_ref().to_string_lossy();
            error!(
                "Detected socket activation, but did not find suitable \
                socket for {socket_path}. Falling back to creating own socket..."
            );
        }
        Listener::new(socket_path, true)
    }
}

// Generics here are horrible...
// Hopefully once https://github.com/rust-vmm/vhost/pull/155 lands,
// this can be simplified!

/// A wrapper around a VhostUserDaemon that exposes a simpler API
pub struct DaemonHandle<
    S: VhostUserBackend<V, B> + 'static,
    V: VringT<GuestMemoryAtomic<GuestMemoryMmap<B>>> + Clone + Send + Sync + 'static,
    B: NewBitmap + Clone + Send + Sync + 'static,
> {
    pub backend: Arc<S>,
    pub daemon: VhostUserDaemon<Arc<S>, V, B>,
}

impl<
        S: VhostUserBackend<V, B> + 'static,
        V: VringT<GuestMemoryAtomic<GuestMemoryMmap<B>>> + Clone + Send + Sync + 'static,
        B: NewBitmap + Clone + Send + Sync + 'static,
    > DaemonHandle<S, V, B>
{
    /// Lets the daemon start listening and waits until exit
    pub fn start<P: AsRef<Path>>(mut self, socket_path: P) -> vhost_user::Result<()> {
        self.daemon
            .start(create_listener(socket_path)?)
            .expect("Starting daemon");

        match self.daemon.wait() {
            Ok(()) => {
                info!("Stopping cleanly.");
            }
            Err(vhost_user_backend::Error::HandleRequest(vhost_user::Error::PartialMessage)) => {
                info!("vhost-user connection closed with partial message. If the VM is shutting down, this is expected behavior; otherwise, it might be a bug.");
            }
            Err(e) => {
                warn!("Error running daemon: {:?}", e);
            }
        }

        // No matter the result, we need to shut down the worker thread.
        // unwrap will only panic if we already panicked somewhere else
        if let Some(exit_event) = self.backend.exit_event(0) {
            exit_event.write(1).expect("Shutting down worker thread");
        }

        Ok(())
    }
}

pub fn create_daemon<
    S: VhostUserBackend<V, B> + 'static,
    V: VringT<GuestMemoryAtomic<GuestMemoryMmap<B>>> + Clone + Send + Sync + 'static,
    B: NewBitmap + Clone + Send + Sync + 'static,
>(
    backend: S,
    name: &str,
) -> DaemonHandle<S, V, B> {
    let backend = Arc::new(backend);
    let daemon = VhostUserDaemon::new(
        name.into(),
        backend.clone(),
        GuestMemoryAtomic::new(GuestMemoryMmap::new()),
    )
    .expect("Creating daemon");

    DaemonHandle { backend, daemon }
}
