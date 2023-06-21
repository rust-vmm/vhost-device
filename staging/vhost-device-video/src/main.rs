// SPDX-License-Identifier: Apache-2.0 or BSD-3-Clause
mod stream;
mod vhu_video;
mod vhu_video_thread;
mod video;
mod video_backends;

use std::{
    path::PathBuf,
    sync::{Arc, RwLock},
};

use clap::Parser;
use log::{info, warn};
use thiserror::Error as ThisError;
use vhost::{vhost_user, vhost_user::Listener};
use vhost_user_backend::VhostUserDaemon;
use vhu_video::{BackendType, VuVideoBackend};
use vm_memory::{GuestMemoryAtomic, GuestMemoryMmap};

pub(crate) type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, ThisError)]
pub(crate) enum Error {
    #[error("Could not create backend: {0}")]
    CouldNotCreateBackend(vhu_video::VuVideoError),
    #[error("Could not create daemon: {0}")]
    CouldNotCreateDaemon(vhost_user_backend::Error),
    #[error("Failed creating listener: {0}")]
    FailedCreatingListener(vhost_user::Error),
}

#[derive(Clone, Parser, Debug)]
#[clap(author, version, about, long_about = None)]
struct VideoArgs {
    /// Unix socket to which a hypervisor connects to and sets up the control
    /// path with the device.
    #[clap(short, long)]
    socket_path: PathBuf,

    /// Path to the video device file. Defaults to /dev/video0.
    #[clap(short = 'd', long, default_value = "/dev/video0")]
    v4l2_device: PathBuf,

    /// Video backend to be used.
    #[clap(short, long)]
    #[clap(value_enum)]
    backend: BackendType,
}

#[derive(Debug, Eq, PartialEq)]
pub(crate) struct VuVideoConfig {
    pub socket_path: PathBuf,
    pub v4l2_device: PathBuf,
    pub backend: BackendType,
}

impl From<VideoArgs> for VuVideoConfig {
    fn from(args: VideoArgs) -> Self {
        // Divide available bandwidth by the number of threads in order
        // to avoid overwhelming the HW.
        Self {
            socket_path: args.socket_path.to_owned(),
            v4l2_device: args.v4l2_device.to_owned(),
            backend: args.backend,
        }
    }
}

pub(crate) fn start_backend(config: VuVideoConfig) -> Result<()> {
    loop {
        info!("Starting backend");
        let vu_video_backend = Arc::new(RwLock::new(
            VuVideoBackend::new(config.v4l2_device.as_path(), config.backend.to_owned())
                .map_err(Error::CouldNotCreateBackend)?,
        ));

        let mut daemon = VhostUserDaemon::new(
            String::from("vhost-device-video"),
            vu_video_backend.clone(),
            GuestMemoryAtomic::new(GuestMemoryMmap::new()),
        )
        .map_err(Error::CouldNotCreateDaemon)?;

        let mut vring_workers = daemon.get_epoll_handlers();
        for thread in vu_video_backend.read().unwrap().threads.iter() {
            thread
                .lock()
                .unwrap()
                .set_vring_workers(vring_workers.remove(0));
        }

        daemon
            .start(Listener::new(&config.socket_path, true).map_err(Error::FailedCreatingListener)?)
            .expect("Stargin daemon");

        match daemon.wait() {
            Ok(()) => {
                info!("Stopping cleanly");
            }
            Err(vhost_user_backend::Error::HandleRequest(
                vhost_user::Error::PartialMessage | vhost_user::Error::Disconnected,
            )) => {
                info!(
                    "vhost-user connection closed with partial message.
                    If the VM is shutting down, this is expected behavior;
                    otherwise, it might be a bug."
                );
            }
            Err(e) => {
                warn!("Error running daemon: {:?} -> {}", e, e.to_string());
            }
        }

        vu_video_backend
            .read()
            .unwrap()
            .exit_event
            .write(1)
            .expect("Shutting down worker thread");
    }
}

fn main() -> Result<()> {
    env_logger::init();

    start_backend(VuVideoConfig::try_from(VideoArgs::parse()).unwrap())
}
