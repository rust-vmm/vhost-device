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
use log::info;
use thiserror::Error as ThisError;
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
    #[error("Fatal error: {0}")]
    ServeFailed(vhost_user_backend::Error),
}

#[derive(Clone, Parser, Debug)]
#[clap(author, version, about, long_about = None)]
struct VideoArgs {
    /// Unix socket to which a hypervisor connects to and sets up the control
    /// path with the device.
    #[clap(short, long)]
    socket_path: PathBuf,

    /// Path to the video device file. Defaults to `/dev/video0`.
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
            .serve(&config.socket_path)
            .map_err(Error::ServeFailed)?;
    }
}

fn main() -> Result<()> {
    env_logger::init();

    start_backend(VuVideoConfig::from(VideoArgs::parse()))
}

#[cfg(test)]
mod tests {
    use assert_matches::assert_matches;
    #[cfg(feature = "v4l2-decoder")]
    use rstest::*;
    use tempfile::tempdir;

    use super::*;

    #[rstest]
    // No device specified defaults to /dev/video0
    #[case::no_device(vec!["", "-s", "video.sock", "-b", "null"],
    VideoArgs {
        socket_path: "video.sock".into(),
        v4l2_device: "/dev/video0".into(),
        backend: BackendType::Null,
    })]
    // Specifying device overwrite the default value
    #[case::set_device(vec!["", "-s" , "video.sock", "-d", "/dev/video1", "-b", "null"],
    VideoArgs {
        socket_path: "video.sock".into(),
        v4l2_device: "/dev/video1".into(),
        backend: BackendType::Null,
    })]
    // Selecting different decoder
    #[cfg(feature = "v4l2-decoder")]
    #[case::set_v4l2_decoder(vec![" ", "--socket-path", "long-video.sock", "-b", "v4l2-decoder"],
    VideoArgs {
        socket_path: "long-video.sock".into(),
        v4l2_device: "/dev/video0".into(),
        backend: BackendType::V4L2Decoder,
    })]
    fn test_command_line_arguments(#[case] args: Vec<&str>, #[case] command_line: VideoArgs) {
        let args: VideoArgs = Parser::parse_from(args.as_slice());

        assert_eq!(VuVideoConfig::from(command_line), VuVideoConfig::from(args));
    }

    #[cfg(feature = "v4l2-decoder")]
    #[test]
    fn test_fail_create_backend() {
        use vhu_video::VuVideoError;
        let config = VideoArgs {
            socket_path: "video.sock".into(),
            v4l2_device: "/path/invalid/video.dev".into(),
            backend: BackendType::V4L2Decoder,
        };
        assert_matches!(
            start_backend(VuVideoConfig::from(config.clone())).unwrap_err(),
            Error::CouldNotCreateBackend(VuVideoError::AccessVideoDeviceFile)
        );
    }

    #[test]
    fn test_fail_listener() {
        use std::fs::File;
        let test_dir = tempdir().expect("Could not create a temp test directory.");
        let v4l2_device = test_dir.path().join("video.dev");
        File::create(&v4l2_device).expect("Could not create a test device file.");
        let config = VideoArgs {
            socket_path: "~/path/invalid/video.sock".into(),
            v4l2_device: v4l2_device.to_owned(),
            backend: BackendType::Null,
        };
        assert_matches!(
            start_backend(VuVideoConfig::from(config)).unwrap_err(),
            Error::ServeFailed(_)
        );
        // cleanup
        std::fs::remove_file(v4l2_device).expect("Failed to clean up");
        test_dir.close().unwrap();
    }
}
