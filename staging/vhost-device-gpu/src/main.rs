// VIRTIO GPU Emulation via vhost-user
//
// Copyright 2024 Red Hat Inc
//
// SPDX-License-Identifier: Apache-2.0 or BSD-3-Clause

use std::{path::PathBuf, process::exit};

use clap::Parser;
use log::{error, info};
use thiserror::Error as ThisError;
use vhost_device_gpu::{
    device::{self, VhostUserGpuBackend},
    GpuConfig, GpuMode,
};
use vhost_user_backend::VhostUserDaemon;
use vm_memory::{GuestMemoryAtomic, GuestMemoryMmap};

type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, ThisError)]
pub enum Error {
    #[error("Could not create backend: {0}")]
    CouldNotCreateBackend(device::Error),
    #[error("Could not create daemon: {0}")]
    CouldNotCreateDaemon(vhost_user_backend::Error),
    #[error("Fatal error: {0}")]
    ServeFailed(vhost_user_backend::Error),
}

#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
pub struct GpuArgs {
    /// vhost-user Unix domain socket.
    #[clap(short, long, value_name = "SOCKET")]
    pub socket_path: PathBuf,
    #[clap(short, long, value_enum)]
    pub gpu_mode: GpuMode,
}

impl From<GpuArgs> for GpuConfig {
    fn from(args: GpuArgs) -> Self {
        let socket_path = args.socket_path;
        let gpu_mode: GpuMode = args.gpu_mode;

        GpuConfig::new(socket_path, gpu_mode)
    }
}

pub fn start_backend(config: &GpuConfig) -> Result<()> {
    info!("Starting backend");
    let socket = config.socket_path();
    let backend = VhostUserGpuBackend::new(config).map_err(Error::CouldNotCreateBackend)?;

    let mut daemon = VhostUserDaemon::new(
        "vhost-device-gpu-backend".to_string(),
        backend.clone(),
        GuestMemoryAtomic::new(GuestMemoryMmap::new()),
    )
    .map_err(Error::CouldNotCreateDaemon)?;

    backend.set_epoll_handler(&daemon.get_epoll_handlers());

    daemon.serve(socket).map_err(Error::ServeFailed)?;
    Ok(())
}

fn main() {
    env_logger::init();

    if let Err(e) = start_backend(&GpuConfig::from(GpuArgs::parse())) {
        error!("{e}");
        exit(1);
    }
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use assert_matches::assert_matches;
    use tempfile::tempdir;
    use vhost_device_gpu::{GpuConfig, GpuMode};

    use super::{start_backend, Error, GpuArgs};

    impl GpuArgs {
        pub(crate) fn from_args(path: &Path) -> Self {
            Self {
                socket_path: path.to_path_buf(),
                gpu_mode: GpuMode::Gfxstream,
            }
        }
    }

    #[test]
    fn test_parse_successful() {
        let test_dir = tempdir().expect("Could not create a temp test directory.");
        let socket_path = test_dir.path().join("vgpu.sock");

        let cmd_args = GpuArgs::from_args(socket_path.as_path());
        let config = GpuConfig::from(cmd_args);

        assert_eq!(config.socket_path(), socket_path);
    }

    #[test]
    fn test_fail_listener() {
        // This will fail the listeners and thread will panic.
        let socket_name = Path::new("/proc/-1/nonexistent");
        let cmd_args = GpuArgs::from_args(socket_name);
        let config = GpuConfig::from(cmd_args);

        assert_matches!(start_backend(&config).unwrap_err(), Error::ServeFailed(_));
    }
}
