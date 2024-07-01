// VIRTIO GPU Emulation via vhost-user
//
// Copyright 2024 Red Hat Inc
//
// SPDX-License-Identifier: Apache-2.0 or BSD-3-Clause

use log::{error, info};
use std::{path::PathBuf, process::exit};

use clap::Parser;
use thiserror::Error as ThisError;
use vhost_device_gpu::{
    device::{self, VhostUserGpuBackend},
    GpuConfig,
};
use vhost_user_backend::VhostUserDaemon;
use vm_memory::{GuestMemoryAtomic, GuestMemoryMmap};

type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, ThisError)]
pub(crate) enum Error {
    #[error("Could not create backend: {0}")]
    CouldNotCreateBackend(device::Error),
    #[error("Could not create daemon: {0}")]
    CouldNotCreateDaemon(vhost_user_backend::Error),
    #[error("Fatal error: {0}")]
    ServeFailed(vhost_user_backend::Error),
}

#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
struct GpuArgs {
    /// vhost-user Unix domain socket.
    #[clap(short, long, value_name = "SOCKET")]
    socket_path: PathBuf,
}

impl TryFrom<GpuArgs> for GpuConfig {
    type Error = Error;

    fn try_from(args: GpuArgs) -> Result<Self> {
        let socket_path = args.socket_path;

        Ok(GpuConfig::new(socket_path))
    }
}

fn start_backend(config: GpuConfig) -> Result<()> {
    info!("Starting backend");
    let socket = config.get_socket_path();
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

    if let Err(e) = start_backend(GpuConfig::try_from(GpuArgs::parse()).unwrap()) {
        error!("{e}");
        exit(1);
    }
}

#[cfg(test)]
mod tests {
    use assert_matches::assert_matches;
    use std::path::Path;

    use super::*;

    impl GpuArgs {
        pub(crate) fn from_args(path: &Path) -> GpuArgs {
            GpuArgs {
                socket_path: path.to_path_buf(),
            }
        }
    }

    #[test]
    fn test_parse_successful() {
        let socket_name = Path::new("vgpu.sock");

        let cmd_args = GpuArgs::from_args(socket_name);
        let config = GpuConfig::try_from(cmd_args);

        assert!(config.is_ok());

        let config = config.unwrap();
        assert_eq!(config.get_socket_path(), socket_name);
    }

    #[test]
    fn test_fail_listener() {
        // This will fail the listeners and thread will panic.
        let socket_name = Path::new("~/path/not/present/gpu");
        let cmd_args = GpuArgs::from_args(socket_name);
        let config = GpuConfig::try_from(cmd_args).unwrap();

        assert_matches!(start_backend(config).unwrap_err(), Error::ServeFailed(_));
    }
}
