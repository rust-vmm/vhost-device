// VIRTIO GPU Emulation via vhost-user
//
// Copyright 2024 Red Hat Inc
//
// SPDX-License-Identifier: Apache-2.0 or BSD-3-Clause

use std::{path::PathBuf, process::exit};

use clap::Parser;
use log::error;
use vhost_device_gpu::{start_backend, GpuConfig, GpuMode};

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

    use tempfile::tempdir;
    use vhost_device_gpu::{GpuConfig, GpuMode};

    use super::*;

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
}
