// Copyright 2024 Red Hat Inc
//
// SPDX-License-Identifier: Apache-2.0 or BSD-3-Clause

#![deny(
    clippy::undocumented_unsafe_blocks,
    /* groups */
    clippy::correctness,
    clippy::suspicious,
    clippy::complexity,
    clippy::perf,
    clippy::style,
    clippy::nursery,
    //* restriction */
    clippy::dbg_macro,
    clippy::rc_buffer,
    clippy::as_underscore,
    clippy::assertions_on_result_states,
    //* pedantic */
    clippy::cast_lossless,
    clippy::cast_possible_wrap,
    clippy::ptr_as_ptr,
    clippy::bool_to_int_with_if,
    clippy::borrow_as_ptr,
    clippy::case_sensitive_file_extension_comparisons,
    clippy::cast_lossless,
    clippy::cast_ptr_alignment,
    clippy::naive_bytecount
)]
#![allow(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::must_use_candidate,
    clippy::significant_drop_in_scrutinee,
    clippy::significant_drop_tightening
)]

pub mod device;
pub mod protocol;
pub mod virtio_gpu;

use std::path::{Path, PathBuf};

use clap::ValueEnum;
use log::info;
use thiserror::Error as ThisError;
use vhost_user_backend::VhostUserDaemon;
use vm_memory::{GuestMemoryAtomic, GuestMemoryMmap};

use crate::device::VhostUserGpuBackend;

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

#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
pub enum GpuMode {
    #[value(name = "virglrenderer", alias("virgl-renderer"))]
    VirglRenderer,
    #[cfg(feature = "gfxstream")]
    Gfxstream,
}

#[derive(Debug, Clone)]
/// This structure holds the internal configuration for the GPU backend,
/// derived from the command-line arguments provided through `GpuArgs`.
pub struct GpuConfig {
    /// vhost-user Unix domain socket
    socket_path: PathBuf,
    gpu_mode: GpuMode,
}

impl GpuConfig {
    /// Create a new instance of the `GpuConfig` struct, containing the
    /// parameters to be fed into the gpu-backend server.
    pub const fn new(socket_path: PathBuf, gpu_mode: GpuMode) -> Self {
        Self {
            socket_path,
            gpu_mode,
        }
    }

    /// Return the path of the unix domain socket which is listening to
    /// requests from the guest.
    pub fn socket_path(&self) -> &Path {
        &self.socket_path
    }

    pub const fn gpu_mode(&self) -> GpuMode {
        self.gpu_mode
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

#[cfg(test)]
mod tests {
    use std::path::Path;

    use assert_matches::assert_matches;
    use tempfile::tempdir;

    use super::*;

    #[test]
    fn test_gpu_config() {
        // Test the creation of `GpuConfig` struct
        let test_dir = tempdir().expect("Could not create a temp test directory.");
        let socket_path = test_dir.path().join("socket");
        let gpu_config = GpuConfig::new(socket_path.clone(), GpuMode::VirglRenderer);
        assert_eq!(gpu_config.socket_path(), socket_path);
    }

    #[test]
    fn test_fail_listener() {
        // This will fail the listeners and thread will panic.
        let socket_name = Path::new("/proc/-1/nonexistent");
        let config = GpuConfig::new(socket_name.into(), GpuMode::VirglRenderer);

        assert_matches!(start_backend(&config).unwrap_err(), Error::ServeFailed(_));
    }
}
