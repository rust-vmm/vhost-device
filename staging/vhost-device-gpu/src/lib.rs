// Copyright 2024 Red Hat Inc
//
// SPDX-License-Identifier: Apache-2.0 or BSD-3-Clause

pub mod device;
pub mod protocol;
pub mod virtio_gpu;

use std::path::PathBuf;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GpuMode {
    ModeVirglRenderer,
    ModeGfxstream,
}

#[derive(Debug, Clone)]
/// This structure is the public API through which an external program
/// is allowed to configure the backend.
pub struct GpuConfig {
    /// vhost-user Unix domain socket
    socket_path: PathBuf,
    renderer: GpuMode,
}

impl GpuConfig {
    /// Create a new instance of the GpuConfig struct, containing the
    /// parameters to be fed into the gpu-backend server.
    pub const fn new(socket_path: PathBuf, renderer: GpuMode) -> Self {
        Self {
            socket_path,
            renderer,
        }
    }

    /// Return the path of the unix domain socket which is listening to
    /// requests from the guest.
    pub fn get_socket_path(&self) -> PathBuf {
        PathBuf::from(&self.socket_path.as_path())
    }

    pub fn get_renderer(&self) -> GpuMode {
        self.renderer
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_gpu_config() {
        // Test the creation of GpuConfig struct
        let socket_path = PathBuf::from("/tmp/socket");
        let gpu_config = GpuConfig::new(socket_path.clone(), GpuMode::ModeVirglRenderer);
        assert_eq!(gpu_config.get_socket_path(), socket_path);
    }
}
