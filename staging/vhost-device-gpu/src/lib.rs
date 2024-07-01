// Copyright 2024 Red Hat Inc
//
// SPDX-License-Identifier: Apache-2.0 or BSD-3-Clause

pub mod device;
pub mod protocol;
pub mod virtio_gpu;

use std::path::PathBuf;

#[derive(Debug, Clone)]
/// This structure is the public API through which an external program
/// is allowed to configure the backend.
pub struct GpuConfig {
    /// vhost-user Unix domain socket
    socket_path: PathBuf,
}

impl GpuConfig {
    /// Create a new instance of the GpuConfig struct, containing the
    /// parameters to be fed into the gpu-backend server.
    pub const fn new(socket_path: PathBuf) -> Self {
        Self { socket_path }
    }

    /// Return the path of the unix domain socket which is listening to
    /// requests from the guest.
    pub fn get_socket_path(&self) -> PathBuf {
        PathBuf::from(&self.socket_path.clone())
    }
}

#[derive(Debug)]
pub enum GpuError {
    /// Failed to create event fd.
    EventFd(std::io::Error),
    /// Failed to decode incoming command.
    DecodeCommand(std::io::Error),
    /// Error writing to the Queue.
    WriteDescriptor(std::io::Error),
    /// Error reading Guest Memory,
    GuestMemory,
}

#[cfg(test)]
mod tests {
    use super::*;
    use assert_matches::assert_matches;
    use std::io;

    #[test]
    fn test_gpu_config() {
        // Test the creation of GpuConfig struct
        let socket_path = PathBuf::from("/tmp/socket");
        let gpu_config = GpuConfig::new(socket_path.clone());
        assert_eq!(gpu_config.get_socket_path(), socket_path);
    }

    #[test]
    fn test_gpu_error() {
        // Test GPU error variants
        let event_fd_error = GpuError::EventFd(io::Error::from(io::ErrorKind::NotFound));
        assert_matches!(event_fd_error, GpuError::EventFd(_));

        let decode_error = GpuError::DecodeCommand(io::Error::from(io::ErrorKind::InvalidData));
        assert_matches!(decode_error, GpuError::DecodeCommand(_));

        let write_error =
            GpuError::WriteDescriptor(io::Error::from(io::ErrorKind::PermissionDenied));
        assert_matches!(write_error, GpuError::WriteDescriptor(_));

        let guest_memory_error = GpuError::GuestMemory;
        assert_matches!(guest_memory_error, GpuError::GuestMemory);
    }
}
