// Copyright 2024 Red Hat Inc
//
// SPDX-License-Identifier: Apache-2.0 or BSD-3-Clause

#![allow(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::cloned_ref_to_slice_refs,
    clippy::must_use_candidate
)]

pub mod device;
pub mod protocol;
// Module for backends
pub mod backend;
// Module for the common renderer trait
pub mod gpu_types;
pub mod renderer;
#[cfg(test)]
pub(crate) mod testutils;

use std::{
    fmt::{Display, Formatter},
    path::Path,
};

use bitflags::bitflags;
use clap::ValueEnum;
use log::info;
#[cfg(feature = "backend-gfxstream")]
use rutabaga_gfx::{RUTABAGA_CAPSET_GFXSTREAM_GLES, RUTABAGA_CAPSET_GFXSTREAM_VULKAN};
#[cfg(feature = "backend-virgl")]
use rutabaga_gfx::{RUTABAGA_CAPSET_VIRGL, RUTABAGA_CAPSET_VIRGL2};
use thiserror::Error as ThisError;
use vhost_user_backend::VhostUserDaemon;
use vm_memory::{GuestMemoryAtomic, GuestMemoryMmap};

use crate::device::VhostUserGpuBackend;

#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
pub enum GpuMode {
    #[value(name = "virglrenderer", alias("virgl-renderer"))]
    #[cfg(feature = "backend-virgl")]
    VirglRenderer,
    #[cfg(feature = "backend-gfxstream")]
    Gfxstream,
    Null,
}

impl Display for GpuMode {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            #[cfg(feature = "backend-virgl")]
            Self::VirglRenderer => write!(f, "virglrenderer"),
            #[cfg(feature = "backend-gfxstream")]
            Self::Gfxstream => write!(f, "gfxstream"),
            Self::Null => write!(f, "null"),
        }
    }
}

bitflags! {
    /// A bitmask for representing supported gpu capability sets.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct GpuCapset: u64 {
        #[cfg(feature = "backend-virgl")]
        const VIRGL = 1 << RUTABAGA_CAPSET_VIRGL as u64;
        #[cfg(feature = "backend-virgl")]
        const VIRGL2 = 1 << RUTABAGA_CAPSET_VIRGL2 as u64;
        #[cfg(feature = "backend-virgl")]
        const ALL_VIRGLRENDERER_CAPSETS = Self::VIRGL.bits() | Self::VIRGL2.bits();

        #[cfg(feature = "backend-gfxstream")]
        const GFXSTREAM_VULKAN = 1 << RUTABAGA_CAPSET_GFXSTREAM_VULKAN as u64;
        #[cfg(feature = "backend-gfxstream")]
        const GFXSTREAM_GLES = 1 << RUTABAGA_CAPSET_GFXSTREAM_GLES as u64;
        #[cfg(feature = "backend-gfxstream")]
        const ALL_GFXSTREAM_CAPSETS = Self::GFXSTREAM_VULKAN.bits() | Self::GFXSTREAM_GLES.bits();
    }
}

impl Display for GpuCapset {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        if self.is_empty() {
            return write!(f, "none");
        }

        let mut first = true;
        #[allow(unused_assignments)]
        for capset in self.iter() {
            if !first {
                write!(f, ", ")?;
            }
            first = false;

            match capset {
                #[cfg(feature = "backend-virgl")]
                Self::VIRGL => write!(f, "virgl")?,
                #[cfg(feature = "backend-virgl")]
                Self::VIRGL2 => write!(f, "virgl2")?,
                #[cfg(feature = "backend-gfxstream")]
                Self::GFXSTREAM_VULKAN => write!(f, "gfxstream-vulkan")?,
                #[cfg(feature = "backend-gfxstream")]
                Self::GFXSTREAM_GLES => write!(f, "gfxstream-gles")?,
                _ => panic!("Unknown capset {:#x}", self.bits()),
            }
        }

        Ok(())
    }
}

impl GpuCapset {
    /// Return the number of enabled capsets
    pub const fn num_capsets(self) -> u32 {
        self.bits().count_ones()
    }
}

#[derive(Debug, Clone)]
/// This structure holds the configuration for the GPU backend
pub struct GpuConfig {
    gpu_mode: GpuMode,
    capset: GpuCapset,
    flags: GpuFlags,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GpuFlags {
    pub use_egl: bool,
    pub use_glx: bool,
    pub use_gles: bool,
    pub use_surfaceless: bool,
}

impl GpuFlags {
    // `const` version of `default()`
    pub const fn new_default() -> Self {
        Self {
            use_egl: true,
            use_glx: false,
            use_gles: true,
            use_surfaceless: true,
        }
    }
}

impl Default for GpuFlags {
    fn default() -> Self {
        Self::new_default()
    }
}

#[derive(Debug, ThisError)]
pub enum GpuConfigError {
    #[error("The mode {0} does not support {1} capset")]
    CapsetUnsupportedByMode(GpuMode, GpuCapset),
    #[error("Requested gfxstream-gles capset, but gles is disabled")]
    GlesRequiredByGfxstream,
}

impl GpuConfig {
    #[cfg(feature = "backend-virgl")]
    pub const DEFAULT_VIRGLRENDER_CAPSET_MASK: GpuCapset = GpuCapset::ALL_VIRGLRENDERER_CAPSETS;

    #[cfg(feature = "backend-gfxstream")]
    pub const DEFAULT_GFXSTREAM_CAPSET_MASK: GpuCapset = GpuCapset::ALL_GFXSTREAM_CAPSETS;

    pub const fn get_default_capset_for_mode(gpu_mode: GpuMode) -> GpuCapset {
        match gpu_mode {
            #[cfg(feature = "backend-virgl")]
            GpuMode::VirglRenderer => Self::DEFAULT_VIRGLRENDER_CAPSET_MASK,
            #[cfg(feature = "backend-gfxstream")]
            GpuMode::Gfxstream => Self::DEFAULT_GFXSTREAM_CAPSET_MASK,
            GpuMode::Null => GpuCapset::empty(),
        }
    }

    fn validate_capset(gpu_mode: GpuMode, capset: GpuCapset) -> Result<(), GpuConfigError> {
        let supported_capset_mask = match gpu_mode {
            #[cfg(feature = "backend-virgl")]
            GpuMode::VirglRenderer => GpuCapset::ALL_VIRGLRENDERER_CAPSETS,
            #[cfg(feature = "backend-gfxstream")]
            GpuMode::Gfxstream => GpuCapset::ALL_GFXSTREAM_CAPSETS,
            GpuMode::Null => GpuCapset::empty(),
        };
        for capset in capset.iter() {
            if !supported_capset_mask.contains(capset) {
                return Err(GpuConfigError::CapsetUnsupportedByMode(gpu_mode, capset));
            }
        }

        Ok(())
    }

    /// Create a new instance of the `GpuConfig` struct, containing the
    /// parameters to be fed into the gpu-backend server.
    pub fn new(
        gpu_mode: GpuMode,
        capset: Option<GpuCapset>,
        flags: GpuFlags,
    ) -> Result<Self, GpuConfigError> {
        let capset = capset.unwrap_or_else(|| Self::get_default_capset_for_mode(gpu_mode));
        Self::validate_capset(gpu_mode, capset)?;

        #[cfg(feature = "backend-gfxstream")]
        if capset.contains(GpuCapset::GFXSTREAM_GLES) && !flags.use_gles {
            return Err(GpuConfigError::GlesRequiredByGfxstream);
        }

        Ok(Self {
            gpu_mode,
            capset,
            flags,
        })
    }

    pub const fn gpu_mode(&self) -> GpuMode {
        self.gpu_mode
    }

    pub const fn capsets(&self) -> GpuCapset {
        self.capset
    }

    pub const fn flags(&self) -> &GpuFlags {
        &self.flags
    }
}

#[derive(Debug, ThisError)]
pub enum StartError {
    #[error("Could not create backend: {0}")]
    CouldNotCreateBackend(device::Error),
    #[error("Could not create daemon: {0}")]
    CouldNotCreateDaemon(vhost_user_backend::Error),
    #[error("Fatal error: {0}")]
    ServeFailed(vhost_user_backend::Error),
}

pub fn start_backend(socket_path: &Path, config: GpuConfig) -> Result<(), StartError> {
    info!("Starting backend");
    let backend = VhostUserGpuBackend::new(config).map_err(StartError::CouldNotCreateBackend)?;

    let mut daemon = VhostUserDaemon::new(
        "vhost-device-gpu-backend".to_string(),
        backend.clone(),
        GuestMemoryAtomic::new(GuestMemoryMmap::new()),
    )
    .map_err(StartError::CouldNotCreateDaemon)?;

    backend.set_epoll_handler(&daemon.get_epoll_handlers());

    daemon.serve(socket_path).map_err(StartError::ServeFailed)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use assert_matches::assert_matches;

    use super::*;

    #[test]
    #[cfg(feature = "backend-virgl")]
    fn test_gpu_config_create_default_virglrenderer() {
        let config = GpuConfig::new(GpuMode::VirglRenderer, None, GpuFlags::new_default()).unwrap();
        assert_eq!(config.gpu_mode(), GpuMode::VirglRenderer);
        assert_eq!(config.capsets(), GpuConfig::DEFAULT_VIRGLRENDER_CAPSET_MASK);
    }

    #[test]
    #[cfg(feature = "backend-gfxstream")]
    fn test_gpu_config_create_default_gfxstream() {
        let config = GpuConfig::new(GpuMode::Gfxstream, None, GpuFlags::default()).unwrap();
        assert_eq!(config.gpu_mode(), GpuMode::Gfxstream);
        assert_eq!(config.capsets(), GpuConfig::DEFAULT_GFXSTREAM_CAPSET_MASK);
    }

    #[cfg(feature = "backend-gfxstream")]
    fn assert_invalid_gpu_config(mode: GpuMode, capset: GpuCapset, expected_capset: GpuCapset) {
        let result = GpuConfig::new(mode, Some(capset), GpuFlags::new_default());
        assert_matches!(
            result,
            Err(GpuConfigError::CapsetUnsupportedByMode(
                requested_mode,
                unsupported_capset
            )) if unsupported_capset == expected_capset && requested_mode == mode
        );
    }

    #[test]
    #[cfg(feature = "backend-virgl")]
    fn test_gpu_config_valid_combination() {
        let config = GpuConfig::new(
            GpuMode::VirglRenderer,
            Some(GpuCapset::VIRGL2),
            GpuFlags::default(),
        )
        .unwrap();
        assert_eq!(config.gpu_mode(), GpuMode::VirglRenderer);
    }

    #[test]
    #[cfg(feature = "backend-gfxstream")]
    fn test_gpu_config_invalid_combinations() {
        assert_invalid_gpu_config(
            GpuMode::VirglRenderer,
            GpuCapset::VIRGL2 | GpuCapset::GFXSTREAM_VULKAN,
            GpuCapset::GFXSTREAM_VULKAN,
        );

        assert_invalid_gpu_config(
            GpuMode::Gfxstream,
            GpuCapset::VIRGL2 | GpuCapset::GFXSTREAM_VULKAN,
            GpuCapset::VIRGL2,
        );
    }

    #[test]
    #[cfg(feature = "backend-gfxstream")]
    fn test_gles_required_by_gfxstream() {
        let capset = GpuCapset::GFXSTREAM_VULKAN | GpuCapset::GFXSTREAM_GLES;
        let flags = GpuFlags {
            use_gles: false,
            ..GpuFlags::new_default()
        };
        let result = GpuConfig::new(GpuMode::Gfxstream, Some(capset), flags);
        assert_matches!(result, Err(GpuConfigError::GlesRequiredByGfxstream));
    }

    #[test]
    fn test_default_num_capsets() {
        #[cfg(feature = "backend-virgl")]
        assert_eq!(GpuConfig::DEFAULT_VIRGLRENDER_CAPSET_MASK.num_capsets(), 2);
        #[cfg(feature = "backend-gfxstream")]
        assert_eq!(GpuConfig::DEFAULT_GFXSTREAM_CAPSET_MASK.num_capsets(), 2);
    }

    #[test]
    #[cfg(feature = "backend-virgl")]
    fn test_capset_display_multiple() {
        let capset = GpuCapset::VIRGL | GpuCapset::VIRGL2;
        let output = capset.to_string();
        assert_eq!(output, "virgl, virgl2");
    }

    /// Check if display name of GpuMode is the same as the name in the CLI arg
    #[test]
    fn test_gpu_mode_display_eq_arg_name() {
        for mode in GpuMode::value_variants() {
            let mode_str = mode.to_string();
            let mode_from_str = GpuMode::from_str(&mode_str, false);
            assert_eq!(*mode, mode_from_str.unwrap());
        }
    }

    #[test]
    #[cfg(feature = "backend-virgl")]
    fn test_fail_listener() {
        // This will fail the listeners and thread will panic.
        let socket_name = Path::new("/proc/-1/nonexistent");
        let config = GpuConfig::new(GpuMode::VirglRenderer, None, GpuFlags::default()).unwrap();

        assert_matches!(
            start_backend(socket_name, config).unwrap_err(),
            StartError::ServeFailed(_)
        );
    }
}
