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

use std::{
    fmt::{Display, Formatter},
    path::Path,
};

use bitflags::bitflags;
use clap::ValueEnum;
use log::info;
#[cfg(feature = "gfxstream")]
use rutabaga_gfx::{RUTABAGA_CAPSET_GFXSTREAM_GLES, RUTABAGA_CAPSET_GFXSTREAM_VULKAN};
use rutabaga_gfx::{RUTABAGA_CAPSET_VIRGL, RUTABAGA_CAPSET_VIRGL2};
use thiserror::Error as ThisError;
use vhost_user_backend::VhostUserDaemon;
use vm_memory::{GuestMemoryAtomic, GuestMemoryMmap};

use crate::device::VhostUserGpuBackend;

#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
pub enum GpuMode {
    #[value(name = "virglrenderer", alias("virgl-renderer"))]
    VirglRenderer,
    #[cfg(feature = "gfxstream")]
    Gfxstream,
}

impl Display for GpuMode {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::VirglRenderer => write!(f, "virglrenderer"),
            #[cfg(feature = "gfxstream")]
            Self::Gfxstream => write!(f, "gfxstream"),
        }
    }
}

bitflags! {
    /// A bitmask for representing supported gpu capability sets.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct GpuCapset: u64 {
        const VIRGL = 1 << RUTABAGA_CAPSET_VIRGL as u64;
        const VIRGL2 = 1 << RUTABAGA_CAPSET_VIRGL2 as u64;
        const ALL_VIRGLRENDERER_CAPSETS = Self::VIRGL.bits() | Self::VIRGL2.bits();

        #[cfg(feature = "gfxstream")]
        const GFXSTREAM_VULKAN = 1 << RUTABAGA_CAPSET_GFXSTREAM_VULKAN as u64;
        #[cfg(feature = "gfxstream")]
        const GFXSTREAM_GLES = 1 << RUTABAGA_CAPSET_GFXSTREAM_GLES as u64;
        #[cfg(feature = "gfxstream")]
        const ALL_GFXSTREAM_CAPSETS = Self::GFXSTREAM_VULKAN.bits() | Self::GFXSTREAM_GLES.bits();
    }
}

impl Display for GpuCapset {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let mut first = true;
        for capset in self.iter() {
            if !first {
                write!(f, ", ")?;
            }
            first = false;

            match capset {
                Self::VIRGL => write!(f, "virgl"),
                Self::VIRGL2 => write!(f, "virgl2"),
                #[cfg(feature = "gfxstream")]
                Self::GFXSTREAM_VULKAN => write!(f, "gfxstream-vulkan"),
                #[cfg(feature = "gfxstream")]
                Self::GFXSTREAM_GLES => write!(f, "gfxstream-gles"),
                _ => panic!("Unknown capset {:#x}", self.bits()),
            }?;
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
    CapsetUnsuportedByMode(GpuMode, GpuCapset),
    #[error("Requested gfxstream-gles capset, but gles is disabled")]
    GlesRequiredByGfxstream,
}

impl GpuConfig {
    pub const DEFAULT_VIRGLRENDER_CAPSET_MASK: GpuCapset = GpuCapset::ALL_VIRGLRENDERER_CAPSETS;

    #[cfg(feature = "gfxstream")]
    pub const DEFAULT_GFXSTREAM_CAPSET_MASK: GpuCapset = GpuCapset::ALL_GFXSTREAM_CAPSETS;

    pub const fn get_default_capset_for_mode(gpu_mode: GpuMode) -> GpuCapset {
        match gpu_mode {
            GpuMode::VirglRenderer => Self::DEFAULT_VIRGLRENDER_CAPSET_MASK,
            #[cfg(feature = "gfxstream")]
            GpuMode::Gfxstream => Self::DEFAULT_GFXSTREAM_CAPSET_MASK,
        }
    }

    fn validate_capset(gpu_mode: GpuMode, capset: GpuCapset) -> Result<(), GpuConfigError> {
        let supported_capset_mask = match gpu_mode {
            GpuMode::VirglRenderer => GpuCapset::ALL_VIRGLRENDERER_CAPSETS,
            #[cfg(feature = "gfxstream")]
            GpuMode::Gfxstream => GpuCapset::ALL_GFXSTREAM_CAPSETS,
        };
        for capset in capset.iter() {
            if !supported_capset_mask.contains(capset) {
                return Err(GpuConfigError::CapsetUnsuportedByMode(gpu_mode, capset));
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

        #[cfg(feature = "gfxstream")]
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

    #[cfg(feature = "gfxstream")]
    use assert_matches::assert_matches;
    use clap::ValueEnum;

    use super::*;

    #[test]
    fn test_gpu_config_create_default_virglrenderer() {
        let config = GpuConfig::new(GpuMode::VirglRenderer, None, GpuFlags::new_default()).unwrap();
        assert_eq!(config.gpu_mode(), GpuMode::VirglRenderer);
        assert_eq!(config.capsets(), GpuConfig::DEFAULT_VIRGLRENDER_CAPSET_MASK);
    }

    #[test]
    #[cfg(feature = "gfxstream")]
    fn test_gpu_config_create_default_gfxstream() {
        let config = GpuConfig::new(GpuMode::Gfxstream, None, GpuFlags::default()).unwrap();
        assert_eq!(config.gpu_mode(), GpuMode::Gfxstream);
        assert_eq!(config.capsets(), GpuConfig::DEFAULT_GFXSTREAM_CAPSET_MASK);
    }

    #[cfg(feature = "gfxstream")]
    fn assert_invalid_gpu_config(mode: GpuMode, capset: GpuCapset, expected_capset: GpuCapset) {
        let result = GpuConfig::new(mode, Some(capset), GpuFlags::new_default());
        assert_matches!(
            result,
            Err(GpuConfigError::CapsetUnsuportedByMode(
                requested_mode,
                unsupported_capset
            )) if unsupported_capset == expected_capset && requested_mode == mode
        );
    }

    #[test]
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
    #[cfg(feature = "gfxstream")]
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
    #[cfg(feature = "gfxstream")]
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
        assert_eq!(GpuConfig::DEFAULT_VIRGLRENDER_CAPSET_MASK.num_capsets(), 2);
        #[cfg(feature = "gfxstream")]
        assert_eq!(GpuConfig::DEFAULT_GFXSTREAM_CAPSET_MASK.num_capsets(), 2);
    }

    #[test]
    fn test_capset_display_multiple() {
        let capset = GpuCapset::VIRGL | GpuCapset::VIRGL2;
        let output = capset.to_string();
        assert_eq!(output, "virgl, virgl2")
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
