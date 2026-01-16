// VIRTIO GPU Emulation via vhost-user
//
// Copyright 2024 Red Hat Inc
//
// SPDX-License-Identifier: Apache-2.0 or BSD-3-Clause

use std::{path::PathBuf, process::exit};

use clap::{ArgAction, Parser, ValueEnum};
use log::error;
use vhost_device_gpu::{
    start_backend, GpuCapset, GpuConfig, GpuConfigBuilder, GpuConfigError, GpuFlags, GpuMode,
};

#[derive(ValueEnum, Debug, Copy, Clone, Eq, PartialEq)]
#[repr(u64)]
// __Null is a placeholder to prevent a zero-variant enum when building with
// --no-default-features, not an implementation of the non-exhaustive pattern
#[allow(clippy::manual_non_exhaustive)]
pub enum CapsetName {
    /// [virglrenderer] OpenGL implementation, superseded by Virgl2
    #[cfg(feature = "backend-virgl")]
    Virgl = GpuCapset::VIRGL.bits(),

    /// [virglrenderer] OpenGL implementation
    #[cfg(feature = "backend-virgl")]
    Virgl2 = GpuCapset::VIRGL2.bits(),

    /// [gfxstream] Vulkan implementation (partial support only){n}
    /// NOTE: Can only be used for 2D display output for now, there is no
    /// hardware acceleration yet
    #[cfg(feature = "backend-gfxstream")]
    GfxstreamVulkan = GpuCapset::GFXSTREAM_VULKAN.bits(),

    /// [gfxstream] OpenGL ES implementation (partial support only){n}
    /// NOTE: Can only be used for 2D display output for now, there is no
    /// hardware acceleration yet
    #[cfg(feature = "backend-gfxstream")]
    GfxstreamGles = GpuCapset::GFXSTREAM_GLES.bits(),

    /// Placeholder variant to prevent zero-variant enum when no backend
    /// features are enabled. The null backend doesn't use capsets, so this
    /// maps to GpuCapset::empty().
    #[doc(hidden)]
    __Null = 0,
}

impl From<CapsetName> for GpuCapset {
    fn from(capset_name: CapsetName) -> GpuCapset {
        if matches!(capset_name, CapsetName::__Null) {
            return GpuCapset::empty();
        }

        GpuCapset::from_bits(capset_name as u64)
            .expect("Internal error: CapsetName enum is incorrectly defined")
    }
}

pub fn capset_names_into_capset(capset_names: impl IntoIterator<Item = CapsetName>) -> GpuCapset {
    capset_names
        .into_iter()
        .map(CapsetName::into)
        .fold(GpuCapset::empty(), GpuCapset::union)
}

#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
pub struct GpuArgs {
    /// vhost-user Unix domain socket.
    #[clap(short, long, value_name = "SOCKET")]
    pub socket_path: PathBuf,

    /// The mode specifies which backend implementation to use
    #[clap(short, long, value_enum)]
    pub gpu_mode: GpuMode,

    /// Comma separated list of enabled capsets
    #[clap(short, long, value_delimiter = ',')]
    pub capset: Option<Vec<CapsetName>>,

    #[clap(flatten)]
    pub flags: GpuFlagsArgs,
}

#[derive(Parser, Debug)]
#[allow(clippy::struct_excessive_bools)]
pub struct GpuFlagsArgs {
    /// Enable backend to use EGL
    #[clap(
            long,
            action = ArgAction::Set,
            default_value_t = GpuFlags::new_default().use_egl
    )]
    pub use_egl: bool,

    /// Enable backend to use GLX
    #[clap(
            long,
            action = ArgAction::Set,
            default_value_t = GpuFlags::new_default().use_glx
    )]
    pub use_glx: bool,

    /// Enable backend to use GLES
    #[clap(
            long,
            action = ArgAction::Set,
            default_value_t = GpuFlags::new_default().use_gles
    )]
    pub use_gles: bool,

    /// Enable surfaceless backend option
    #[clap(
            long,
            action = ArgAction::Set,
            default_value_t = GpuFlags::new_default().use_surfaceless
    )]
    pub use_surfaceless: bool,

    /// Enable headless mode (no display output)
    #[clap(long, action = ArgAction::SetTrue, default_value_t = false)]
    pub headless: bool,
}

impl From<GpuFlagsArgs> for GpuFlags {
    fn from(args: GpuFlagsArgs) -> Self {
        GpuFlags {
            use_egl: args.use_egl,
            use_glx: args.use_glx,
            use_gles: args.use_gles,
            use_surfaceless: args.use_surfaceless,
            headless: args.headless,
        }
    }
}

pub fn config_from_args(args: GpuArgs) -> Result<(PathBuf, GpuConfig), GpuConfigError> {
    let flags = GpuFlags::from(args.flags);
    let capset = args.capset.map(capset_names_into_capset);
    let mut builder = GpuConfigBuilder::default()
        .set_gpu_mode(args.gpu_mode)
        .set_flags(flags);
    if let Some(capset) = capset {
        builder = builder.set_capset(capset);
    }

    let config = builder.build()?;
    Ok((args.socket_path, config))
}

pub fn main() {
    env_logger::init();

    let args = GpuArgs::parse();

    let (socket_path, config) = match config_from_args(args) {
        Ok(config) => config,
        Err(e) => {
            error!("{e}");
            exit(1);
        }
    };

    if let Err(e) = start_backend(&socket_path, config) {
        error!("{e}");
        exit(1);
    }
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use clap::{Parser, ValueEnum};
    use vhost_device_gpu::{GpuCapset, GpuFlags, GpuMode};

    use super::*;

    #[test]
    fn test_capset_enum_in_sync_with_capset_bitset() {
        // Convert each GpuCapset into CapsetName
        for capset in GpuCapset::all().iter() {
            let display_name = capset.to_string();
            let capset_name = CapsetName::from_str(&display_name, false).unwrap();
            let resulting_capset: GpuCapset = capset_name.into();
            assert_eq!(resulting_capset, capset);
        }

        // Convert each CapsetName into GpuCapset
        for capset_name in CapsetName::value_variants().iter().copied() {
            let resulting_capset: GpuCapset = capset_name.into(); // Would panic! if the definition is incorrect
            assert_eq!(resulting_capset.bits(), capset_name as u64);
        }
    }

    #[test]
    fn test_default_cli_flags() {
        // The default CLI flags should match GpuFlags::default()
        let args: &[&str] = &[];
        let flag_args = GpuFlagsArgs::parse_from(args);
        let flags: GpuFlags = flag_args.into();
        assert_eq!(flags, GpuFlags::default());
    }

    #[test]
    fn test_config_from_args() {
        let expected_path = Path::new("/some/test/path");
        let args = GpuArgs {
            socket_path: expected_path.into(),
            gpu_mode: GpuMode::VirglRenderer,
            capset: Some(vec![CapsetName::Virgl, CapsetName::Virgl2]),
            flags: GpuFlagsArgs {
                use_egl: false,
                use_glx: true,
                use_gles: false,
                use_surfaceless: false,
                headless: false,
            },
        };

        let (socket_path, config) = config_from_args(args).unwrap();

        assert_eq!(socket_path, expected_path);
        assert_eq!(
            *config.flags(),
            GpuFlags {
                use_egl: false,
                use_glx: true,
                use_gles: false,
                use_surfaceless: false,
                headless: false,
            }
        );
        assert_eq!(config.gpu_mode(), GpuMode::VirglRenderer);
        assert_eq!(config.capsets(), GpuCapset::VIRGL | GpuCapset::VIRGL2)
    }
}
