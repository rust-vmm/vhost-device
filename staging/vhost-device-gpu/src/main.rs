// VIRTIO GPU Emulation via vhost-user
//
// Copyright 2024 Red Hat Inc
//
// SPDX-License-Identifier: Apache-2.0 or BSD-3-Clause

// Rust vmm container (https://github.com/rust-vmm/rust-vmm-container) doesn't
// have tools to do a musl build at the moment, and adding that support is
// tricky as well to the container. Skip musl builds until the time pre-built
// rutabaga library is available for musl.
#[cfg(target_env = "gnu")]
pub mod gnu_main {
    use std::{
        path::{Path, PathBuf},
        process::exit,
    };

    use clap::{ArgAction, Parser, ValueEnum};
    use log::{error, info};
    use thiserror::Error as ThisError;
    use vhost_device_gpu::{
        device, device::VhostUserGpuBackend, GpuCapset, GpuConfig, GpuFlags, GpuMode,
    };
    use vhost_user_backend::VhostUserDaemon;
    use vm_memory::{GuestMemoryAtomic, GuestMemoryMmap};

    #[derive(ValueEnum, Debug, Copy, Clone, Eq, PartialEq)]
    #[repr(u64)]
    pub enum CapsetName {
        /// [virglrenderer] OpenGL implementation, superseded by Virgl2
        Virgl = GpuCapset::VIRGL.bits(),

        /// [virglrenderer] OpenGL implementation
        Virgl2 = GpuCapset::VIRGL2.bits(),

        /// [virglrenderer] Vulkan implementation
        Venus = GpuCapset::VENUS.bits(),

        /// [gfxstream] Vulkan implementation
        #[cfg(feature = "gfxstream")]
        GfxstreamVulkan = GpuCapset::GFXSTREAM_VULKAN.bits(),

        /// [gfxstream] OpenGL ES implementation
        #[cfg(feature = "gfxstream")]
        GfxstreamGles = GpuCapset::GFXSTREAM_GLES.bits(),
    }

    impl From<CapsetName> for GpuCapset {
        fn from(capset_name: CapsetName) -> GpuCapset {
            GpuCapset::from_bits(capset_name as u64)
                .expect("Internal error: CapsetName enum is incorrectly defined")
        }
    }

    pub fn capset_names_into_capset(
        capset_names: impl IntoIterator<Item = CapsetName>,
    ) -> GpuCapset {
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
        socket_path: PathBuf,

        /// The mode specifies which backend implementation to use
        #[clap(short, long, value_enum)]
        gpu_mode: GpuMode,

        /// Comma separated list of enabled capsets
        #[clap(short, long, value_delimiter = ',')]
        capset: Option<Vec<CapsetName>>,

        #[clap(flatten)]
        flags: GpuFlagsArgs,
    }

    #[derive(Parser, Debug)]
    #[allow(clippy::struct_excessive_bools)]
    pub struct GpuFlagsArgs {
        /// Enable backend to use EGL
        #[clap(
            long,
            action=ArgAction::Set,
            default_value_t = GpuFlags::new_default().use_egl
        )]
        use_egl: bool,

        /// Enable backend to use GLX
        #[clap(
            long,
            action=ArgAction::Set,
            default_value_t = GpuFlags::new_default().use_glx
        )]
        use_glx: bool,

        /// Enable backend to use GLES
        #[clap(
            long,
            action=ArgAction::Set,
            default_value_t = GpuFlags::new_default().use_gles
        )]
        use_gles: bool,

        /// Enable surfaceless backend option
        #[clap(
            long,
            action = ArgAction::Set,
            default_value_t = GpuFlags::new_default().use_surfaceless
        )]
        use_surfaceless: bool,
    }

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

    impl From<GpuFlagsArgs> for GpuFlags {
        fn from(args: GpuFlagsArgs) -> Self {
            GpuFlags {
                use_egl: args.use_egl,
                use_glx: args.use_glx,
                use_gles: args.use_gles,
                use_surfaceless: args.use_surfaceless,
            }
        }
    }

    pub fn start_backend(socket_path: &Path, config: GpuConfig) -> Result<()> {
        info!("Starting backend");
        let backend = VhostUserGpuBackend::new(config).map_err(Error::CouldNotCreateBackend)?;

        let mut daemon = VhostUserDaemon::new(
            "vhost-device-gpu-backend".to_string(),
            backend.clone(),
            GuestMemoryAtomic::new(GuestMemoryMmap::new()),
        )
        .map_err(Error::CouldNotCreateDaemon)?;

        backend.set_epoll_handler(&daemon.get_epoll_handlers());

        daemon.serve(socket_path).map_err(Error::ServeFailed)?;
        Ok(())
    }

    pub fn main() {
        env_logger::init();

        let args = GpuArgs::parse();

        let flags = GpuFlags::from(args.flags);
        let capsets = args.capset.map(capset_names_into_capset);

        let config = match GpuConfig::new(args.gpu_mode, capsets, flags) {
            Ok(config) => config,
            Err(e) => {
                error!("{e}");
                exit(1);
            }
        };

        if let Err(e) = start_backend(&args.socket_path, config) {
            error!("{e}");
            exit(1);
        }
    }
}

#[cfg(target_env = "gnu")]
fn main() {
    gnu_main::main();
}

#[cfg(target_env = "musl")]
fn main() {}

#[cfg(target_env = "gnu")]
#[cfg(test)]
mod tests {
    use std::path::Path;

    use assert_matches::assert_matches;
    use clap::ValueEnum;
    use vhost_device_gpu::{GpuCapset, GpuConfig, GpuFlags, GpuMode};

    use super::gnu_main::*;

    #[test]
    fn test_fail_listener() {
        // This will fail the listeners and thread will panic.
        let socket_name = Path::new("/proc/-1/nonexistent");
        let config = GpuConfig::new(GpuMode::VirglRenderer, None, GpuFlags::default()).unwrap();

        assert_matches!(
            start_backend(socket_name, config).unwrap_err(),
            Error::ServeFailed(_)
        );
    }

    #[test]
    fn test_capset_enum_in_sync_with_capset_bitset() {
        // Convert each GpuCapset into CapsetName
        for capset in GpuCapset::all().iter() {
            let display_name = format!("{capset}");
            let capset_name = CapsetName::from_str(&display_name, false).unwrap();
            let resulting_capset: GpuCapset = capset_name.into();
            assert_eq!(resulting_capset, capset);
        }

        // Convert each CapsetName into GpuCapset
        for capset_name in CapsetName::value_variants().iter().cloned() {
            let resulting_capset: GpuCapset = capset_name.into(); // Would panic! if the definition is incorrect
            assert_eq!(resulting_capset.bits(), capset_name as u64)
        }
    }

    #[test]
    fn test_capset_names_into_capset() {
        let capset_names = [CapsetName::Virgl, CapsetName::Virgl2, CapsetName::Venus];
        let capset = capset_names_into_capset(capset_names);
        assert_eq!(
            capset,
            GpuCapset::VIRGL | GpuCapset::VIRGL2 | GpuCapset::VENUS
        )
    }
}
