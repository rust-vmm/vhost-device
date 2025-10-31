// src/backend/mod.rs

mod common;
#[cfg(feature = "backend-gfxstream")]
pub mod gfxstream;
#[cfg(feature = "backend-virgl")]
pub mod virgl;

use std::{fmt::Display, io::Result as IoResult};

use clap::ValueEnum;
use vhost::vhost_user::GpuBackend;
use vhost_user_backend::VringRwLock;

use crate::{renderer::Renderer, GpuConfig};

#[derive(ValueEnum, Debug, Clone, Copy, PartialEq, Eq)]
pub enum BackendKind {
    #[cfg(feature = "backend-virgl")]
    Virgl,
    #[cfg(feature = "backend-gfxstream")]
    Gfxstream,
}

impl Display for BackendKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            #[cfg(feature = "backend-virgl")]
            Self::Virgl => write!(f, "virgl"),
            #[cfg(feature = "backend-gfxstream")]
            Self::Gfxstream => write!(f, "gfxstream"),
        }
    }
}

pub fn load_backend(
    kind: BackendKind,
    queue_ctl: &VringRwLock,
    config: &GpuConfig,
    gpu_backend: GpuBackend,
) -> IoResult<Box<dyn Renderer>> {
    match kind {
        #[cfg(feature = "backend-virgl")]
        BackendKind::Virgl => Ok(Box::new(virgl::VirglRendererAdapter::new(
            queue_ctl,
            config,
            gpu_backend,
        ))),
        #[cfg(feature = "backend-gfxstream")]
        BackendKind::Gfxstream => Ok(Box::new(gfxstream::GfxstreamAdapter::new(
            queue_ctl,
            config,
            gpu_backend,
        ))),
    }
}

#[cfg(test)]
mod backend_mod_tests {
    use std::{collections::HashSet, os::unix::net::UnixStream};

    use clap::ValueEnum;
    use rusty_fork::rusty_fork_test;
    use vm_memory::{GuestAddress, GuestMemoryAtomic, GuestMemoryMmap};

    use super::*;
    use crate::{
        renderer::Renderer,
        testutils::{create_vring, TestingDescChainArgs},
        GpuCapset, GpuFlags, GpuMode,
    };

    fn dummy_gpu_backend() -> GpuBackend {
        let (_, backend) = UnixStream::pair().unwrap();
        GpuBackend::from_stream(backend)
    }

    /// Ensure Display and `ValueEnum` mapping expose the expected names.
    #[test]
    fn backendkind_display_and_values() {
        let names: HashSet<String> = BackendKind::value_variants()
            .iter()
            .filter_map(|v| v.to_possible_value())
            .map(|pv| pv.get_name().to_owned()) // <- own it
            .collect();

        #[cfg(feature = "backend-gfxstream")]
        {
            assert!(names.contains("gfxstream"));
            assert_eq!(BackendKind::Gfxstream.to_string(), "gfxstream");
        }

        #[cfg(feature = "backend-virgl")]
        {
            assert!(names.contains("virgl"));
            assert_eq!(BackendKind::Virgl.to_string(), "virgl");
        }
    }

    /// Build a minimal ready vring (same path as in other tests).
    fn ready_vring() -> vhost_user_backend::VringRwLock {
        let mem = GuestMemoryAtomic::new(
            GuestMemoryMmap::from_ranges(&[(GuestAddress(0), 0x20_000)]).unwrap(),
        );
        let chains: [TestingDescChainArgs; 0] = [];
        let (vring, _outs, _call_evt) = create_vring(
            &mem,
            &chains,
            GuestAddress(0x2000),
            GuestAddress(0x4000),
            64,
        );
        vring
    }

    rusty_fork_test! {
        #[cfg(feature = "backend-virgl")]
        #[test]
        fn load_backend_virgl_constructs_renderer() {
            let vring = ready_vring();

            // Typical config for virgl
            let cfg = GpuConfig::new(
                GpuMode::VirglRenderer,
                Some(GpuCapset::VIRGL | GpuCapset::VIRGL2),
                GpuFlags::default(),
            )
            .expect("GpuConfig");

            let gpu_backend = dummy_gpu_backend();

            let renderer: Box<dyn Renderer> =
                super::load_backend(BackendKind::Virgl, &vring, &cfg, gpu_backend)
                    .expect("load_backend virgl");

            renderer.display_info().unwrap_err();
        }
    }
}
