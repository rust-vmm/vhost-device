// Manos Pitsidianakis <manos.pitsidianakis@linaro.org>
// SPDX-License-Identifier: Apache-2.0 or BSD-3-Clause

#[cfg(all(feature = "alsa-backend", target_env = "gnu"))]
mod alsa;
mod null;

#[cfg(all(feature = "pw-backend", target_env = "gnu"))]
mod pipewire;

use std::sync::{Arc, RwLock};

#[cfg(all(feature = "alsa-backend", target_env = "gnu"))]
use self::alsa::AlsaBackend;
use self::null::NullBackend;
#[cfg(all(feature = "pw-backend", target_env = "gnu"))]
use self::pipewire::PwBackend;
use crate::{stream::Stream, BackendType, Result, VirtioSndPcmSetParams};

pub trait AudioBackend {
    fn write(&self, stream_id: u32) -> Result<()>;

    fn read(&self, stream_id: u32) -> Result<()>;

    fn set_parameters(&self, _stream_id: u32, _: VirtioSndPcmSetParams) -> Result<()> {
        Ok(())
    }

    fn prepare(&self, _stream_id: u32) -> Result<()> {
        Ok(())
    }

    fn release(&self, _stream_id: u32) -> Result<()> {
        Ok(())
    }

    fn start(&self, _stream_id: u32) -> Result<()> {
        Ok(())
    }

    fn stop(&self, _stream_id: u32) -> Result<()> {
        Ok(())
    }

    #[cfg(test)]
    fn as_any(&self) -> &dyn std::any::Any;
}

pub fn alloc_audio_backend(
    backend: BackendType,
    streams: Arc<RwLock<Vec<Stream>>>,
) -> Result<Box<dyn AudioBackend + Send + Sync>> {
    log::trace!("allocating audio backend {:?}", backend);
    match backend {
        BackendType::Null => Ok(Box::new(NullBackend::new(streams))),
        #[cfg(all(feature = "pw-backend", target_env = "gnu"))]
        BackendType::Pipewire => {
            Ok(Box::new(PwBackend::new(streams).map_err(|err| {
                crate::Error::UnexpectedAudioBackendError(err.into())
            })?))
        }
        #[cfg(all(feature = "alsa-backend", target_env = "gnu"))]
        BackendType::Alsa => Ok(Box::new(AlsaBackend::new(streams))),
    }
}

#[cfg(test)]
mod tests {
    use std::any::TypeId;

    #[cfg(all(
        any(feature = "pw-backend", feature = "alsa-backend"),
        target_env = "gnu"
    ))]
    use rusty_fork::rusty_fork_test;

    use super::*;

    #[test]
    fn test_alloc_audio_backend_null() {
        crate::init_logger();
        let v = BackendType::Null;
        let value = alloc_audio_backend(v, Default::default()).unwrap();
        assert_eq!(TypeId::of::<NullBackend>(), value.as_any().type_id());
    }

    // `PipewireTestHarness` modifies the process's environment, so this test should
    // be executed on a forked process.
    #[cfg(all(feature = "pw-backend", target_env = "gnu"))]
    rusty_fork_test! {
        #[test]
        fn test_alloc_audio_backend_pipewire() {
            crate::init_logger();
            use pipewire::{
                test_utils::{try_backoff, PipewireTestHarness},
                *,
            };

            let _test_harness = PipewireTestHarness::new();
            let v = BackendType::Pipewire;
            let value = try_backoff(|| alloc_audio_backend(v, Default::default()), std::num::NonZeroU32::new(3)).expect("reached maximum retry count");
            assert_eq!(TypeId::of::<PwBackend>(), value.as_any().type_id());
        }
    }

    // `setup_alsa_conf` modifies the process's environment, so this test should be
    // executed on a forked process.
    #[cfg(all(feature = "alsa-backend", target_env = "gnu"))]
    rusty_fork_test! {
        #[test]
        fn test_alloc_audio_backend_alsa() {
            crate::init_logger();
            let _harness = alsa::test_utils::setup_alsa_conf();
            let v = BackendType::Alsa;
            let value = alloc_audio_backend(v, Default::default()).unwrap();
            assert_eq!(TypeId::of::<AlsaBackend>(), value.as_any().type_id());
        }
    }
}
