// Manos Pitsidianakis <manos.pitsidianakis@linaro.org>
// SPDX-License-Identifier: Apache-2.0 or BSD-3-Clause

#[cfg(feature = "alsa-backend")]
mod alsa;
#[cfg(feature = "null-backend")]
mod null;

#[cfg(feature = "pw-backend")]
mod pipewire;

use std::sync::{Arc, RwLock};

#[cfg(feature = "alsa-backend")]
use self::alsa::AlsaBackend;
#[cfg(feature = "null-backend")]
use self::null::NullBackend;
#[cfg(feature = "pw-backend")]
use self::pipewire::PwBackend;
use crate::{device::ControlMessage, stream::Stream, BackendType, Error, Result};

pub trait AudioBackend {
    fn write(&self, stream_id: u32) -> Result<()>;

    fn read(&self, stream_id: u32) -> Result<()>;

    fn set_parameters(&self, _stream_id: u32, _: ControlMessage) -> Result<()> {
        Ok(())
    }

    fn prepare(&self, _stream_id: u32) -> Result<()> {
        Ok(())
    }

    fn release(&self, _stream_id: u32, _: ControlMessage) -> Result<()> {
        Ok(())
    }

    fn start(&self, _stream_id: u32) -> Result<()> {
        Ok(())
    }

    fn stop(&self, _stream_id: u32) -> Result<()> {
        Ok(())
    }
}

pub fn alloc_audio_backend(
    backend: BackendType,
    // Unused when compiled with no features.
    #[allow(unused_variables)] streams: Arc<RwLock<Vec<Stream>>>,
) -> Result<Box<dyn AudioBackend + Send + Sync>> {
    log::trace!("allocating audio backend {:?}", backend);
    match backend {
        #[cfg(feature = "null-backend")]
        BackendType::Null => Ok(Box::new(NullBackend::new(streams))),
        #[cfg(feature = "pw-backend")]
        BackendType::Pipewire => Ok(Box::new(PwBackend::new(streams))),
        #[cfg(feature = "alsa-backend")]
        BackendType::Alsa => Ok(Box::new(AlsaBackend::new(streams))),
        // By default all features are enabled and this branch is unreachable.
        // Nonetheless, it is required when inidividual features (or no features
        // at all) are enabled.
        // To avoid having a complicated compilation condition and make the
        // code more maintainable, we supress the unreachable_patterns warning.
        #[allow(unreachable_patterns)]
        _ => Err(Error::AudioBackendNotSupported),
    }
}
