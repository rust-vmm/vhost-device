// Manos Pitsidianakis <manos.pitsidianakis@linaro.org>
// SPDX-License-Identifier: Apache-2.0 or BSD-3-Clause

#[cfg(feature = "alsa-backend")]
mod alsa;
mod null;

#[cfg(feature = "pw-backend")]
mod pipewire;

use std::sync::{Arc, RwLock};

#[cfg(feature = "alsa-backend")]
use self::alsa::AlsaBackend;
use self::null::NullBackend;
#[cfg(feature = "pw-backend")]
use self::pipewire::PwBackend;
use crate::{stream::Stream, BackendType, ControlMessage, Result, VirtioSndPcmSetParams};

pub trait AudioBackend {
    fn write(&self, stream_id: u32) -> Result<()>;

    fn read(&self, stream_id: u32) -> Result<()>;

    fn set_parameters(&self, _stream_id: u32, _: VirtioSndPcmSetParams) -> Result<()> {
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
    streams: Arc<RwLock<Vec<Stream>>>,
) -> Result<Box<dyn AudioBackend + Send + Sync>> {
    log::trace!("allocating audio backend {:?}", backend);
    match backend {
        BackendType::Null => Ok(Box::new(NullBackend::new(streams))),
        #[cfg(feature = "pw-backend")]
        BackendType::Pipewire => Ok(Box::new(PwBackend::new(streams))),
        #[cfg(feature = "alsa-backend")]
        BackendType::Alsa => Ok(Box::new(AlsaBackend::new(streams))),
    }
}
