// Manos Pitsidianakis <manos.pitsidianakis@linaro.org>
// SPDX-License-Identifier: Apache-2.0 or BSD-3-Clause

#[cfg(feature = "null-backend")]
mod null;

#[cfg(feature = "pw-backend")]
mod pipewire;

use std::sync::{Arc, RwLock};

#[cfg(feature = "null-backend")]
use self::null::NullBackend;
#[cfg(feature = "pw-backend")]
use self::pipewire::PwBackend;
use crate::{device::ControlMessage, stream::Stream, Error, Result};

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
    name: String,
    streams: Arc<RwLock<Vec<Stream>>>,
) -> Result<Box<dyn AudioBackend + Send + Sync>> {
    log::trace!("allocating audio backend {}", name);
    match name.as_str() {
        #[cfg(feature = "null-backend")]
        "null" => Ok(Box::new(NullBackend::new(streams))),
        #[cfg(feature = "pw-backend")]
        "pipewire" => Ok(Box::new(PwBackend::new(streams))),
        _ => Err(Error::AudioBackendNotSupported),
    }
}
