// Manos Pitsidianakis <manos.pitsidianakis@linaro.org>
// SPDX-License-Identifier: Apache-2.0 or BSD-3-Clause

#[cfg(feature = "null-backend")]
mod null;

#[cfg(feature = "pw-backend")]
mod pipewire;

#[cfg(feature = "null-backend")]
use self::null::NullBackend;
#[cfg(feature = "pw-backend")]
use self::pipewire::PwBackend;
use crate::{Error, Result, SoundRequest};

pub trait AudioBackend {
    fn write(&self, req: &SoundRequest) -> Result<()>;

    fn read(&self, req: &mut SoundRequest) -> Result<()>;
}

pub fn alloc_audio_backend(name: String) -> Result<Box<dyn AudioBackend + Send + Sync>> {
    match name.as_str() {
        #[cfg(feature = "null-backend")]
        "null" => Ok(Box::new(NullBackend::new())),
        #[cfg(feature = "pw-backend")]
        "pipewire" => Ok(Box::new(PwBackend::new())),
        _ => Err(Error::AudioBackendNotSupported),
    }
}
