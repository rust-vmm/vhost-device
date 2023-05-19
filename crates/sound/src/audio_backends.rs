// SPDX-License-Identifier: Apache-2.0 or BSD-3-Clause

use crate::{Error, Result, SoundRequest};

pub trait AudioBackend {
    fn write(&self, req: &SoundRequest) -> Result<()>;

    fn read(&self, req: &mut SoundRequest) -> Result<()>;
}

pub fn allocate_audio_backend(name: String) -> Result<Box<dyn AudioBackend + Send + Sync>> {
    match name.as_str() {
        _ => Err(Error::AudioBackendNotSupported),
    }
}
