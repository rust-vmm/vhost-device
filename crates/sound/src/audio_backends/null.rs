// SPDX-License-Identifier: Apache-2.0 or BSD-3-Clause

use std::sync::{Arc, RwLock};

use super::AudioBackend;
use crate::{Result, Stream};

pub struct NullBackend {
    streams: Arc<RwLock<Vec<Stream>>>,
}

impl NullBackend {
    pub fn new(streams: Arc<RwLock<Vec<Stream>>>) -> Self {
        Self { streams }
    }
}

impl AudioBackend for NullBackend {
    fn write(&self, stream_id: u32) -> Result<()> {
        log::trace!("NullBackend write stream_id {}", stream_id);
        Ok(())
    }

    fn read(&self, _id: u32) -> Result<()> {
        log::trace!("NullBackend read stream_id {}", _id);
        Ok(())
    }
}
