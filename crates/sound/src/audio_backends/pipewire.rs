// Pipewire backend device
// SPDX-License-Identifier: Apache-2.0 or BSD-3-Clause

use std::sync::{Arc, RwLock};

use super::AudioBackend;
use crate::{Result, Stream};

pub struct PwBackend {
    streams: Arc<RwLock<Vec<Stream>>>,
}

impl PwBackend {
    pub fn new(streams: Arc<RwLock<Vec<Stream>>>) -> Self {
        Self { streams }
    }
}

impl AudioBackend for PwBackend {
    fn write(&self, stream_id: u32) -> Result<()> {
        log::trace!("PipewireBackend write stream_id {}", stream_id);
        _ = std::mem::take(&mut self.streams.write().unwrap()[stream_id as usize].buffers);
        Ok(())
    }

    fn read(&self, _id: u32) -> Result<()> {
        log::trace!("PipewireBackend read stream_id {}", _id);
        Ok(())
    }
}
