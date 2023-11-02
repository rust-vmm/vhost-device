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
        _ = std::mem::take(&mut self.streams.write().unwrap()[stream_id as usize].buffers);
        Ok(())
    }

    fn read(&self, _id: u32) -> Result<()> {
        log::trace!("NullBackend read stream_id {}", _id);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_null_backend_write() {
        let streams = Arc::new(RwLock::new(vec![Stream::default()]));
        let null_backend = NullBackend::new(streams.clone());

        assert!(null_backend.write(0).is_ok());

        let streams = streams.read().unwrap();
        assert_eq!(streams[0].buffers.len(), 0);
    }

    #[test]
    fn test_null_backend_read() {
        let streams = Arc::new(RwLock::new(vec![Stream::default()]));
        let null_backend = NullBackend::new(streams.clone());

        assert!(null_backend.read(0).is_ok());

        // buffer lengths should remain unchanged
        let streams = streams.read().unwrap();
        assert_eq!(streams[0].buffers.len(), 0);
    }
}
