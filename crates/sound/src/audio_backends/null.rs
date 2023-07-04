// SPDX-License-Identifier: Apache-2.0 or BSD-3-Clause

use super::AudioBackend;
use crate::Result;

pub struct NullBackend {}

impl NullBackend {
    pub fn new() -> Self {
        NullBackend {}
    }
}

impl AudioBackend for NullBackend {
    fn write(&self, stream_id: u32) -> Result<()> {
        println!("null backend, writting to stream: {}", stream_id);
        Ok(())
    }

    fn read(&self, _stream_id: u32) -> Result<()> {

        /*
        let buf = req.data_slice().ok_or(Error::SoundReqMissingData)?;
        let zero_mem = vec![0u8; buf.len()];

        buf.copy_from(&zero_mem);

        */
        Ok(())
    }
}
