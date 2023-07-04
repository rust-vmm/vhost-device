// Pipewire backend device
// SPDX-License-Identifier: Apache-2.0 or BSD-3-Clause

use super::AudioBackend;
use std::{thread};
use std::{cell::Cell, rc::Rc};
use crate::Result;

use vm_memory::Le32;
use pipewire as pw;
use pw::sys::PW_ID_CORE;

#[derive(Default, Debug)]
pub struct PCMParams {
    pub features: Le32,
    /// size of hardware buffer in bytes
    pub buffer_bytes: Le32,
    /// size of hardware period in bytes
    pub period_bytes: Le32,
    pub channels: u8,
    pub format: u8,
    pub rate: u8,
}

// SAFETY: Safe as the structure can be sent to another thread.
unsafe impl Send for WrapMainLoop {}

// SAFETY: Safe as the structure can be shared with another thread as the state
// is protected with a lock.
unsafe impl Sync for WrapMainLoop {}

#[derive(Clone, Debug)]
pub struct WrapMainLoop {
    mainloop: pipewire::MainLoop,
}
pub struct PwBackend {
    //pub streams: Arc<RwLock<Vec<StreamInfo>>>,
}

impl PwBackend {
    pub fn new() -> Self {
        pw::init();

        let wrap_mainloop = WrapMainLoop {
            mainloop : pw::MainLoop::new().expect("we can't create mainloop")
        };
        //let mainloop = pw::MainLoop::new().expect("Failed to create Pipewire Mainloop");
        let context = pw::Context::new(&wrap_mainloop.mainloop).expect("Failed to create Pipewire Context");
        let core = context
            .connect(None)
            .expect("Failed to connect to Pipewire Core");

        // To comply with Rust's safety rules, we wrap this variable in an `Rc` and  a `Cell`.
        let done = Rc::new(Cell::new(false));

        // Create new reference for each variable so that they can be moved into the closure.
        let done_clone = done.clone();
        let loop_clone = wrap_mainloop.mainloop.clone();

        let pending = core.sync(0).expect("sync failed");
        let _listener_core = core
        .add_listener_local()
        .done(move |id, seq| {
            if id == PW_ID_CORE && seq == pending {
                done_clone.set(true);
                loop_clone.quit();
            }
        })
        .register();

        thread::spawn(move || {
            wrap_mainloop.mainloop.run();
        });

        println!("pipewire backend running");

        Self {
        }

    }
}

impl AudioBackend for PwBackend {
    fn write(&self, stream_id: u32) -> Result<()> {
        println!("pipewire backend, writting to stream: {}", stream_id);
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
    fn set_param(&self, _stream_id: u32, _params: PCMParams) -> Result<()> {
        Ok(())
    }
}
