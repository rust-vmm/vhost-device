// Pipewire backend device
// SPDX-License-Identifier: Apache-2.0 or BSD-3-Clause

use super::AudioBackend;
use crate::Result;
use std::ops::Deref;
use std::ptr;
use std::ptr::NonNull;
use std::sync::Arc;

use pipewire as pw;
use pw::sys::{pw_loop, pw_thread_loop_new, pw_thread_loop_signal, PW_ID_CORE};
use pw::sys::{pw_thread_loop, pw_thread_loop_start, pw_thread_loop_wait};
use pw::sys::{pw_thread_loop_get_loop, pw_thread_loop_lock, pw_thread_loop_unlock};
use pw::Core;
use pw::LoopRef;
use vm_memory::Le32;

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

pub struct PwThreadLoop(NonNull<pw_thread_loop>);

impl PwThreadLoop {
    pub fn new(name: Option<&str>) -> Option<Self> {
        let inner = unsafe {
            pw_thread_loop_new(
                name.map_or(ptr::null(), |p| p.as_ptr() as *const _),
                std::ptr::null_mut(),
            )
        };
        if inner.is_null() {
            None
        } else {
            Some(Self(
                NonNull::new(inner).expect("pw_thread_loop can't be null"),
            ))
        }
    }

    pub fn get_loop(&self) -> PwThreadLoopTheLoop {
        let inner = unsafe { pw_thread_loop_get_loop(self.0.as_ptr()) };
        PwThreadLoopTheLoop(NonNull::new(inner).unwrap())
    }

    pub fn unlock(&self) {
        unsafe { pw_thread_loop_unlock(self.0.as_ptr()) }
    }

    pub fn lock(&self) {
        unsafe { pw_thread_loop_lock(self.0.as_ptr()) }
    }

    pub fn start(&self) {
        unsafe {
            pw_thread_loop_start(self.0.as_ptr());
        }
    }

    pub fn signal(&self) {
        unsafe {
            pw_thread_loop_signal(self.0.as_ptr(), false);
        }
    }

    pub fn wait(&self) {
        unsafe {
            pw_thread_loop_wait(self.0.as_ptr());
        }
    }
}

#[derive(Debug, Clone)]
pub struct PwThreadLoopTheLoop(NonNull<pw_loop>);

impl AsRef<LoopRef> for PwThreadLoopTheLoop {
    fn as_ref(&self) -> &LoopRef {
        self.deref()
    }
}

impl Deref for PwThreadLoopTheLoop {
    type Target = LoopRef;

    fn deref(&self) -> &Self::Target {
        unsafe { &*(self.0.as_ptr() as *mut LoopRef) }
    }
}

// SAFETY: Safe as the structure can be sent to another thread.
unsafe impl Send for PwBackend {}

// SAFETY: Safe as the structure can be shared with another thread as the state
// is protected with a lock.
unsafe impl Sync for PwBackend {}

pub struct PwBackend {
    //pub streams: Arc<RwLock<Vec<StreamInfo>>>,
    pub thread_loop: Arc<PwThreadLoop>,
    pub core: Core,
}

impl PwBackend {
    pub fn new() -> Self {
        pw::init();

        let thread_loop = Arc::new(PwThreadLoop::new(Some("Pipewire thread loop")).unwrap());
        let get_loop = thread_loop.get_loop();

        thread_loop.lock();

        let context = pw::Context::new(&get_loop).expect("failed to create context");
        thread_loop.start();
        let core = context.connect(None).expect("Failed to connect to core");

        // Create new reference for the variable so that it can be moved into the closure.
        let thread_clone = thread_loop.clone();

        // Trigger the sync event. The server's answer won't be processed until we start the thread loop,
        // so we can safely do this before setting up a callback. This lets us avoid using a Cell.
        let pending = core.sync(0).expect("sync failed");
        let _listener_core = core
            .add_listener_local()
            .done(move |id, seq| {
                if id == PW_ID_CORE && seq == pending {
                    thread_clone.signal();
                }
            })
            .register();

        thread_loop.wait();
        thread_loop.unlock();

        println!("pipewire backend running");

        Self { thread_loop, core }
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
