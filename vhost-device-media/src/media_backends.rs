// Copyright 2026 Red Hat Inc
//
// SPDX-License-Identifier: Apache-2.0 or BSD-3-Clause

use std::os::fd::BorrowedFd;

use log::warn;
use vhost::vhost_user::{
    message::{VhostUserMMap, VhostUserMMapFlags},
    Backend, VhostUserFrontendReqHandler,
};
use vhost_user_backend::{VringRwLock, VringT};
use virtio_media::{
    protocol::{DequeueBufferEvent, ErrorEvent, SessionEvent, SgEntry, V4l2Event},
    GuestMemoryRange, VirtioMediaEventQueue, VirtioMediaGuestMemoryMapper,
    VirtioMediaHostMemoryMapper,
};
use virtio_queue::QueueOwnedT;
use vm_memory::{
    atomic::GuestMemoryAtomic, mmap::GuestMemoryMmap, Bytes, GuestAddress, GuestAddressSpace,
};

#[repr(C)]
pub struct EventQueue {
    pub queue: VringRwLock,
    /// Guest memory map.
    pub mem: GuestMemoryAtomic<GuestMemoryMmap>,
}

impl VirtioMediaEventQueue for EventQueue {
    fn send_event(&mut self, event: V4l2Event) {
        let eventq = &self.queue;
        let desc_chain = eventq
            .get_mut()
            .get_queue_mut()
            .iter(self.mem.memory())
            .unwrap()
            .collect::<Vec<_>>()
            .pop();
        let desc_chain = match desc_chain {
            Some(desc_chain) => desc_chain,
            None => {
                warn!("No available buffer found in the event queue.");
                return;
            }
        };
        let descriptors: Vec<_> = desc_chain.clone().collect();
        if desc_chain
            .memory()
            .write_slice(
                match event {
                    V4l2Event::Error(event) => unsafe {
                        std::slice::from_raw_parts(
                            &event as *const _ as *const u8,
                            std::mem::size_of::<ErrorEvent>(),
                        )
                    },
                    V4l2Event::DequeueBuffer(event) => unsafe {
                        std::slice::from_raw_parts(
                            &event as *const _ as *const u8,
                            std::mem::size_of::<DequeueBufferEvent>(),
                        )
                    },
                    V4l2Event::Event(event) => unsafe {
                        std::slice::from_raw_parts(
                            &event as *const _ as *const u8,
                            std::mem::size_of::<SessionEvent>(),
                        )
                    },
                },
                descriptors[0].addr(),
            )
            .is_err()
        {
            warn!("Failed to write event");
            return;
        }

        if eventq
            .add_used(desc_chain.head_index(), descriptors[0].len())
            .is_err()
        {
            warn!("Couldn't return used descriptors to the ring");
        }
        if let Err(e) = eventq.signal_used_queue() {
            warn!("Failed to signal used queue: {}", e);
        }
    }
}

#[derive(Debug, Default)]
pub struct AddressRange {
    offset: u64,
    length: u64,
}

pub struct VuBackend {
    backend: Backend,
    address: Vec<AddressRange>,
}

impl VuBackend {
    pub fn new(backend: Backend) -> Self {
        Self {
            backend,
            address: Vec::new(),
        }
    }
}

impl VirtioMediaHostMemoryMapper for VuBackend {
    fn add_mapping(
        &mut self,
        buffer: BorrowedFd,
        length: u64,
        offset: u64,
        rw: bool,
    ) -> std::result::Result<u64, i32> {
        let mut msg: VhostUserMMap = Default::default();
        msg.shm_offset = offset;
        msg.len = length;
        msg.flags = if rw {
            VhostUserMMapFlags::WRITABLE.bits()
        } else {
            VhostUserMMapFlags::default().bits()
        };

        self.address.push(AddressRange {
            offset: msg.shm_offset,
            length: msg.len,
        });

        self.backend
            .shmem_map(&msg, &buffer)
            .map_err(|_| libc::EINVAL)?;

        Ok(offset)
    }

    fn remove_mapping(&mut self, shm_offset: u64) -> std::result::Result<(), i32> {
        let mut msg: VhostUserMMap = Default::default();
        msg.shm_offset = shm_offset;
        match self.address.iter().position(|a| a.offset == msg.shm_offset) {
            Some(index) => {
                let addr = self.address.swap_remove(index);
                msg.len = addr.length;
                self.backend.shmem_unmap(&msg).map_err(|_| libc::EINVAL)?;
            }
            None => return Err(libc::EINVAL),
        };

        Ok(())
    }
}

pub struct GuestMemoryMapping {
    data: Vec<u8>,
    mem: GuestMemoryAtomic<GuestMemoryMmap>,
    sgs: Vec<SgEntry>,
    dirty: bool,
}

impl GuestMemoryMapping {
    fn new(mem: &GuestMemoryAtomic<GuestMemoryMmap>, sgs: Vec<SgEntry>) -> anyhow::Result<Self> {
        let total_size = sgs.iter().fold(0, |total, sg| total + sg.len as usize);
        let mut data = Vec::with_capacity(total_size);
        // Safe because we are about to write `total_size` bytes of data.
        // This is not ideal and we should use `spare_capacity_mut` instead but the
        // methods of `MaybeUnint` that would make it possible to use that with
        // `read_exact_at_addr` are still in nightly.
        unsafe { data.set_len(total_size) };
        let mut pos = 0;
        for sg in &sgs {
            mem.memory().read(
                &mut data[pos..pos + sg.len as usize],
                GuestAddress(sg.start),
            )?;
            pos += sg.len as usize;
        }

        Ok(Self {
            data,
            mem: mem.clone(),
            sgs,
            dirty: false,
        })
    }
}

impl GuestMemoryRange for GuestMemoryMapping {
    fn as_ptr(&self) -> *const u8 {
        self.data.as_ptr()
    }

    fn as_mut_ptr(&mut self) -> *mut u8 {
        self.dirty = true;
        self.data.as_mut_ptr()
    }
}

/// Write the potentially modified shadow buffer back into the guest memory.
impl Drop for GuestMemoryMapping {
    fn drop(&mut self) {
        // No need to copy back if no modification has been done.
        if !self.dirty {
            return;
        }

        let mut pos = 0;
        for sg in &self.sgs {
            if let Err(e) = self.mem.memory().write(
                &self.data[pos..pos + sg.len as usize],
                GuestAddress(sg.start),
            ) {
                log::error!("failed to write back guest memory shadow mapping: {:#}", e);
            }
            pos += sg.len as usize;
        }
    }
}

pub struct VuMemoryMapper(GuestMemoryAtomic<GuestMemoryMmap>);

impl VuMemoryMapper {
    pub fn new(mem: GuestMemoryAtomic<GuestMemoryMmap>) -> Self {
        Self { 0: mem }
    }
}

impl VirtioMediaGuestMemoryMapper for VuMemoryMapper {
    type GuestMemoryMapping = GuestMemoryMapping;

    fn new_mapping(&self, sgs: Vec<SgEntry>) -> anyhow::Result<Self::GuestMemoryMapping> {
        GuestMemoryMapping::new(&self.0, sgs)
    }
}
