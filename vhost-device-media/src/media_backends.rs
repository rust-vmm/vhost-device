// Copyright 2026 Red Hat Inc
//
// SPDX-License-Identifier: Apache-2.0 or BSD-3-Clause

use std::{borrow::Borrow, os::fd::BorrowedFd};

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
use virtio_queue::{DescriptorChain, QueueOwnedT};
use vm_memory::{
    atomic::GuestMemoryAtomic, mmap::GuestMemoryMmap, Bytes, GuestAddress, GuestAddressSpace,
    GuestMemoryLoadGuard,
};

use crate::{
    media_allocator::{AddressRange, MediaAllocator},
    vhu_media::SHMEM_SIZE,
};

type MediaDescriptorChain = DescriptorChain<GuestMemoryLoadGuard<GuestMemoryMmap>>;

#[repr(C)]
pub struct EventQueue {
    pub queue: VringRwLock,
    /// Guest memory map.
    pub mem: GuestMemoryAtomic<GuestMemoryMmap>,
}

impl EventQueue {
    fn event(&self) -> Vec<MediaDescriptorChain> {
        self.queue
            .borrow()
            .get_mut()
            .get_queue_mut()
            .iter(self.mem.memory())
            .unwrap()
            .collect()
    }
}

impl VirtioMediaEventQueue for EventQueue {
    fn send_event(&mut self, event: V4l2Event) {
        let eventq = self.queue.borrow();
        let desc_chain;
        loop {
            if let Some(d) = self.event().pop() {
                desc_chain = d;
                break;
            }
        }
        let descriptors: Vec<_> = desc_chain.clone().collect();
        if descriptors.len() > 1 {
            warn!("Unexpected descriptor count {}", descriptors.len());
        }
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

pub struct VuBackend {
    backend: Backend,
    allocator: MediaAllocator,
}

impl VuBackend {
    pub fn new(backend: Backend) -> std::result::Result<Self, i32> {
        Ok(Self {
            backend,
            allocator: MediaAllocator::new(AddressRange::from_range(0, SHMEM_SIZE), Some(0x1000))?,
        })
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
        let shm_offset = self.allocator.allocate(length, offset)?;
        let mut msg: VhostUserMMap = Default::default();
        msg.len = length;
        msg.flags = if rw {
            VhostUserMMapFlags::WRITABLE.bits()
        } else {
            VhostUserMMapFlags::default().bits()
        };
        msg.shm_offset = shm_offset;

        self.backend
            .shmem_map(&msg, &buffer)
            .map_err(|_| libc::EINVAL)?;

        Ok(shm_offset)
    }

    fn remove_mapping(&mut self, offset: u64) -> std::result::Result<(), i32> {
        let mut msg: VhostUserMMap = Default::default();
        let shm_offset = self.allocator.release_containing(offset)?;
        msg.shm_offset = shm_offset.start;
        msg.len = match shm_offset.len() {
            Some(len) => len,
            None => return Err(libc::EINVAL),
        };
        self.backend.shmem_unmap(&msg).map_err(|_| libc::EINVAL)?;

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

#[cfg(test)]
mod tests {
    use vm_memory::{Bytes, GuestAddress};

    use super::*;

    fn sg(start: u64, len: u32) -> SgEntry {
        // SAFETY: SgEntry is a plain C repr POD; we initialize required public
        // fields and leave the private padding zeroed.
        let mut entry: SgEntry = unsafe { std::mem::zeroed() };
        entry.start = start;
        entry.len = len;
        entry
    }

    fn test_mem() -> GuestMemoryAtomic<GuestMemoryMmap> {
        GuestMemoryAtomic::new(GuestMemoryMmap::from_ranges(&[(GuestAddress(0), 0x4000)]).unwrap())
    }

    #[test]
    fn test_guest_memory_mapping_new_reads_from_guest() {
        let mem = test_mem();
        mem.memory()
            .write_slice(&[1, 2, 3, 4], GuestAddress(0x100))
            .unwrap();
        mem.memory()
            .write_slice(&[9, 8, 7], GuestAddress(0x200))
            .unwrap();

        let sgs = vec![sg(0x100, 4), sg(0x200, 3)];

        let mapping = GuestMemoryMapping::new(&mem, sgs).unwrap();
        assert_eq!(mapping.data, vec![1, 2, 3, 4, 9, 8, 7]);
        assert!(!mapping.dirty);
    }

    #[test]
    fn test_guest_memory_mapping_drop_writes_back_when_dirty() {
        let mem = test_mem();
        mem.memory()
            .write_slice(&[10, 11, 12, 13], GuestAddress(0x300))
            .unwrap();

        let sgs = vec![sg(0x300, 4)];

        {
            let mut mapping = GuestMemoryMapping::new(&mem, sgs).unwrap();
            let _ = mapping.as_mut_ptr(); // mark dirty
            mapping.data.copy_from_slice(&[42, 43, 44, 45]);
        } // Drop writes back

        let mut out = [0u8; 4];
        mem.memory()
            .read_slice(&mut out, GuestAddress(0x300))
            .unwrap();
        assert_eq!(out, [42, 43, 44, 45]);
    }

    #[test]
    fn test_guest_memory_mapping_drop_no_write_when_clean() {
        let mem = test_mem();
        mem.memory()
            .write_slice(&[21, 22, 23, 24], GuestAddress(0x380))
            .unwrap();

        let sgs = vec![sg(0x380, 4)];

        {
            let _mapping = GuestMemoryMapping::new(&mem, sgs).unwrap();
            // not marked dirty
        }

        let mut out = [0u8; 4];
        mem.memory()
            .read_slice(&mut out, GuestAddress(0x380))
            .unwrap();
        assert_eq!(out, [21, 22, 23, 24]);
    }

    #[test]
    fn test_vu_memory_mapper_new_mapping() {
        let mem = test_mem();
        mem.memory()
            .write_slice(&[5, 6, 7], GuestAddress(0x120))
            .unwrap();

        let mapper = VuMemoryMapper::new(mem.clone());
        let mapping = mapper.new_mapping(vec![sg(0x120, 3)]).unwrap();

        assert_eq!(mapping.data, vec![5, 6, 7]);
    }
}
