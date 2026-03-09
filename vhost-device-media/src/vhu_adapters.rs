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
    protocol::{DequeueBufferEvent, SessionEvent, SgEntry, V4l2Event},
    GuestMemoryRange, VirtioMediaEventQueue, VirtioMediaGuestMemoryMapper,
    VirtioMediaHostMemoryMapper,
};
use virtio_queue::{DescriptorChain, QueueOwnedT};
use vm_memory::{
    atomic::GuestMemoryAtomic, mmap::GuestMemoryMmap, Bytes, GuestAddress, GuestAddressSpace,
    GuestMemoryLoadGuard,
};
use zerocopy::IntoBytes;

use crate::{
    media_allocator::{AddressRange, MediaAllocator},
    vhu_media::{Writer, SHMEM_SIZE},
};

type MediaDescriptorChain = DescriptorChain<GuestMemoryLoadGuard<GuestMemoryMmap>>;

pub struct EventQueue {
    pub queue: VringRwLock,
    /// Guest memory map.
    pub mem: GuestMemoryAtomic<GuestMemoryMmap>,
}

impl EventQueue {
    fn event(&self) -> Option<MediaDescriptorChain> {
        self.queue
            .borrow()
            .get_mut()
            .get_queue_mut()
            .iter(self.mem.memory())
            .map_or(None, |mut iter| iter.next())
    }
}

impl VirtioMediaEventQueue for EventQueue {
    fn send_event(&mut self, event: V4l2Event) {
        let eventq = self.queue.borrow();
        let desc_chain = match self.event() {
            Some(d) => d,
            None => {
                warn!("No event buffer available, dropping event");
                return;
            }
        };
        let mut writer = Writer::new(desc_chain.clone());
        let bytes: &[u8] = match event {
            V4l2Event::Error(ref event) => event.as_bytes(),
            // TODO: use `as_bytes()` once DequeueBufferEvent derives IntoBytes upstream.
            // SAFETY: DequeueBufferEvent is a plain C struct with no padding or
            // invalid bit patterns, so it is safe to view it as a byte slice.
            V4l2Event::DequeueBuffer(ref event) => unsafe {
                std::slice::from_raw_parts(
                    (&raw const *event).cast::<u8>(),
                    std::mem::size_of::<DequeueBufferEvent>(),
                )
            },
            // TODO: use `as_bytes()` once SessionEvent derives IntoBytes upstream.
            // SAFETY: SessionEvent is a plain C struct with no padding or
            // invalid bit patterns, so it is safe to view it as a byte slice.
            V4l2Event::Event(ref event) => unsafe {
                std::slice::from_raw_parts(
                    (&raw const *event).cast::<u8>(),
                    std::mem::size_of::<SessionEvent>(),
                )
            },
        };
        if std::io::Write::write_all(&mut writer, bytes).is_err() {
            warn!("Failed to write event");
            return;
        }

        if eventq
            .add_used(desc_chain.head_index(), writer.max_written())
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
            allocator: MediaAllocator::new(
                AddressRange::from_range(0, SHMEM_SIZE - 1),
                Some(0x1000),
            )?,
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
        let msg = VhostUserMMap {
            len: length,
            flags: if rw {
                VhostUserMMapFlags::WRITABLE.bits()
            } else {
                VhostUserMMapFlags::default().bits()
            },
            shm_offset,
            ..Default::default()
        };

        if self.backend.shmem_map(&msg, &buffer).is_err() {
            let _ = self.allocator.release(offset);
            return Err(libc::EINVAL);
        }

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
    fn new(mem: &GuestMemoryAtomic<GuestMemoryMmap>, sgs: Vec<SgEntry>) -> std::io::Result<Self> {
        let total_size = sgs.iter().fold(0, |total, sg| total + sg.len as usize);
        let mut data = vec![0u8; total_size];
        let mut pos = 0;
        for sg in &sgs {
            mem.memory()
                .read(
                    &mut data[pos..pos + sg.len as usize],
                    GuestAddress(sg.start),
                )
                .map_err(std::io::Error::other)?;
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
        Self(mem)
    }
}

impl VirtioMediaGuestMemoryMapper for VuMemoryMapper {
    type GuestMemoryMapping = GuestMemoryMapping;

    fn new_mapping(&self, sgs: Vec<SgEntry>) -> anyhow::Result<Self::GuestMemoryMapping> {
        Ok(GuestMemoryMapping::new(&self.0, sgs)?)
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
    fn test_guest_memory_mapping_as_ptr_is_readable() {
        let mem = test_mem();
        mem.memory()
            .write_slice(&[11, 22, 33], GuestAddress(0x500))
            .unwrap();

        let sgs = vec![sg(0x500, 3)];
        let mapping = GuestMemoryMapping::new(&mem, sgs).unwrap();
        let ptr = mapping.as_ptr();
        // SAFETY: ptr points into mapping.data which is valid for exactly 3 bytes.
        let data = unsafe { std::slice::from_raw_parts(ptr, 3) };
        assert_eq!(data, &[11u8, 22, 33]);
        assert!(!mapping.dirty);
    }

    #[test]
    fn test_vu_backend_new() {
        use std::os::unix::net::UnixStream;

        use vhost::vhost_user::Backend;
        let (sock, _peer) = UnixStream::pair().unwrap();
        let backend = Backend::from_stream(sock);
        VuBackend::new(backend).unwrap();
    }

    /// `add_mapping` allocates from the shared memory region, then calls
    /// `shmem_map` on the backend.  When the backend call fails (no real
    /// vhost-user frontend on the other end of the socket pair), the error is
    /// propagated as `EINVAL` and the allocator slot is released.
    #[test]
    fn test_vu_backend_add_mapping_backend_fails() {
        use std::os::{fd::AsFd, unix::net::UnixStream};

        use vhost::vhost_user::Backend;

        let (sock, peer) = UnixStream::pair().unwrap();
        let backend = Backend::from_stream(sock);
        let mut vu = VuBackend::new(backend).unwrap();

        // SHMEM_SIZE bytes fit exactly in the allocator range [0, SHMEM_SIZE-1].
        // The allocator succeeds; then shmem_map fails because there is no
        // real frontend reading the socket.
        assert_eq!(
            vu.add_mapping(peer.as_fd(), crate::vhu_media::SHMEM_SIZE, 0, false),
            Err(libc::EINVAL)
        );
    }

    /// `remove_mapping` should propagate the allocator's `EFAULT` when no
    /// allocation covers the given offset.
    #[test]
    fn test_vu_backend_remove_mapping_not_found() {
        use std::os::unix::net::UnixStream;

        use vhost::vhost_user::Backend;

        let (sock, _peer) = UnixStream::pair().unwrap();
        let backend = Backend::from_stream(sock);
        let mut vu = VuBackend::new(backend).unwrap();

        assert_eq!(vu.remove_mapping(0x1000), Err(libc::EFAULT));
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
