// vhost device foo
//
// Copyright 2023 Linaro Ltd. All Rights Reserved.
//          Viresh Kumar <viresh.kumar@linaro.org>
//
// SPDX-License-Identifier: Apache-2.0 or BSD-3-Clause

use log::{info, warn};
use std::{
    convert,
    io::{self, Result as IoResult},
};

use thiserror::Error as ThisError;
use vhost::vhost_user::message::{VhostUserProtocolFeatures, VhostUserVirtioFeatures};
use vhost_user_backend::{VhostUserBackendMut, VringRwLock, VringT};
use virtio_bindings::bindings::virtio_config::{VIRTIO_F_NOTIFY_ON_EMPTY, VIRTIO_F_VERSION_1};
use virtio_bindings::bindings::virtio_ring::{
    VIRTIO_RING_F_EVENT_IDX, VIRTIO_RING_F_INDIRECT_DESC,
};
use virtio_queue::{DescriptorChain, QueueOwnedT};
use vm_memory::{GuestAddressSpace, GuestMemoryAtomic, GuestMemoryLoadGuard, GuestMemoryMmap};
use vmm_sys_util::epoll::EventSet;
use vmm_sys_util::eventfd::{EventFd, EFD_NONBLOCK};

use crate::FooInfo;

const QUEUE_SIZE: usize = 1024;
const NUM_QUEUES: usize = 1;

type Result<T> = std::result::Result<T, Error>;

#[derive(Copy, Clone, Debug, Eq, PartialEq, ThisError)]
/// Errors related to vhost-device-foo daemon.
pub enum Error {
    #[error("Failed to handle event, didn't match EPOLLIN")]
    HandleEventNotEpollIn,
    #[error("Failed to handle unknown event")]
    HandleEventUnknown,
    #[error("Descriptor not found")]
    DescriptorNotFound,
    #[error("Failed to send notification")]
    NotificationFailed,
    #[error("Failed to create new EventFd")]
    EventFdFailed,
}

impl convert::From<Error> for io::Error {
    fn from(e: Error) -> Self {
        Self::new(io::ErrorKind::Other, e)
    }
}

pub struct VhostUserFooBackend {
    info: FooInfo,
    event_idx: bool,
    pub exit_event: EventFd,
    mem: Option<GuestMemoryLoadGuard<GuestMemoryMmap>>,
}

type FooDescriptorChain = DescriptorChain<GuestMemoryLoadGuard<GuestMemoryMmap<()>>>;

impl VhostUserFooBackend {
    pub fn new(info: FooInfo) -> Result<Self> {
        Ok(Self {
            info,
            event_idx: false,
            exit_event: EventFd::new(EFD_NONBLOCK).map_err(|_| Error::EventFdFailed)?,
            mem: None,
        })
    }

    /// Process the requests in the vring and dispatch replies
    fn process_requests(
        &mut self,
        requests: Vec<FooDescriptorChain>,
        _vring: &VringRwLock,
    ) -> Result<()> {
        if requests.is_empty() {
            info!("No pending requests");
            return Ok(());
        }

        // Iterate over each FOO request.
        //
        // The layout of the various structures, to be read from and written into the descriptor
        // buffers, is defined in the Virtio specification for each protocol.
        for desc_chain in requests {
            let counter = self.info.counter();
            let descriptors: Vec<_> = desc_chain.clone().collect();

            info!(
                "Request number: {} contains {} descriptors",
                counter,
                descriptors.len(),
            );

            for (i, desc) in descriptors.iter().enumerate() {
                let perm = if desc.is_write_only() {
                    "write only"
                } else {
                    "read only"
                };

                // We now can iterate over the set of descriptors and process the messages. There
                // will be a number of read only descriptors containing messages as defined by the
                // specification. If any replies are needed, the driver should have placed one or
                // more writable descriptors at the end for the device to use to reply.
                info!("Length of the {} descriptor@{} is: {}", perm, i, desc.len());
            }
        }

        Ok(())
    }

    /// Process the requests in the vring and dispatch replies
    fn process_queue(&mut self, vring: &VringRwLock) -> Result<()> {
        // Collect all pending requests
        let requests: Vec<_> = vring
            .get_mut()
            .get_queue_mut()
            .iter(self.mem.as_ref().unwrap().clone())
            .map_err(|_| Error::DescriptorNotFound)?
            .collect();

        if self.process_requests(requests, vring).is_ok() {
            // Send notification once all the requests are processed
            vring
                .signal_used_queue()
                .map_err(|_| Error::NotificationFailed)?;
        }

        Ok(())
    }
}

/// VhostUserBackendMut trait methods
impl VhostUserBackendMut for VhostUserFooBackend {
    type Vring = VringRwLock;
    type Bitmap = ();

    fn num_queues(&self) -> usize {
        NUM_QUEUES
    }

    fn max_queue_size(&self) -> usize {
        QUEUE_SIZE
    }

    fn features(&self) -> u64 {
        // this matches the current libvhost defaults except VHOST_F_LOG_ALL
        1 << VIRTIO_F_VERSION_1
            | 1 << VIRTIO_F_NOTIFY_ON_EMPTY
            | 1 << VIRTIO_RING_F_INDIRECT_DESC
            | 1 << VIRTIO_RING_F_EVENT_IDX

            // Protocol features are optional and must not be defined unless required and must be
            // accompanied by the supporting PROTOCOL_FEATURES bits in features.
            | VhostUserVirtioFeatures::PROTOCOL_FEATURES.bits()
    }

    fn protocol_features(&self) -> VhostUserProtocolFeatures {
        VhostUserProtocolFeatures::MQ
    }

    fn set_event_idx(&mut self, enabled: bool) {
        self.event_idx = enabled;
    }

    fn update_memory(&mut self, mem: GuestMemoryAtomic<GuestMemoryMmap>) -> IoResult<()> {
        self.mem = Some(mem.memory());
        Ok(())
    }

    fn handle_event(
        &mut self,
        device_event: u16,
        evset: EventSet,
        vrings: &[VringRwLock],
        _thread_id: usize,
    ) -> IoResult<()> {
        if evset != EventSet::IN {
            return Err(Error::HandleEventNotEpollIn.into());
        }

        match device_event {
            0 => {
                let vring = &vrings[0];

                if self.event_idx {
                    // vm-virtio's Queue implementation only checks avail_index
                    // once, so to properly support EVENT_IDX we need to keep
                    // calling process_queue() until it stops finding new
                    // requests on the queue.
                    loop {
                        vring.disable_notification().unwrap();
                        self.process_queue(vring)?;
                        if !vring.enable_notification().unwrap() {
                            break;
                        }
                    }
                } else {
                    // Without EVENT_IDX, a single call is enough.
                    self.process_queue(vring)?;
                }
            }

            _ => {
                warn!("unhandled device_event: {}", device_event);
                return Err(Error::HandleEventUnknown.into());
            }
        }
        Ok(())
    }

    fn exit_event(&self, _thread_index: usize) -> Option<EventFd> {
        self.exit_event.try_clone().ok()
    }
}

#[cfg(test)]
mod tests {
    use std::mem::size_of;
    use vhost_user_backend::{VhostUserBackendMut, VringRwLock, VringT};
    use virtio_bindings::bindings::virtio_ring::{VRING_DESC_F_NEXT, VRING_DESC_F_WRITE};
    use virtio_queue::{mock::MockSplitQueue, Descriptor, Queue};
    use vm_memory::{Address, ByteValued, Bytes, GuestAddress, GuestMemoryAtomic, GuestMemoryMmap};

    use super::*;

    #[derive(Copy, Clone, Default)]
    #[repr(C)]
    struct VirtioFooOutHdr {
        a: u16,
        b: u16,
        c: u32,
    }
    // SAFETY: The layout of the structure is fixed and can be initialized by
    // reading its content from byte array.
    unsafe impl ByteValued for VirtioFooOutHdr {}

    #[derive(Copy, Clone, Default)]
    #[repr(C)]
    struct VirtioFooInHdr {
        d: u8,
    }
    // SAFETY: The layout of the structure is fixed and can be initialized by
    // reading its content from byte array.
    unsafe impl ByteValued for VirtioFooInHdr {}

    fn init() -> (
        VhostUserFooBackend,
        GuestMemoryAtomic<GuestMemoryMmap>,
        VringRwLock,
    ) {
        let backend = VhostUserFooBackend::new(FooInfo::new()).unwrap();
        let mem = GuestMemoryAtomic::new(
            GuestMemoryMmap::<()>::from_ranges(&[(GuestAddress(0), 0x1000)]).unwrap(),
        );
        let vring = VringRwLock::new(mem.clone(), 16).unwrap();

        (backend, mem, vring)
    }

    // Prepares a single chain of descriptors
    fn prepare_descriptors(
        mut next_addr: u64,
        mem: &GuestMemoryLoadGuard<GuestMemoryMmap<()>>,
        buf: &[u8],
    ) -> Vec<Descriptor> {
        let mut descriptors = Vec::new();
        let mut index = 0;

        // Out header descriptor
        let out_hdr = VirtioFooOutHdr {
            a: 0x10,
            b: 0x11,
            c: 0x20,
        };

        let desc_out = Descriptor::new(
            next_addr,
            size_of::<VirtioFooOutHdr>() as u32,
            VRING_DESC_F_NEXT as u16,
            index + 1,
        );
        next_addr += u64::from(desc_out.len());
        index += 1;

        mem.write_obj::<VirtioFooOutHdr>(out_hdr, desc_out.addr())
            .unwrap();
        descriptors.push(desc_out);

        // Buf descriptor: optional
        if !buf.is_empty() {
            let desc_buf = Descriptor::new(
                next_addr,
                buf.len() as u32,
                (VRING_DESC_F_WRITE | VRING_DESC_F_NEXT) as u16,
                index + 1,
            );
            next_addr += u64::from(desc_buf.len());

            mem.write(buf, desc_buf.addr()).unwrap();
            descriptors.push(desc_buf);
        }

        // In response descriptor
        let desc_in = Descriptor::new(
            next_addr,
            size_of::<VirtioFooInHdr>() as u32,
            VRING_DESC_F_WRITE as u16,
            0,
        );
        descriptors.push(desc_in);
        descriptors
    }

    // Prepares a single chain of descriptors
    fn prepare_desc_chain(buf: &[u8]) -> (VhostUserFooBackend, VringRwLock) {
        let (mut backend, mem, vring) = init();
        let mem_handle = mem.memory();
        let vq = MockSplitQueue::new(&*mem_handle, 16);
        let next_addr = vq.desc_table().total_size() + 0x100;

        let descriptors = prepare_descriptors(next_addr, &mem_handle, buf);

        vq.build_desc_chain(&descriptors).unwrap();

        // Put the descriptor index 0 in the first available ring position.
        mem_handle
            .write_obj(0u16, vq.avail_addr().unchecked_add(4))
            .unwrap();

        // Set `avail_idx` to 1.
        mem_handle
            .write_obj(1u16, vq.avail_addr().unchecked_add(2))
            .unwrap();

        vring.set_queue_size(16);
        vring
            .set_queue_info(vq.desc_table_addr().0, vq.avail_addr().0, vq.used_addr().0)
            .unwrap();
        vring.set_queue_ready(true);

        backend.update_memory(mem).unwrap();

        (backend, vring)
    }

    // Prepares a chain of descriptors
    fn prepare_desc_chains(
        mem: &GuestMemoryAtomic<GuestMemoryMmap>,
        buf: &[u8],
    ) -> FooDescriptorChain {
        let mem_handle = mem.memory();
        let vq = MockSplitQueue::new(&*mem_handle, 16);
        let next_addr = vq.desc_table().total_size() + 0x100;

        let descriptors = prepare_descriptors(next_addr, &mem_handle, buf);

        for (idx, desc) in descriptors.iter().enumerate() {
            vq.desc_table().store(idx as u16, *desc).unwrap();
        }

        // Put the descriptor index 0 in the first available ring position.
        mem_handle
            .write_obj(0u16, vq.avail_addr().unchecked_add(4))
            .unwrap();

        // Set `avail_idx` to 1.
        mem_handle
            .write_obj(1u16, vq.avail_addr().unchecked_add(2))
            .unwrap();

        // Create descriptor chain from pre-filled memory
        vq.create_queue::<Queue>()
            .unwrap()
            .iter(mem_handle)
            .unwrap()
            .next()
            .unwrap()
    }

    #[test]
    fn process_requests_no_desc() {
        let (mut backend, _, vring) = init();

        // Descriptor chain size zero, shouldn't fail
        backend
            .process_requests(Vec::<FooDescriptorChain>::new(), &vring)
            .unwrap();
    }

    #[test]
    fn process_request_single() {
        // Single valid descriptor
        let buf: Vec<u8> = vec![0; 30];
        let (mut backend, vring) = prepare_desc_chain(&buf);
        backend.process_queue(&vring).unwrap();
    }

    #[test]
    fn process_requests_multi() {
        // Multiple valid descriptors
        let (mut backend, mem, vring) = init();

        let bufs: Vec<Vec<u8>> = vec![vec![0; 30]; 6];
        let desc_chains = vec![
            prepare_desc_chains(&mem, &bufs[0]),
            prepare_desc_chains(&mem, &bufs[1]),
            prepare_desc_chains(&mem, &bufs[2]),
            prepare_desc_chains(&mem, &bufs[3]),
            prepare_desc_chains(&mem, &bufs[4]),
            prepare_desc_chains(&mem, &bufs[5]),
        ];

        backend.process_requests(desc_chains, &vring).unwrap();
    }

    #[test]
    fn verify_backend() {
        let info = FooInfo::new();
        let mut backend = VhostUserFooBackend::new(info).unwrap();

        assert_eq!(backend.num_queues(), NUM_QUEUES);
        assert_eq!(backend.max_queue_size(), QUEUE_SIZE);
        assert_eq!(backend.features(), 0x171000000);
        assert_eq!(backend.protocol_features(), VhostUserProtocolFeatures::MQ);

        assert_eq!(backend.queues_per_thread(), vec![0xffff_ffff]);
        assert_eq!(backend.get_config(0, 0), vec![]);

        backend.set_event_idx(true);
        assert!(backend.event_idx);

        assert!(backend.exit_event(0).is_some());

        let mem = GuestMemoryAtomic::new(
            GuestMemoryMmap::<()>::from_ranges(&[(GuestAddress(0), 0x1000)]).unwrap(),
        );
        backend.update_memory(mem.clone()).unwrap();

        let vring = VringRwLock::new(mem, 0x1000).unwrap();
        vring.set_queue_info(0x100, 0x200, 0x300).unwrap();
        vring.set_queue_ready(true);

        assert_eq!(
            backend
                .handle_event(0, EventSet::OUT, &[vring.clone()], 0)
                .unwrap_err()
                .kind(),
            io::ErrorKind::Other
        );

        assert_eq!(
            backend
                .handle_event(1, EventSet::IN, &[vring.clone()], 0)
                .unwrap_err()
                .kind(),
            io::ErrorKind::Other
        );

        // Hit the loop part
        backend.set_event_idx(true);
        backend
            .handle_event(0, EventSet::IN, &[vring.clone()], 0)
            .unwrap();

        // Hit the non-loop part
        backend.set_event_idx(false);
        backend.handle_event(0, EventSet::IN, &[vring], 0).unwrap();
    }
}
