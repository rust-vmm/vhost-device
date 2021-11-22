// vhost device gpio
//
// Copyright 2021 Linaro Ltd. All Rights Reserved.
//          Viresh Kumar <viresh.kumar@linaro.org>
//
// SPDX-License-Identifier: Apache-2.0

use log::error;
use std::mem::size_of;
use std::slice::from_raw_parts;
use std::{convert, io};

use thiserror::Error as ThisError;
use vhost::vhost_user::message::{VhostUserProtocolFeatures, VhostUserVirtioFeatures};
use vhost_user_backend::{VhostUserBackendMut, VringRwLock, VringT};
use virtio_bindings::bindings::virtio_net::{VIRTIO_F_NOTIFY_ON_EMPTY, VIRTIO_F_VERSION_1};
use virtio_bindings::bindings::virtio_ring::{
    VIRTIO_RING_F_EVENT_IDX, VIRTIO_RING_F_INDIRECT_DESC,
};
use virtio_queue::DescriptorChain;
use vm_memory::{ByteValued, Bytes, GuestMemoryAtomic, GuestMemoryMmap, Le16, Le32};
use vmm_sys_util::epoll::EventSet;
use vmm_sys_util::eventfd::{EventFd, EFD_NONBLOCK};

use crate::gpio::{GpioController, GpioDevice, VirtioGpioConfig};

/// Possible values of the status field
const VIRTIO_GPIO_STATUS_OK: u8 = 0x0;
const VIRTIO_GPIO_STATUS_ERR: u8 = 0x1;

const QUEUE_SIZE: usize = 20;
const NUM_QUEUES: usize = 2;

/// Queues
const REQUEST_QUEUE: u16 = 0;

type Result<T> = std::result::Result<T, Error>;
type VhostUserBackendResult<T> = std::result::Result<T, std::io::Error>;

#[derive(Copy, Clone, Debug, PartialEq, ThisError)]
/// Errors related to vhost-device-gpio-daemon.
pub enum Error {
    #[error("Failed to handle event, didn't match EPOLLIN")]
    HandleEventNotEpollIn,
    #[error("Failed to handle unknown event")]
    HandleEventUnknown,
    #[error("Received unexpected write only descriptor at index {0}")]
    UnexpectedWriteOnlyDescriptor(usize),
    #[error("Received unexpected readable descriptor at index {0}")]
    UnexpectedReadableDescriptor(usize),
    #[error("Invalid descriptor count {0}")]
    UnexpectedDescriptorCount(usize),
    #[error("Invalid descriptor size, expected: {0}, found: {1}")]
    UnexpectedDescriptorSize(usize, u32),
    #[error("Descriptor not found")]
    DescriptorNotFound,
    #[error("Descriptor read failed")]
    DescriptorReadFailed,
    #[error("Descriptor write failed")]
    DescriptorWriteFailed,
    #[error("Failed to send notification")]
    NotificationFailed,
    #[error("Failed to create new EventFd")]
    EventFdFailed,
}

impl convert::From<Error> for io::Error {
    fn from(e: Error) -> Self {
        io::Error::new(io::ErrorKind::Other, e)
    }
}

/// Virtio GPIO Request / Response messages
///
/// The response message is a stream of bytes, where first byte represents the
/// status, and rest is message specific data.
#[derive(Copy, Clone, Default)]
#[repr(C)]
struct VirtioGpioRequest {
    rtype: Le16,
    gpio: Le16,
    value: Le32,
}
unsafe impl ByteValued for VirtioGpioRequest {}

pub struct VhostUserGpioBackend<D: GpioDevice> {
    controller: GpioController<D>,
    event_idx: bool,
    pub exit_event: EventFd,
}

type GpioDescriptorChain = DescriptorChain<GuestMemoryAtomic<GuestMemoryMmap<()>>>;

impl<D: GpioDevice> VhostUserGpioBackend<D> {
    pub fn new(controller: GpioController<D>) -> Result<Self> {
        Ok(VhostUserGpioBackend {
            controller,
            event_idx: false,
            exit_event: EventFd::new(EFD_NONBLOCK).map_err(|_| Error::EventFdFailed)?,
        })
    }

    /// Process the requests in the request queue
    fn process_requests(
        &self,
        requests: Vec<GpioDescriptorChain>,
        vring: Option<&VringRwLock>,
    ) -> Result<bool> {
        if requests.is_empty() {
            return Ok(true);
        }

        for desc_chain in requests.clone() {
            let descriptors: Vec<_> = desc_chain.clone().collect();
            if descriptors.len() != 2 {
                return Err(Error::UnexpectedDescriptorCount(descriptors.len()));
            }

            let desc_request = descriptors[0];
            if desc_request.is_write_only() {
                return Err(Error::UnexpectedWriteOnlyDescriptor(0));
            }

            if desc_request.len() as usize != size_of::<VirtioGpioRequest>() {
                return Err(Error::UnexpectedDescriptorSize(
                    size_of::<VirtioGpioRequest>(),
                    desc_request.len(),
                ));
            }

            let request = desc_chain
                .memory()
                .read_obj::<VirtioGpioRequest>(desc_request.addr())
                .map_err(|_| Error::DescriptorReadFailed)?;

            let desc_response = descriptors[1];
            if !desc_response.is_write_only() {
                return Err(Error::UnexpectedReadableDescriptor(1));
            }

            let response = match self.controller.operation(
                request.rtype.to_native(),
                request.gpio.to_native(),
                request.value.to_native(),
            ) {
                Ok(mut data) => {
                    if data.len() != (desc_response.len() - 1) as usize {
                        error!(
                            "Invalid response size, expected {}, received {}",
                            desc_response.len(),
                            data.len()
                        );
                        vec![VIRTIO_GPIO_STATUS_ERR, 0]
                    } else {
                        let mut buf = vec![VIRTIO_GPIO_STATUS_OK];
                        buf.append(&mut data);
                        buf
                    }
                }

                Err(x) => {
                    error!("{:?}", x);
                    vec![VIRTIO_GPIO_STATUS_ERR, 0]
                }
            };

            desc_chain
                .memory()
                .write_slice(response.as_slice(), desc_response.addr())
                .map_err(|_| Error::DescriptorWriteFailed)?;

            if let Some(vring) = vring {
                if vring
                    .add_used(desc_chain.head_index(), desc_response.len())
                    .is_err()
                {
                    error!("Couldn't return used descriptors to the ring");
                }
            }
        }

        Ok(true)
    }

    /// Process the messages in the vring and dispatch replies
    fn process_request_queue(&self, vring: &VringRwLock) -> Result<bool> {
        let requests: Vec<_> = vring
            .get_mut()
            .get_queue_mut()
            .iter()
            .map_err(|_| Error::DescriptorNotFound)?
            .collect();

        if requests.is_empty() {
            return Ok(true);
        }

        if self.process_requests(requests, Some(vring))? {
            // Send notification once all the requests are processed
            vring
                .signal_used_queue()
                .map_err(|_| Error::NotificationFailed)?;
        }

        Ok(true)
    }
}

/// VhostUserBackendMut trait methods
impl<D: 'static + GpioDevice + Sync + Send> VhostUserBackendMut<VringRwLock, ()>
    for VhostUserGpioBackend<D>
{
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
            | VhostUserVirtioFeatures::PROTOCOL_FEATURES.bits()
    }

    fn protocol_features(&self) -> VhostUserProtocolFeatures {
        VhostUserProtocolFeatures::MQ | VhostUserProtocolFeatures::CONFIG
    }

    fn get_config(&self, _offset: u32, _size: u32) -> Vec<u8> {
        unsafe {
            from_raw_parts(
                self.controller.get_config() as *const _ as *const _,
                size_of::<VirtioGpioConfig>(),
            )
            .to_vec()
        }
    }

    fn set_event_idx(&mut self, enabled: bool) {
        dbg!(self.event_idx = enabled);
    }

    fn update_memory(
        &mut self,
        _mem: GuestMemoryAtomic<GuestMemoryMmap>,
    ) -> VhostUserBackendResult<()> {
        Ok(())
    }

    fn handle_event(
        &mut self,
        device_event: u16,
        evset: EventSet,
        vrings: &[VringRwLock],
        _thread_id: usize,
    ) -> VhostUserBackendResult<bool> {
        if evset != EventSet::IN {
            return Err(Error::HandleEventNotEpollIn.into());
        }

        match device_event {
            REQUEST_QUEUE => {
                let vring = &vrings[0];

                if self.event_idx {
                    // vm-virtio's Queue implementation only checks avail_index
                    // once, so to properly support EVENT_IDX we need to keep
                    // calling process_request_queue() until it stops finding
                    // new requests on the queue.
                    loop {
                        vring.disable_notification().unwrap();
                        self.process_request_queue(vring)?;
                        if !vring.enable_notification().unwrap() {
                            break;
                        }
                    }
                } else {
                    // Without EVENT_IDX, a single call is enough.
                    self.process_request_queue(vring)?;
                }
            }

            _ => {
                return Err(Error::HandleEventUnknown.into());
            }
        }
        Ok(false)
    }

    fn exit_event(&self, _thread_index: usize) -> Option<EventFd> {
        self.exit_event.try_clone().ok()
    }
}

#[cfg(test)]
mod tests {
    use virtio_queue::defs::{VIRTQ_DESC_F_NEXT, VIRTQ_DESC_F_WRITE};
    use virtio_queue::{mock::MockSplitQueue, Descriptor};
    use vm_memory::{Address, GuestAddress, GuestMemoryAtomic, GuestMemoryMmap};

    use super::Error;
    use super::*;
    use crate::gpio::tests::DummyDevice;
    use crate::gpio::*;

    // Prepares a single chain of descriptors
    fn prepare_desc_chain(
        start_addr: GuestAddress,
        rtype: u16,
        gpio: u16,
        value: u32,
        len: u32,
    ) -> GpioDescriptorChain {
        let mem = GuestMemoryMmap::<()>::from_ranges(&[(start_addr, 0x1000)]).unwrap();
        let vq = MockSplitQueue::new(&mem, 16);
        let mut next_addr = vq.desc_table().total_size() + 0x100;
        let mut index = 0;

        // Out request descriptor
        let out_hdr = VirtioGpioRequest {
            rtype: From::from(rtype),
            gpio: From::from(gpio),
            value: From::from(value),
        };

        let desc_out = Descriptor::new(
            next_addr,
            size_of::<VirtioGpioRequest>() as u32,
            VIRTQ_DESC_F_NEXT,
            index + 1,
        );

        mem.write_obj::<VirtioGpioRequest>(out_hdr, desc_out.addr())
            .unwrap();
        vq.desc_table().store(index, desc_out);
        next_addr += desc_out.len() as u64;
        index += 1;

        // In response descriptor
        let desc_in = Descriptor::new(next_addr, len + 1, VIRTQ_DESC_F_WRITE, 0);
        vq.desc_table().store(index, desc_in);

        // Put the descriptor index 0 in the first available ring position.
        mem.write_obj(0u16, vq.avail_addr().unchecked_add(4))
            .unwrap();

        // Set `avail_idx` to 1.
        mem.write_obj(1u16, vq.avail_addr().unchecked_add(2))
            .unwrap();

        // Create descriptor chain from pre-filled memory
        vq.create_queue(GuestMemoryAtomic::<GuestMemoryMmap>::new(mem.clone()))
            .iter()
            .unwrap()
            .next()
            .unwrap()
    }

    // Prepares list of dummy descriptors, their content isn't significant
    fn prepare_desc_chain_dummy(
        addr: Option<Vec<u64>>,
        flags: Vec<u16>,
        len: Vec<u32>,
    ) -> GpioDescriptorChain {
        let mem = GuestMemoryMmap::<()>::from_ranges(&[(GuestAddress(0), 0x1000)]).unwrap();
        let vq = MockSplitQueue::new(&mem, 16);

        for (i, flag) in flags.iter().enumerate() {
            let mut f = if i == flags.len() - 1 {
                0
            } else {
                VIRTQ_DESC_F_NEXT
            };
            f |= flag;

            let offset = match addr {
                Some(ref addr) => addr[i],
                _ => 0x100,
            };

            let desc = Descriptor::new(offset, len[i], f, (i + 1) as u16);
            vq.desc_table().store(i as u16, desc);
        }

        // Put the descriptor index 0 in the first available ring position.
        mem.write_obj(0u16, vq.avail_addr().unchecked_add(4))
            .unwrap();

        // Set `avail_idx` to 1.
        mem.write_obj(1u16, vq.avail_addr().unchecked_add(2))
            .unwrap();

        // Create descriptor chain from pre-filled memory
        vq.create_queue(GuestMemoryAtomic::<GuestMemoryMmap>::new(mem.clone()))
            .iter()
            .unwrap()
            .next()
            .unwrap()
    }

    // Validate descriptor chains after processing them, checks pass/failure of
    // operation and the value of the buffers updated by the `DummyDevice`.
    fn validate_desc_chains(desc_chains: Vec<GpioDescriptorChain>, status: u8, val: Vec<u8>) {
        for (i, desc_chain) in desc_chains.iter().enumerate() {
            let descriptors: Vec<_> = desc_chain.clone().collect();
            let mut response = vec![0; descriptors[1].len() as usize];

            desc_chain
                .memory()
                .read(&mut response, descriptors[1].addr())
                .unwrap();

            // Operation result should match expected status.
            assert_eq!(response[0], status);
            assert_eq!(response[1], val[i]);
        }
    }

    #[test]
    fn process_requests_success() {
        const NGPIO: u16 = 256;
        let device = DummyDevice::new(NGPIO);
        let controller = GpioController::new(device).unwrap();
        let backend = VhostUserGpioBackend::new(controller).unwrap();

        // Descriptor chain size zero, shouldn't fail
        backend
            .process_requests(Vec::<GpioDescriptorChain>::new(), None)
            .unwrap();

        // Valid single GPIO operation
        let desc_chain = prepare_desc_chain(GuestAddress(0), VIRTIO_GPIO_MSG_SET_VALUE, 5, 1, 1);
        let desc_chains = vec![desc_chain];

        backend.process_requests(desc_chains.clone(), None).unwrap();
        validate_desc_chains(desc_chains, VIRTIO_GPIO_STATUS_OK, vec![0]);

        // Valid multi GPIO operation
        let desc_chains = vec![
            prepare_desc_chain(GuestAddress(0), VIRTIO_GPIO_MSG_SET_VALUE, 5, 1, 1),
            prepare_desc_chain(
                GuestAddress(0),
                VIRTIO_GPIO_MSG_SET_DIRECTION,
                5,
                VIRTIO_GPIO_DIRECTION_OUT as u32,
                1,
            ),
            prepare_desc_chain(GuestAddress(0), VIRTIO_GPIO_MSG_GET_VALUE, 5, 0, 1),
            prepare_desc_chain(GuestAddress(0), VIRTIO_GPIO_MSG_GET_DIRECTION, 5, 0, 1),
        ];

        backend.process_requests(desc_chains.clone(), None).unwrap();
        validate_desc_chains(
            desc_chains,
            VIRTIO_GPIO_STATUS_OK,
            vec![0, 0, 1, VIRTIO_GPIO_DIRECTION_OUT],
        );
    }

    #[test]
    fn process_requests_failure() {
        const NGPIO: u16 = 256;
        let device = DummyDevice::new(NGPIO);
        let controller = GpioController::new(device).unwrap();
        let backend = VhostUserGpioBackend::new(controller).unwrap();

        // One descriptors
        let flags: Vec<u16> = vec![0];
        let len: Vec<u32> = vec![0];
        let desc_chain = prepare_desc_chain_dummy(None, flags, len);
        assert_eq!(
            backend
                .process_requests(vec![desc_chain], None)
                .unwrap_err(),
            Error::UnexpectedDescriptorCount(1)
        );

        // Three descriptors
        let flags: Vec<u16> = vec![0, 0, 0];
        let len: Vec<u32> = vec![0, 0, 0];
        let desc_chain = prepare_desc_chain_dummy(None, flags, len);
        assert_eq!(
            backend
                .process_requests(vec![desc_chain], None)
                .unwrap_err(),
            Error::UnexpectedDescriptorCount(3)
        );

        // Write only out hdr
        let flags: Vec<u16> = vec![VIRTQ_DESC_F_WRITE, VIRTQ_DESC_F_WRITE];
        let len: Vec<u32> = vec![size_of::<VirtioGpioRequest>() as u32, 2];
        let desc_chain = prepare_desc_chain_dummy(None, flags, len);
        assert_eq!(
            backend
                .process_requests(vec![desc_chain], None)
                .unwrap_err(),
            Error::UnexpectedWriteOnlyDescriptor(0)
        );

        // Invalid out hdr address
        let addr: Vec<u64> = vec![0x10000, 0];
        let flags: Vec<u16> = vec![0, VIRTQ_DESC_F_WRITE];
        let len: Vec<u32> = vec![size_of::<VirtioGpioRequest>() as u32, 2];
        let desc_chain = prepare_desc_chain_dummy(Some(addr), flags, len);
        assert_eq!(
            backend
                .process_requests(vec![desc_chain], None)
                .unwrap_err(),
            Error::DescriptorReadFailed
        );

        // Invalid out hdr length
        let flags: Vec<u16> = vec![0, VIRTQ_DESC_F_WRITE];
        let len: Vec<u32> = vec![100, 2];
        let desc_chain = prepare_desc_chain_dummy(None, flags, len);
        assert_eq!(
            backend
                .process_requests(vec![desc_chain], None)
                .unwrap_err(),
            Error::UnexpectedDescriptorSize(size_of::<VirtioGpioRequest>(), 100)
        );

        // Read only in hdr
        let flags: Vec<u16> = vec![0, 0];
        let len: Vec<u32> = vec![size_of::<VirtioGpioRequest>() as u32, 2];
        let desc_chain = prepare_desc_chain_dummy(None, flags, len);
        assert_eq!(
            backend
                .process_requests(vec![desc_chain], None)
                .unwrap_err(),
            Error::UnexpectedReadableDescriptor(1)
        );

        // Invalid in hdr address
        let addr: Vec<u64> = vec![0, 0x10000];
        let flags: Vec<u16> = vec![0, VIRTQ_DESC_F_WRITE];
        let len: Vec<u32> = vec![size_of::<VirtioGpioRequest>() as u32, 2];
        let desc_chain = prepare_desc_chain_dummy(Some(addr), flags, len);
        assert_eq!(
            backend
                .process_requests(vec![desc_chain], None)
                .unwrap_err(),
            Error::DescriptorWriteFailed
        );

        // Invalid in hdr length
        let desc_chain = prepare_desc_chain(GuestAddress(0), VIRTIO_GPIO_MSG_SET_VALUE, 5, 1, 3);
        let desc_chains = vec![desc_chain];
        backend.process_requests(desc_chains.clone(), None).unwrap();
        validate_desc_chains(desc_chains, VIRTIO_GPIO_STATUS_ERR, vec![0]);
    }

    #[test]
    fn verify_backend() {
        const NGPIO: u16 = 256;
        let device = DummyDevice::new(NGPIO);
        let controller = GpioController::new(device).unwrap();
        let mut backend = VhostUserGpioBackend::new(controller).unwrap();

        assert_eq!(backend.num_queues(), NUM_QUEUES);
        assert_eq!(backend.max_queue_size(), QUEUE_SIZE);
        assert_eq!(backend.features(), 0x171000000);
        assert_eq!(
            backend.protocol_features(),
            VhostUserProtocolFeatures::MQ | VhostUserProtocolFeatures::CONFIG
        );

        assert_eq!(backend.queues_per_thread(), vec![0xffff_ffff]);

        backend.set_event_idx(true);
        assert!(backend.event_idx);
    }
}
