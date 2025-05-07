// vhost device gpio
//
// Copyright 2022 Linaro Ltd. All Rights Reserved.
//          Viresh Kumar <viresh.kumar@linaro.org>
//
// SPDX-License-Identifier: Apache-2.0 or BSD-3-Clause

use log::error;
use std::mem::size_of;
use std::slice::from_raw_parts;
use std::sync::{Arc, RwLock};
use std::thread::{spawn, JoinHandle};
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
use vm_memory::{
    ByteValued, Bytes, GuestAddress, GuestAddressSpace, GuestMemoryAtomic, GuestMemoryLoadGuard,
    GuestMemoryMmap, Le16, Le32,
};
use vmm_sys_util::epoll::EventSet;
use vmm_sys_util::eventfd::{EventFd, EFD_NONBLOCK};

use crate::gpio::{GpioController, GpioDevice};
use crate::virtio_gpio::VIRTIO_GPIO_IRQ_TYPE_NONE;

/// Possible values of the status field
const VIRTIO_GPIO_STATUS_OK: u8 = 0x0;
const VIRTIO_GPIO_STATUS_ERR: u8 = 0x1;

/// Virtio GPIO Feature bits
const VIRTIO_GPIO_F_IRQ: u16 = 0;

const QUEUE_SIZE: usize = 256;
const NUM_QUEUES: usize = 2;

/// Queues
const REQUEST_QUEUE: u16 = 0;
const EVENT_QUEUE: u16 = 1;

type Result<T> = std::result::Result<T, Error>;

#[derive(Copy, Clone, Debug, PartialEq, ThisError)]
/// Errors related to vhost-device-gpio-daemon.
pub(crate) enum Error {
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
// SAFETY: The layout of the structure is fixed and can be initialized by
// reading its content from byte array.
unsafe impl ByteValued for VirtioGpioRequest {}

/// Virtio GPIO IRQ Request / Response
#[derive(Copy, Clone, Default)]
struct VirtioGpioIrqRequest {
    gpio: Le16,
}
// SAFETY: The layout of the structure is fixed and can be initialized by
// reading its content from byte array.
unsafe impl ByteValued for VirtioGpioIrqRequest {}

#[derive(Copy, Clone, Default)]
struct VirtioGpioIrqResponse {
    #[allow(dead_code)]
    status: u8,
}
// SAFETY: The layout of the structure is fixed and can be initialized by
// reading its content from byte array.
unsafe impl ByteValued for VirtioGpioIrqResponse {}

/// Possible values of the interrupt status field
const VIRTIO_GPIO_IRQ_STATUS_INVALID: u8 = 0x0;
const VIRTIO_GPIO_IRQ_STATUS_VALID: u8 = 0x1;

/// Send response over the eventq virtqueue.
fn send_event_response(
    vring: &VringRwLock,
    desc_chain: GpioDescriptorChain,
    addr: GuestAddress,
    status: u8,
) {
    let response = VirtioGpioIrqResponse { status };

    if desc_chain
        .memory()
        .write_obj::<VirtioGpioIrqResponse>(response, addr)
        .is_err()
    {
        error!("Failed to write response");
    }

    if vring
        .add_used(
            desc_chain.head_index(),
            size_of::<VirtioGpioIrqResponse>() as u32,
        )
        .is_err()
    {
        error!("Couldn't return used descriptors to the ring");
    }

    // Send notification once all the requests are processed
    if vring.signal_used_queue().is_err() {
        error!("Couldn't signal used queue");
    }
}

pub(crate) struct VhostUserGpioBackend<D: GpioDevice> {
    controller: Arc<GpioController<D>>,
    handles: Arc<RwLock<Vec<Option<JoinHandle<()>>>>>,
    event_idx: bool,
    pub(crate) exit_event: EventFd,
    mem: Option<GuestMemoryAtomic<GuestMemoryMmap>>,
}

type GpioDescriptorChain = DescriptorChain<GuestMemoryLoadGuard<GuestMemoryMmap<()>>>;

impl<D: GpioDevice> VhostUserGpioBackend<D> {
    pub(crate) fn new(controller: GpioController<D>) -> Result<Self> {
        // Can't set a vector to all None easily
        let mut handles: Vec<Option<JoinHandle<()>>> = Vec::new();
        handles.resize_with(controller.num_gpios() as usize, || None);

        Ok(VhostUserGpioBackend {
            controller: Arc::new(controller),
            handles: Arc::new(RwLock::new(handles)),
            event_idx: false,
            exit_event: EventFd::new(EFD_NONBLOCK).map_err(|_| Error::EventFdFailed)?,
            mem: None,
        })
    }

    /// Process the requests in the request queue
    fn process_requests(
        &self,
        requests: Vec<GpioDescriptorChain>,
        vring: &VringRwLock,
    ) -> Result<bool> {
        if requests.is_empty() {
            return Ok(true);
        }

        for desc_chain in requests {
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

            if vring
                .add_used(desc_chain.head_index(), desc_response.len())
                .is_err()
            {
                error!("Couldn't return used descriptors to the ring");
            }
        }

        Ok(true)
    }

    /// Process the messages in the vring and dispatch replies
    fn process_request_queue(&self, vring: &VringRwLock) -> Result<()> {
        let requests: Vec<_> = vring
            .get_mut()
            .get_queue_mut()
            .iter(self.mem.as_ref().unwrap().memory())
            .map_err(|_| Error::DescriptorNotFound)?
            .collect();

        if self.process_requests(requests, vring)? {
            // Send notification once all the requests are processed
            vring
                .signal_used_queue()
                .map_err(|_| Error::NotificationFailed)?;
        }

        Ok(())
    }

    /// Process the request in the event queue
    fn process_event(
        &mut self,
        vring: &VringRwLock,
        desc_chain: GpioDescriptorChain,
        gpio: u16,
        addr: GuestAddress,
    ) {
        // Take lock here to avoid race with thread.
        let handle = &mut self.handles.write().unwrap()[gpio as usize];
        let controller = self.controller.clone();

        // Interrupt should be enabled before sending buffer and no other buffer
        // should have been received earlier for this GPIO pin.
        if controller.irq_type(gpio) == VIRTIO_GPIO_IRQ_TYPE_NONE || handle.is_some() {
            send_event_response(vring, desc_chain, addr, VIRTIO_GPIO_IRQ_STATUS_INVALID);
            return;
        }

        // Queue a thread to wait for and process the interrupt.
        let handles = self.handles.clone();
        let vring = vring.clone();
        *handle = Some(spawn(move || {
            let status = match controller.wait_for_interrupt(gpio) {
                Ok(_) => VIRTIO_GPIO_IRQ_STATUS_VALID,
                _ => VIRTIO_GPIO_IRQ_STATUS_INVALID,
            };

            send_event_response(&vring, desc_chain, addr, status);
            handles.write().unwrap()[gpio as usize] = None;
        }));
    }

    /// Process the requests in the event queue
    fn process_events(
        &mut self,
        requests: Vec<GpioDescriptorChain>,
        vring: &VringRwLock,
    ) -> Result<()> {
        if requests.is_empty() {
            return Ok(());
        }

        for desc_chain in requests {
            let descriptors: Vec<_> = desc_chain.clone().collect();
            if descriptors.len() != 2 {
                return Err(Error::UnexpectedDescriptorCount(descriptors.len()));
            }

            let desc_request = descriptors[0];
            if desc_request.is_write_only() {
                return Err(Error::UnexpectedWriteOnlyDescriptor(0));
            }

            if desc_request.len() as usize != size_of::<VirtioGpioIrqRequest>() {
                return Err(Error::UnexpectedDescriptorSize(
                    size_of::<VirtioGpioIrqRequest>(),
                    desc_request.len(),
                ));
            }

            let request = desc_chain
                .memory()
                .read_obj::<VirtioGpioIrqRequest>(desc_request.addr())
                .map_err(|_| Error::DescriptorReadFailed)?;

            let desc_response = descriptors[1];
            if !desc_response.is_write_only() {
                return Err(Error::UnexpectedReadableDescriptor(1));
            }

            if desc_response.len() as usize != size_of::<VirtioGpioIrqResponse>() {
                return Err(Error::UnexpectedDescriptorSize(
                    size_of::<VirtioGpioIrqResponse>(),
                    desc_response.len(),
                ));
            }

            self.process_event(
                vring,
                desc_chain,
                request.gpio.to_native(),
                desc_response.addr(),
            );
        }

        Ok(())
    }

    /// Process the messages in the vring and dispatch replies
    fn process_event_queue(&mut self, vring: &VringRwLock) -> Result<()> {
        let requests: Vec<_> = vring
            .get_mut()
            .get_queue_mut()
            .iter(self.mem.as_ref().unwrap().memory())
            .map_err(|_| Error::DescriptorNotFound)?
            .collect();

        self.process_events(requests, vring)?;
        Ok(())
    }
}

/// VhostUserBackendMut trait methods
impl<D: 'static + GpioDevice + Sync + Send> VhostUserBackendMut for VhostUserGpioBackend<D> {
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
        (1 << VIRTIO_F_VERSION_1)
            | (1 << VIRTIO_F_NOTIFY_ON_EMPTY)
            | (1 << VIRTIO_RING_F_INDIRECT_DESC)
            | (1 << VIRTIO_RING_F_EVENT_IDX)
            | (1 << VIRTIO_GPIO_F_IRQ)
            | VhostUserVirtioFeatures::PROTOCOL_FEATURES.bits()
    }

    fn protocol_features(&self) -> VhostUserProtocolFeatures {
        VhostUserProtocolFeatures::MQ
            | VhostUserProtocolFeatures::CONFIG
            | VhostUserProtocolFeatures::REPLY_ACK
    }

    fn get_config(&self, offset: u32, size: u32) -> Vec<u8> {
        // SAFETY: The layout of the structure is fixed and can be initialized by
        // reading its content from byte array.
        unsafe {
            from_raw_parts(
                self.controller
                    .config()
                    .as_slice()
                    .as_ptr()
                    .offset(offset as isize) as *const _ as *const _,
                size as usize,
            )
            .to_vec()
        }
    }

    fn set_event_idx(&mut self, enabled: bool) {
        self.event_idx = enabled;
    }

    fn update_memory(&mut self, mem: GuestMemoryAtomic<GuestMemoryMmap>) -> IoResult<()> {
        self.mem = Some(mem);
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

            EVENT_QUEUE => {
                let vring = &vrings[1];

                if self.event_idx {
                    // vm-virtio's Queue implementation only checks avail_index
                    // once, so to properly support EVENT_IDX we need to keep
                    // calling process_event_queue() until it stops finding
                    // new requests on the queue.
                    loop {
                        vring.disable_notification().unwrap();
                        self.process_event_queue(vring)?;
                        if !vring.enable_notification().unwrap() {
                            break;
                        }
                    }
                } else {
                    // Without EVENT_IDX, a single call is enough.
                    self.process_event_queue(vring)?;
                }
            }

            _ => {
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
    use virtio_bindings::bindings::virtio_ring::{VRING_DESC_F_NEXT, VRING_DESC_F_WRITE};
    use virtio_queue::{
        desc::{split::Descriptor as SplitDescriptor, RawDescriptor},
        mock::MockSplitQueue,
        Queue,
    };
    use vm_memory::{Address, GuestAddress, GuestMemoryAtomic, GuestMemoryMmap};

    use super::Error;
    use super::*;
    use crate::gpio::Error as GpioError;
    use crate::gpio::*;
    use crate::mock_gpio::MockGpioDevice;
    use crate::virtio_gpio::*;

    // Prepares a single chain of descriptors for request queue
    fn prepare_desc_chain<R: ByteValued>(
        start_addr: GuestAddress,
        out_hdr: R,
        response_len: u32,
    ) -> GpioDescriptorChain {
        let mem = &GuestMemoryMmap::<()>::from_ranges(&[(start_addr, 0x1000)]).unwrap();
        let vq = MockSplitQueue::new(mem, 16);
        let mut next_addr = vq.desc_table().total_size() + 0x100;
        let mut index = 0;

        let desc_out = SplitDescriptor::new(
            next_addr,
            size_of::<R>() as u32,
            VRING_DESC_F_NEXT as u16,
            index + 1,
        );

        mem.write_obj::<R>(out_hdr, desc_out.addr()).unwrap();
        vq.desc_table()
            .store(index, RawDescriptor::from(desc_out))
            .unwrap();
        next_addr += desc_out.len() as u64;
        index += 1;

        // In response descriptor
        let desc_in = RawDescriptor::from(SplitDescriptor::new(
            next_addr,
            response_len,
            VRING_DESC_F_WRITE as u16,
            0,
        ));
        vq.desc_table().store(index, desc_in).unwrap();

        // Put the descriptor index 0 in the first available ring position.
        mem.write_obj(0u16, vq.avail_addr().unchecked_add(4))
            .unwrap();

        // Set `avail_idx` to 1.
        mem.write_obj(1u16, vq.avail_addr().unchecked_add(2))
            .unwrap();

        // Create descriptor chain from pre-filled memory
        vq.create_queue::<Queue>()
            .unwrap()
            .iter(GuestMemoryAtomic::new(mem.clone()).memory())
            .unwrap()
            .next()
            .unwrap()
    }

    // Prepares a single chain of descriptors for request queue
    fn prepare_request_desc_chain(
        start_addr: GuestAddress,
        rtype: u16,
        gpio: u16,
        value: u32,
        len: u32,
    ) -> GpioDescriptorChain {
        // Out request descriptor
        let out_hdr = VirtioGpioRequest {
            rtype: From::from(rtype),
            gpio: From::from(gpio),
            value: From::from(value),
        };

        prepare_desc_chain::<VirtioGpioRequest>(start_addr, out_hdr, len + 1)
    }

    // Prepares a single chain of descriptors for event queue
    fn prepare_event_desc_chain(start_addr: GuestAddress, gpio: u16) -> GpioDescriptorChain {
        // Out event descriptor
        let out_hdr = VirtioGpioIrqRequest {
            gpio: From::from(gpio),
        };

        prepare_desc_chain::<VirtioGpioIrqRequest>(
            start_addr,
            out_hdr,
            size_of::<VirtioGpioIrqResponse>() as u32,
        )
    }

    // Prepares list of dummy descriptors, their content isn't significant.
    fn prepare_desc_chain_dummy(
        addr: Option<Vec<u64>>,
        flags: Vec<u16>,
        len: Vec<u32>,
    ) -> GpioDescriptorChain {
        let mem = &GuestMemoryMmap::<()>::from_ranges(&[(GuestAddress(0), 0x1000)]).unwrap();
        let vq = MockSplitQueue::new(mem, 16);

        for (i, flag) in flags.iter().enumerate() {
            let mut f: u16 = if i == flags.len() - 1 {
                0
            } else {
                VRING_DESC_F_NEXT as u16
            };
            f |= flag;

            let offset = match addr {
                Some(ref addr) => addr[i],
                _ => 0x100,
            };

            let desc = RawDescriptor::from(SplitDescriptor::new(offset, len[i], f, (i + 1) as u16));
            vq.desc_table().store(i as u16, desc).unwrap();
        }

        // Put the descriptor index 0 in the first available ring position.
        mem.write_obj(0u16, vq.avail_addr().unchecked_add(4))
            .unwrap();

        // Set `avail_idx` to 1.
        mem.write_obj(1u16, vq.avail_addr().unchecked_add(2))
            .unwrap();

        // Create descriptor chain from pre-filled memory
        vq.create_queue::<Queue>()
            .unwrap()
            .iter(GuestMemoryAtomic::new(mem.clone()).memory())
            .unwrap()
            .next()
            .unwrap()
    }

    // Validate descriptor chains after processing them, checks pass/failure of
    // operation and the value of the buffers updated by the `MockGpioDevice`.
    fn validate_desc_chains(
        desc_chains: Vec<GpioDescriptorChain>,
        status: u8,
        val: Option<Vec<u8>>,
    ) {
        for (i, desc_chain) in desc_chains.iter().enumerate() {
            let descriptors: Vec<_> = desc_chain.clone().collect();
            let mut response = vec![0; descriptors[1].len() as usize];

            desc_chain
                .memory()
                .read(&mut response, descriptors[1].addr())
                .unwrap();

            // Operation result should match expected status.
            assert_eq!(response[0], status);
            if let Some(val) = &val {
                assert_eq!(response[1], val[i]);
            }
        }
    }

    #[test]
    fn test_gpio_process_requests_success() {
        const NGPIO: u16 = 256;
        const GPIO: u16 = 5;
        let device = MockGpioDevice::new(NGPIO);
        let controller = GpioController::new(device).unwrap();
        let backend = VhostUserGpioBackend::new(controller).unwrap();
        let mem = GuestMemoryAtomic::new(
            GuestMemoryMmap::<()>::from_ranges(&[(GuestAddress(0), 0x1000)]).unwrap(),
        );
        let vring = VringRwLock::new(mem, 0x1000).unwrap();

        // Descriptor chain size zero, shouldn't fail
        backend
            .process_requests(Vec::<GpioDescriptorChain>::new(), &vring)
            .unwrap();

        // Valid single GPIO operation
        let desc_chain =
            prepare_request_desc_chain(GuestAddress(0), VIRTIO_GPIO_MSG_SET_VALUE, GPIO, 1, 1);
        let desc_chains = vec![desc_chain];

        backend
            .process_requests(desc_chains.clone(), &vring)
            .unwrap();
        validate_desc_chains(desc_chains, VIRTIO_GPIO_STATUS_OK, Some(vec![0]));

        // Valid multi GPIO operation
        let desc_chains = vec![
            prepare_request_desc_chain(GuestAddress(0), VIRTIO_GPIO_MSG_SET_VALUE, GPIO, 1, 1),
            prepare_request_desc_chain(
                GuestAddress(0),
                VIRTIO_GPIO_MSG_SET_DIRECTION,
                GPIO,
                VIRTIO_GPIO_DIRECTION_OUT as u32,
                1,
            ),
            prepare_request_desc_chain(GuestAddress(0), VIRTIO_GPIO_MSG_GET_VALUE, GPIO, 0, 1),
            prepare_request_desc_chain(GuestAddress(0), VIRTIO_GPIO_MSG_GET_DIRECTION, GPIO, 0, 1),
        ];

        backend
            .process_requests(desc_chains.clone(), &vring)
            .unwrap();
        validate_desc_chains(
            desc_chains,
            VIRTIO_GPIO_STATUS_OK,
            Some(vec![0, 0, 1, VIRTIO_GPIO_DIRECTION_OUT]),
        );
    }

    #[test]
    fn test_gpio_process_requests_failure() {
        const NGPIO: u16 = 256;
        const GPIO: u16 = 5;
        let device = MockGpioDevice::new(NGPIO);
        let controller = GpioController::new(device).unwrap();
        let backend = VhostUserGpioBackend::new(controller).unwrap();
        let mem = GuestMemoryAtomic::new(
            GuestMemoryMmap::<()>::from_ranges(&[(GuestAddress(0), 0x1000)]).unwrap(),
        );
        let vring = VringRwLock::new(mem, 0x1000).unwrap();

        // Have only one descriptor, expected two.
        let flags: Vec<u16> = vec![0];
        let len: Vec<u32> = vec![0];
        let desc_chain = prepare_desc_chain_dummy(None, flags, len);
        assert_eq!(
            backend
                .process_requests(vec![desc_chain], &vring)
                .unwrap_err(),
            Error::UnexpectedDescriptorCount(1)
        );

        // Have three descriptors, expected two.
        let flags: Vec<u16> = vec![0, 0, 0];
        let len: Vec<u32> = vec![0, 0, 0];
        let desc_chain = prepare_desc_chain_dummy(None, flags, len);
        assert_eq!(
            backend
                .process_requests(vec![desc_chain], &vring)
                .unwrap_err(),
            Error::UnexpectedDescriptorCount(3)
        );

        // Write only out hdr.
        let flags: Vec<u16> = vec![VRING_DESC_F_WRITE as u16, VRING_DESC_F_WRITE as u16];
        let len: Vec<u32> = vec![size_of::<VirtioGpioRequest>() as u32, 2];
        let desc_chain = prepare_desc_chain_dummy(None, flags, len);
        assert_eq!(
            backend
                .process_requests(vec![desc_chain], &vring)
                .unwrap_err(),
            Error::UnexpectedWriteOnlyDescriptor(0)
        );

        // Invalid out hdr address.
        let addr: Vec<u64> = vec![0x10000, 0];
        let flags: Vec<u16> = vec![0, VRING_DESC_F_WRITE as u16];
        let len: Vec<u32> = vec![size_of::<VirtioGpioRequest>() as u32, 2];
        let desc_chain = prepare_desc_chain_dummy(Some(addr), flags, len);
        assert_eq!(
            backend
                .process_requests(vec![desc_chain], &vring)
                .unwrap_err(),
            Error::DescriptorReadFailed
        );

        // Invalid out hdr length.
        let flags: Vec<u16> = vec![0, VRING_DESC_F_WRITE as u16];
        let len: Vec<u32> = vec![100, 2];
        let desc_chain = prepare_desc_chain_dummy(None, flags, len);
        assert_eq!(
            backend
                .process_requests(vec![desc_chain], &vring)
                .unwrap_err(),
            Error::UnexpectedDescriptorSize(size_of::<VirtioGpioRequest>(), 100)
        );

        // Read only in hdr.
        let flags: Vec<u16> = vec![0, 0];
        let len: Vec<u32> = vec![size_of::<VirtioGpioRequest>() as u32, 2];
        let desc_chain = prepare_desc_chain_dummy(None, flags, len);
        assert_eq!(
            backend
                .process_requests(vec![desc_chain], &vring)
                .unwrap_err(),
            Error::UnexpectedReadableDescriptor(1)
        );

        // Invalid in hdr address.
        let addr: Vec<u64> = vec![0, 0x10000];
        let flags: Vec<u16> = vec![0, VRING_DESC_F_WRITE as u16];
        let len: Vec<u32> = vec![size_of::<VirtioGpioRequest>() as u32, 2];
        let desc_chain = prepare_desc_chain_dummy(Some(addr), flags, len);
        assert_eq!(
            backend
                .process_requests(vec![desc_chain], &vring)
                .unwrap_err(),
            Error::DescriptorWriteFailed
        );

        // Invalid in hdr length.
        let desc_chain =
            prepare_request_desc_chain(GuestAddress(0), VIRTIO_GPIO_MSG_SET_VALUE, GPIO, 1, 3);
        let desc_chains = vec![desc_chain];
        backend
            .process_requests(desc_chains.clone(), &vring)
            .unwrap();
        validate_desc_chains(desc_chains, VIRTIO_GPIO_STATUS_ERR, Some(vec![0]));
    }

    #[test]
    fn test_gpio_process_events_success() {
        const NGPIO: u16 = 256;
        const GPIO: u16 = 5;
        let device = MockGpioDevice::new(NGPIO);
        let controller = GpioController::new(device).unwrap();
        let mut backend = VhostUserGpioBackend::new(controller).unwrap();
        let mem = GuestMemoryAtomic::new(
            GuestMemoryMmap::<()>::from_ranges(&[(GuestAddress(0), 0x1000)]).unwrap(),
        );
        let vring = VringRwLock::new(mem, 0x1000).unwrap();

        // Descriptor chain size zero, shouldn't fail.
        backend
            .process_events(Vec::<GpioDescriptorChain>::new(), &vring)
            .unwrap();

        // Set direction should pass.
        let desc_chain = prepare_request_desc_chain(
            GuestAddress(0),
            VIRTIO_GPIO_MSG_SET_DIRECTION,
            GPIO,
            VIRTIO_GPIO_DIRECTION_IN as u32,
            1,
        );
        let desc_chains = vec![desc_chain];
        backend
            .process_requests(desc_chains.clone(), &vring)
            .unwrap();
        validate_desc_chains(desc_chains, VIRTIO_GPIO_STATUS_OK, Some(vec![0]));

        // Set irq type should pass.
        let desc_chain = prepare_request_desc_chain(
            GuestAddress(0),
            VIRTIO_GPIO_MSG_IRQ_TYPE,
            GPIO,
            VIRTIO_GPIO_IRQ_TYPE_EDGE_BOTH as u32,
            1,
        );
        let desc_chains = vec![desc_chain];
        backend
            .process_requests(desc_chains.clone(), &vring)
            .unwrap();
        validate_desc_chains(desc_chains, VIRTIO_GPIO_STATUS_OK, Some(vec![0]));

        // Wait for interrupt should pass
        let desc_chain = prepare_event_desc_chain(GuestAddress(0), GPIO);
        let desc_chains = vec![desc_chain];
        backend.process_events(desc_chains.clone(), &vring).unwrap();

        while backend.handles.read().unwrap()[GPIO as usize].is_some() {}
        validate_desc_chains(desc_chains, VIRTIO_GPIO_IRQ_STATUS_VALID, None);
    }

    #[test]
    fn test_gpio_process_events_multi_success() {
        const NGPIO: u16 = 256;
        const GPIO: u16 = 5;
        let device = MockGpioDevice::new(NGPIO);
        let controller = GpioController::new(device).unwrap();
        let mut backend = VhostUserGpioBackend::new(controller).unwrap();
        let mem = GuestMemoryAtomic::new(
            GuestMemoryMmap::<()>::from_ranges(&[(GuestAddress(0), 0x1000)]).unwrap(),
        );
        let vring = VringRwLock::new(mem, 0x1000).unwrap();

        let desc_chains = vec![
            // Prepare line: GPIO
            prepare_request_desc_chain(
                GuestAddress(0),
                VIRTIO_GPIO_MSG_SET_DIRECTION,
                GPIO,
                VIRTIO_GPIO_DIRECTION_IN as u32,
                1,
            ),
            prepare_request_desc_chain(
                GuestAddress(0),
                VIRTIO_GPIO_MSG_IRQ_TYPE,
                GPIO,
                VIRTIO_GPIO_IRQ_TYPE_EDGE_BOTH as u32,
                1,
            ),
            // Prepare line: GPIO + 1
            prepare_request_desc_chain(
                GuestAddress(0),
                VIRTIO_GPIO_MSG_SET_DIRECTION,
                GPIO + 1,
                VIRTIO_GPIO_DIRECTION_IN as u32,
                1,
            ),
            prepare_request_desc_chain(
                GuestAddress(0),
                VIRTIO_GPIO_MSG_IRQ_TYPE,
                GPIO + 1,
                VIRTIO_GPIO_IRQ_TYPE_EDGE_BOTH as u32,
                1,
            ),
            // Prepare line: GPIO + 2
            prepare_request_desc_chain(
                GuestAddress(0),
                VIRTIO_GPIO_MSG_SET_DIRECTION,
                GPIO + 2,
                VIRTIO_GPIO_DIRECTION_IN as u32,
                1,
            ),
            prepare_request_desc_chain(
                GuestAddress(0),
                VIRTIO_GPIO_MSG_IRQ_TYPE,
                GPIO + 2,
                VIRTIO_GPIO_IRQ_TYPE_EDGE_BOTH as u32,
                1,
            ),
        ];

        backend
            .process_requests(desc_chains.clone(), &vring)
            .unwrap();
        validate_desc_chains(
            desc_chains,
            VIRTIO_GPIO_STATUS_OK,
            Some(vec![0, 0, 0, 0, 0, 0]),
        );

        // Wait for interrupt should pass.
        let desc_chains = vec![
            prepare_event_desc_chain(GuestAddress(0), GPIO),
            prepare_event_desc_chain(GuestAddress(0), GPIO + 1),
            prepare_event_desc_chain(GuestAddress(0), GPIO + 2),
        ];

        backend.process_events(desc_chains.clone(), &vring).unwrap();

        while {
            let h = backend.handles.read().unwrap();

            h[GPIO as usize].is_some()
                || h[(GPIO + 1) as usize].is_some()
                || h[(GPIO + 2) as usize].is_some()
        } {}

        validate_desc_chains(desc_chains, VIRTIO_GPIO_IRQ_STATUS_VALID, None);
    }

    #[test]
    fn test_gpio_process_events_failure() {
        const NGPIO: u16 = 256;
        let err = GpioError::GpioIrqTypeInvalid(0);
        let mut device = MockGpioDevice::new(NGPIO);

        // This will make process-request fail later with
        // VIRTIO_GPIO_IRQ_STATUS_INVALID error.
        device.wait_for_irq_result = Err(err);

        let controller = GpioController::new(device).unwrap();
        let mut backend = VhostUserGpioBackend::new(controller).unwrap();
        let mem = GuestMemoryAtomic::new(
            GuestMemoryMmap::<()>::from_ranges(&[(GuestAddress(0), 0x1000)]).unwrap(),
        );
        let vring = VringRwLock::new(mem, 0x1000).unwrap();

        // Only one descriptor, expected two.
        let flags: Vec<u16> = vec![0];
        let len: Vec<u32> = vec![0];
        let desc_chain = prepare_desc_chain_dummy(None, flags, len);
        assert_eq!(
            backend
                .process_events(vec![desc_chain], &vring)
                .unwrap_err(),
            Error::UnexpectedDescriptorCount(1)
        );

        // Three descriptors, expected two.
        let flags: Vec<u16> = vec![0, 0, 0];
        let len: Vec<u32> = vec![0, 0, 0];
        let desc_chain = prepare_desc_chain_dummy(None, flags, len);
        assert_eq!(
            backend
                .process_events(vec![desc_chain], &vring)
                .unwrap_err(),
            Error::UnexpectedDescriptorCount(3)
        );

        // Write only out hdr
        let flags: Vec<u16> = vec![VRING_DESC_F_WRITE as u16, VRING_DESC_F_WRITE as u16];
        let len: Vec<u32> = vec![
            size_of::<VirtioGpioIrqRequest>() as u32,
            size_of::<VirtioGpioIrqResponse>() as u32,
        ];
        let desc_chain = prepare_desc_chain_dummy(None, flags, len);
        assert_eq!(
            backend
                .process_events(vec![desc_chain], &vring)
                .unwrap_err(),
            Error::UnexpectedWriteOnlyDescriptor(0)
        );

        // Invalid out hdr address
        let addr: Vec<u64> = vec![0x10000, 0];
        let flags: Vec<u16> = vec![0, VRING_DESC_F_WRITE as u16];
        let len: Vec<u32> = vec![
            size_of::<VirtioGpioIrqRequest>() as u32,
            size_of::<VirtioGpioIrqResponse>() as u32,
        ];
        let desc_chain = prepare_desc_chain_dummy(Some(addr), flags, len);
        assert_eq!(
            backend
                .process_events(vec![desc_chain], &vring)
                .unwrap_err(),
            Error::DescriptorReadFailed
        );

        // Invalid out hdr length
        let flags: Vec<u16> = vec![0, VRING_DESC_F_WRITE as u16];
        let len: Vec<u32> = vec![100, size_of::<VirtioGpioIrqResponse>() as u32];
        let desc_chain = prepare_desc_chain_dummy(None, flags, len);
        assert_eq!(
            backend
                .process_events(vec![desc_chain], &vring)
                .unwrap_err(),
            Error::UnexpectedDescriptorSize(size_of::<VirtioGpioIrqRequest>(), 100)
        );

        // Read only in hdr
        let flags: Vec<u16> = vec![0, 0];
        let len: Vec<u32> = vec![
            size_of::<VirtioGpioIrqRequest>() as u32,
            size_of::<VirtioGpioIrqResponse>() as u32,
        ];
        let desc_chain = prepare_desc_chain_dummy(None, flags, len);
        assert_eq!(
            backend
                .process_events(vec![desc_chain], &vring)
                .unwrap_err(),
            Error::UnexpectedReadableDescriptor(1)
        );

        // Invalid in hdr length
        let flags: Vec<u16> = vec![0, VRING_DESC_F_WRITE as u16];
        let len: Vec<u32> = vec![size_of::<VirtioGpioIrqRequest>() as u32, 100];
        let desc_chain = prepare_desc_chain_dummy(None, flags, len);
        assert_eq!(
            backend
                .process_events(vec![desc_chain], &vring)
                .unwrap_err(),
            Error::UnexpectedDescriptorSize(size_of::<VirtioGpioIrqResponse>(), 100)
        );

        // Wait for event without setting irq type first.
        let flags: Vec<u16> = vec![0, VRING_DESC_F_WRITE as u16];
        let len: Vec<u32> = vec![
            size_of::<VirtioGpioIrqRequest>() as u32,
            size_of::<VirtioGpioIrqResponse>() as u32,
        ];
        let desc_chain = prepare_desc_chain_dummy(None, flags, len);
        let desc_chains = vec![desc_chain];
        backend.process_events(desc_chains.clone(), &vring).unwrap();
        validate_desc_chains(desc_chains, VIRTIO_GPIO_IRQ_STATUS_INVALID, None);

        // Wait for interrupt failure with VIRTIO_GPIO_IRQ_STATUS_INVALID status, as was set at the
        // top of this function.
        const GPIO: u16 = 5;
        // Set irq type
        let desc_chain = prepare_request_desc_chain(
            GuestAddress(0),
            VIRTIO_GPIO_MSG_IRQ_TYPE,
            GPIO,
            VIRTIO_GPIO_IRQ_TYPE_EDGE_BOTH as u32,
            1,
        );
        let desc_chains = vec![desc_chain];
        backend
            .process_requests(desc_chains.clone(), &vring)
            .unwrap();
        validate_desc_chains(desc_chains, VIRTIO_GPIO_STATUS_OK, Some(vec![0]));

        // Wait for interrupt
        let desc_chain = prepare_event_desc_chain(GuestAddress(0), GPIO);
        let desc_chains = vec![desc_chain];
        backend.process_events(desc_chains.clone(), &vring).unwrap();

        while backend.handles.read().unwrap()[GPIO as usize].is_some() {}
        validate_desc_chains(desc_chains, VIRTIO_GPIO_IRQ_STATUS_INVALID, None);
    }

    #[test]
    fn test_gpio_verify_backend() {
        const NGPIO: u16 = 8;
        let mut gpio_names = vec![
            "gpio0".to_string(),
            '\0'.to_string(),
            "gpio2".to_string(),
            '\0'.to_string(),
            "gpio4".to_string(),
            '\0'.to_string(),
            "gpio6".to_string(),
            '\0'.to_string(),
        ];
        // Controller adds '\0' for each line.
        let names_size = std::mem::size_of_val(&gpio_names) + gpio_names.len();

        let mut device = MockGpioDevice::new(NGPIO);
        device.gpio_names.clear();
        device.gpio_names.append(&mut gpio_names);
        let controller = GpioController::new(device).unwrap();
        let mut backend = VhostUserGpioBackend::new(controller).unwrap();

        assert_eq!(backend.num_queues(), NUM_QUEUES);
        assert_eq!(backend.max_queue_size(), QUEUE_SIZE);
        assert_eq!(backend.features(), 0x171000001);
        assert_eq!(
            backend.protocol_features(),
            VhostUserProtocolFeatures::MQ
                | VhostUserProtocolFeatures::CONFIG
                | VhostUserProtocolFeatures::REPLY_ACK
        );

        assert_eq!(backend.queues_per_thread(), vec![0xffff_ffff]);

        backend.set_event_idx(true);
        assert!(backend.event_idx);

        assert!(backend.exit_event(0).is_some());

        let config = VirtioGpioConfig {
            ngpio: From::from(NGPIO),
            padding: From::from(0),
            gpio_names_size: From::from(names_size as u32),
        };

        assert_eq!(
            backend.get_config(0, size_of::<VirtioGpioConfig>() as u32),
            // SAFETY: The layout of the structure is fixed and can be initialized by
            // reading its content from byte array.
            unsafe {
                from_raw_parts(
                    &config as *const _ as *const _,
                    size_of::<VirtioGpioConfig>(),
                )
                .to_vec()
            }
        );

        let mem = GuestMemoryAtomic::new(
            GuestMemoryMmap::<()>::from_ranges(&[(GuestAddress(0), 0x1000)]).unwrap(),
        );
        backend.update_memory(mem.clone()).unwrap();

        let vring_request = VringRwLock::new(mem.clone(), 0x1000).unwrap();
        vring_request.set_queue_info(0x100, 0x200, 0x300).unwrap();
        vring_request.set_queue_ready(true);

        let vring_event = VringRwLock::new(mem, 0x1000).unwrap();
        vring_event.set_queue_info(0x100, 0x200, 0x300).unwrap();
        vring_event.set_queue_ready(true);

        assert_eq!(
            backend
                .handle_event(
                    0,
                    EventSet::OUT,
                    &[vring_request.clone(), vring_event.clone()],
                    0,
                )
                .unwrap_err()
                .kind(),
            io::ErrorKind::Other
        );

        assert_eq!(
            backend
                .handle_event(
                    2,
                    EventSet::IN,
                    &[vring_request.clone(), vring_event.clone()],
                    0,
                )
                .unwrap_err()
                .kind(),
            io::ErrorKind::Other
        );

        // Hit the loop part
        backend.set_event_idx(true);
        backend
            .handle_event(
                0,
                EventSet::IN,
                &[vring_request.clone(), vring_event.clone()],
                0,
            )
            .unwrap();

        // Hit the non-loop part
        backend.set_event_idx(false);
        backend
            .handle_event(
                0,
                EventSet::IN,
                &[vring_request.clone(), vring_event.clone()],
                0,
            )
            .unwrap();

        // Hit the loop part
        backend.set_event_idx(true);
        backend
            .handle_event(
                1,
                EventSet::IN,
                &[vring_request.clone(), vring_event.clone()],
                0,
            )
            .unwrap();

        // Hit the non-loop part
        backend.set_event_idx(false);
        backend
            .handle_event(1, EventSet::IN, &[vring_request, vring_event], 0)
            .unwrap();
    }
}
