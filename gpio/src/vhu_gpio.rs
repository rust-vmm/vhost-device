// vhost device gpio
//
// Copyright 2022 Linaro Ltd. All Rights Reserved.
//          Viresh Kumar <viresh.kumar@linaro.org>
//
// SPDX-License-Identifier: Apache-2.0

use log::error;
use std::mem::size_of;
use std::slice::from_raw_parts;
use std::sync::{Arc, RwLock};
use std::thread::{spawn, JoinHandle};
use std::{convert, io};

use thiserror::Error as ThisError;
use vhost::vhost_user::message::{VhostUserProtocolFeatures, VhostUserVirtioFeatures};
use vhost_user_backend::{VhostUserBackendMut, VringRwLock, VringT};
use virtio_bindings::bindings::virtio_net::{VIRTIO_F_NOTIFY_ON_EMPTY, VIRTIO_F_VERSION_1};
use virtio_bindings::bindings::virtio_ring::{
    VIRTIO_RING_F_EVENT_IDX, VIRTIO_RING_F_INDIRECT_DESC,
};
use virtio_queue::DescriptorChain;
use vm_memory::{
    ByteValued, Bytes, GuestAddress, GuestMemoryAtomic, GuestMemoryLoadGuard, GuestMemoryMmap,
    Le16, Le32,
};
use vmm_sys_util::epoll::EventSet;
use vmm_sys_util::eventfd::{EventFd, EFD_NONBLOCK};

use crate::gpio::{GpioController, GpioDevice, VirtioGpioConfig, VIRTIO_GPIO_IRQ_TYPE_NONE};

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
type VhostUserBackendResult<T> = std::result::Result<T, std::io::Error>;

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
unsafe impl ByteValued for VirtioGpioRequest {}

/// Virtio GPIO IRQ Request / Response
#[derive(Copy, Clone, Default)]
struct VirtioGpioIrqRequest {
    gpio: Le16,
}
unsafe impl ByteValued for VirtioGpioIrqRequest {}

#[derive(Copy, Clone, Default)]
struct VirtioGpioIrqResponse {
    #[allow(dead_code)]
    status: u8,
}
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
}

type GpioDescriptorChain = DescriptorChain<GuestMemoryLoadGuard<GuestMemoryMmap<()>>>;

impl<D: GpioDevice> VhostUserGpioBackend<D> {
    pub(crate) fn new(controller: GpioController<D>) -> Result<Self> {
        // Can't set a vector to all None easily
        let mut handles: Vec<Option<JoinHandle<()>>> = Vec::new();
        handles.resize_with(controller.get_num_gpios() as usize, || None);

        Ok(VhostUserGpioBackend {
            controller: Arc::new(controller),
            handles: Arc::new(RwLock::new(handles)),
            event_idx: false,
            exit_event: EventFd::new(EFD_NONBLOCK).map_err(|_| Error::EventFdFailed)?,
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
            .iter()
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
        if controller.get_irq_type(gpio) == VIRTIO_GPIO_IRQ_TYPE_NONE || handle.is_some() {
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
            .iter()
            .map_err(|_| Error::DescriptorNotFound)?
            .collect();

        self.process_events(requests, vring)?;
        Ok(())
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
            | 1 << VIRTIO_GPIO_F_IRQ
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
        Ok(false)
    }

    fn exit_event(&self, _thread_index: usize) -> Option<EventFd> {
        self.exit_event.try_clone().ok()
    }
}
