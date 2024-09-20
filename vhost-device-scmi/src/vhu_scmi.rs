// SPDX-FileCopyrightText: Red Hat, Inc.
// SPDX-License-Identifier: Apache-2.0
// Based on https://github.com/rust-vmm/vhost-device, Copyright by Linaro Ltd.

//! General part of the vhost-user SCMI backend.  Nothing very different from
//! the other rust-vmm backends.

use log::{debug, error, warn};
use std::io;
use std::io::Result as IoResult;
use std::mem::size_of;
use thiserror::Error as ThisError;
use vhost::vhost_user::message::{VhostUserProtocolFeatures, VhostUserVirtioFeatures};
use vhost_user_backend::{VhostUserBackendMut, VringRwLock, VringT};
use virtio_bindings::bindings::virtio_config::{VIRTIO_F_NOTIFY_ON_EMPTY, VIRTIO_F_VERSION_1};
use virtio_bindings::bindings::virtio_ring::{
    VIRTIO_RING_F_EVENT_IDX, VIRTIO_RING_F_INDIRECT_DESC,
};
use virtio_queue::{DescriptorChain, QueueOwnedT};
use vm_memory::{
    Bytes, GuestAddressSpace, GuestMemoryAtomic, GuestMemoryLoadGuard, GuestMemoryMmap,
};
use vmm_sys_util::epoll::EventSet;
use vmm_sys_util::eventfd::{EventFd, EFD_NONBLOCK};

use crate::devices::common::{available_devices, DeviceError};
use crate::scmi::{MessageHeader, ScmiHandler, ScmiRequest};
use crate::VuScmiConfig;

// QUEUE_SIZE must be apparently at least 1024 for MMIO.
// There is probably a maximum size per descriptor defined in the kernel.
const QUEUE_SIZE: usize = 1024;
const NUM_QUEUES: usize = 2;

const COMMAND_QUEUE: u16 = 0;
const EVENT_QUEUE: u16 = 1;

const VIRTIO_SCMI_F_P2A_CHANNELS: u16 = 0;

#[derive(Debug, ThisError)]
pub enum VuScmiError {
    #[error("Descriptor not found")]
    DescriptorNotFound,
    #[error("Descriptor read failed")]
    DescriptorReadFailed,
    #[error("Descriptor write failed")]
    DescriptorWriteFailed,
    #[error("Error when configuring device {0}: {1}")]
    DeviceConfigurationError(String, DeviceError),
    #[error("Failed to create new EventFd")]
    EventFdFailed,
    #[error("Failed to handle event, didn't match EPOLLIN")]
    HandleEventNotEpollIn,
    #[error("Failed to handle unknown event")]
    HandleEventUnknownEvent,
    #[error("Isufficient descriptor size, required: {0}, found: {1}")]
    InsufficientDescriptorSize(usize, usize),
    #[error("Failed to send notification")]
    SendNotificationFailed,
    #[error("Invalid descriptor count {0}")]
    UnexpectedDescriptorCount(usize),
    #[error("Invalid descriptor size, expected: {0}, found: {1}")]
    UnexpectedDescriptorSize(usize, usize),
    #[error("Invalid descriptor size, expected at least: {0}, found: {1}")]
    UnexpectedMinimumDescriptorSize(usize, usize),
    #[error("Received unexpected readable descriptor at index {0}")]
    UnexpectedReadableDescriptor(usize),
    #[error("Received unexpected write only descriptor at index {0}")]
    UnexpectedWriteOnlyDescriptor(usize),
    #[error("Unknown device requested: {0}")]
    UnknownDeviceRequested(String),
}

impl From<VuScmiError> for io::Error {
    fn from(e: VuScmiError) -> Self {
        Self::new(io::ErrorKind::Other, e)
    }
}

type Result<T> = std::result::Result<T, VuScmiError>;

type ScmiDescriptorChain = DescriptorChain<GuestMemoryLoadGuard<GuestMemoryMmap<()>>>;

pub struct VuScmiBackend {
    event_idx: bool,
    pub exit_event: EventFd,
    mem: Option<GuestMemoryAtomic<GuestMemoryMmap>>,
    /// Event vring and descriptors serve for asynchronous responses and notifications.
    /// They are obtained from the driver and we store them here for later use.
    /// (We currently don't implement asynchronous responses or notifications but we support
    /// the event queue because the Linux VIRTIO SCMI driver seems to be unhappy if it is not
    /// present. And it doesn't harm to be ready for possible event queue use in future.)
    event_vring: Option<VringRwLock>,
    event_descriptors: Vec<DescriptorChain<GuestMemoryLoadGuard<GuestMemoryMmap>>>,
    /// The abstraction of request handling, with all the needed information stored inside.
    scmi_handler: ScmiHandler,
}

impl VuScmiBackend {
    pub fn new(config: &VuScmiConfig) -> Result<Self> {
        let handler = ScmiHandler::new();
        let device_mapping = available_devices();
        for (name, properties) in config.devices.iter() {
            match device_mapping.get(name.as_str()) {
                Some(specification) => match (specification.constructor)(properties) {
                    Ok(mut device) => {
                        if let Err(error) = device.initialize() {
                            return Result::Err(VuScmiError::DeviceConfigurationError(
                                name.clone(),
                                error,
                            ));
                        }
                        handler.register_device(device);
                    }
                    Err(error) => {
                        return Result::Err(VuScmiError::DeviceConfigurationError(
                            name.clone(),
                            error,
                        ));
                    }
                },
                None => return Result::Err(VuScmiError::UnknownDeviceRequested(name.clone())),
            };
        }
        Ok(Self {
            event_idx: false,
            exit_event: EventFd::new(EFD_NONBLOCK).map_err(|_| VuScmiError::EventFdFailed)?,
            mem: None,
            event_vring: None,
            event_descriptors: vec![],
            scmi_handler: handler,
        })
    }

    pub fn process_requests(
        &self,
        requests: Vec<ScmiDescriptorChain>,
        vring: &VringRwLock,
    ) -> Result<()> {
        if requests.is_empty() {
            return Ok(());
        }

        for desc_chain in requests {
            let descriptors: Vec<_> = desc_chain.clone().collect();
            if descriptors.len() != 2 {
                return Err(VuScmiError::UnexpectedDescriptorCount(descriptors.len()));
            }

            let desc_request = descriptors[0];
            if desc_request.is_write_only() {
                return Err(VuScmiError::UnexpectedWriteOnlyDescriptor(0));
            }

            let read_desc_len: usize = desc_request.len() as usize;
            let header_size = size_of::<MessageHeader>();
            if read_desc_len < header_size {
                return Err(VuScmiError::UnexpectedMinimumDescriptorSize(
                    header_size,
                    read_desc_len,
                ));
            }

            let header = desc_chain
                .memory()
                .read_obj::<MessageHeader>(desc_request.addr())
                .map_err(|_| VuScmiError::DescriptorReadFailed)?;
            let mut scmi_request = ScmiRequest::new(header);
            let n_parameters = self.scmi_handler.number_of_parameters(&scmi_request);
            debug!("SCMI request with n parameters: {:?}", n_parameters);
            let value_size = 4;
            if let Some(expected_parameters) = n_parameters {
                if expected_parameters > 0 {
                    let param_bytes = (expected_parameters as usize) * value_size;
                    let total_size = value_size + param_bytes;
                    if read_desc_len != total_size {
                        return Err(VuScmiError::UnexpectedDescriptorSize(
                            total_size,
                            read_desc_len,
                        ));
                    }
                    let mut buffer: Vec<u8> = vec![0; header_size + param_bytes];
                    desc_chain
                        .memory()
                        .read_slice(&mut buffer, desc_request.addr())
                        .map_err(|_| VuScmiError::DescriptorReadFailed)?;
                    self.scmi_handler
                        .store_parameters(&mut scmi_request, &buffer[header_size..]);
                } else if read_desc_len != value_size {
                    return Err(VuScmiError::UnexpectedDescriptorSize(
                        value_size,
                        read_desc_len,
                    ));
                }
            }

            debug!("Calling SCMI request handler");
            let mut response = self.scmi_handler.handle(scmi_request);
            debug!("SCMI response: {:?}", response);

            let desc_response = descriptors[1];
            if !desc_response.is_write_only() {
                return Err(VuScmiError::UnexpectedReadableDescriptor(1));
            }

            let write_desc_len: usize = desc_response.len() as usize;
            if response.len() > write_desc_len {
                error!(
                    "Response of length {} cannot fit into the descriptor size {}",
                    response.len(),
                    write_desc_len
                );
                response = response.communication_error();
                if response.len() > write_desc_len {
                    return Err(VuScmiError::InsufficientDescriptorSize(
                        response.len(),
                        write_desc_len,
                    ));
                }
            }
            desc_chain
                .memory()
                .write_slice(response.as_slice(), desc_response.addr())
                .map_err(|_| VuScmiError::DescriptorWriteFailed)?;

            if vring
                .add_used(desc_chain.head_index(), response.len() as u32)
                .is_err()
            {
                error!("Couldn't return used descriptors to the ring");
            }
        }
        Ok(())
    }

    fn process_command_queue(&self, vring: &VringRwLock) -> Result<()> {
        debug!("Processing command queue");
        let requests: Vec<_> = vring
            .get_mut()
            .get_queue_mut()
            .iter(self.mem.as_ref().unwrap().memory())
            .map_err(|_| VuScmiError::DescriptorNotFound)?
            .collect();

        debug!("Requests to process: {}", requests.len());
        match self.process_requests(requests, vring) {
            Ok(_) => {
                // Send notification once all the requests are processed
                debug!("Sending processed request notification");
                vring
                    .signal_used_queue()
                    .map_err(|_| VuScmiError::SendNotificationFailed)?;
                debug!("Notification sent");
            }
            Err(err) => {
                warn!("Failed SCMI request: {}", err);
                return Err(err);
            }
        }
        debug!("Processing command queue finished");
        Ok(())
    }

    fn start_event_queue(&mut self, vring: &VringRwLock) {
        if self.event_vring.is_none() {
            self.event_vring = Some(vring.clone());
        }
    }

    pub fn process_event_requests(
        &mut self,
        requests: Vec<ScmiDescriptorChain>,
        _vring: &VringRwLock,
    ) -> Result<()> {
        // The requests here are notifications from the guest about adding
        // fresh buffers for the used ring. The Linux driver allocates 256
        // buffers for the event queue initially (arriving here in several
        // batches) and then adds a free buffer after each message delivered
        // through the event queue.
        for desc_chain in requests {
            let descriptors: Vec<_> = desc_chain.clone().collect();
            debug!(
                "SCMI event request with n descriptors: {}",
                descriptors.len()
            );
            if descriptors.len() != 1 {
                return Err(VuScmiError::UnexpectedDescriptorCount(descriptors.len()));
            }

            let desc = descriptors[0];
            if !desc.is_write_only() {
                return Err(VuScmiError::UnexpectedReadableDescriptor(0));
            }
            debug!("SCMI event request avail descriptor length: {}", desc.len());

            self.event_descriptors.push(desc_chain);
        }
        Ok(())
    }

    fn process_event_queue(&mut self, vring: &VringRwLock) -> Result<()> {
        debug!("Processing event queue");

        let requests: Vec<_> = vring
            .get_mut()
            .get_queue_mut()
            .iter(self.mem.as_ref().unwrap().memory())
            .map_err(|_| VuScmiError::DescriptorNotFound)?
            .collect();
        debug!("Requests to process: {}", requests.len());
        match self.process_event_requests(requests, vring) {
            Ok(_) => {
                // Send notification once all the requests are processed
                debug!("Sending processed request notification");
                vring
                    .signal_used_queue()
                    .map_err(|_| VuScmiError::SendNotificationFailed)?;
                debug!("Notification sent");
            }
            Err(err) => {
                warn!("Failed SCMI request: {}", err);
                return Err(err);
            }
        }
        self.start_event_queue(vring);
        debug!("Processing event queue finished");
        Ok(())
    }
}

/// VhostUserBackend trait methods
impl VhostUserBackendMut for VuScmiBackend {
    type Vring = VringRwLock;
    type Bitmap = ();

    fn num_queues(&self) -> usize {
        debug!("Num queues called");
        NUM_QUEUES
    }

    fn max_queue_size(&self) -> usize {
        debug!("Max queue size called");
        QUEUE_SIZE
    }

    fn features(&self) -> u64 {
        debug!("Features called");
        1 << VIRTIO_F_VERSION_1
            | 1 << VIRTIO_F_NOTIFY_ON_EMPTY
            | 1 << VIRTIO_RING_F_INDIRECT_DESC
            | 1 << VIRTIO_RING_F_EVENT_IDX
            | 1 << VIRTIO_SCMI_F_P2A_CHANNELS
            | VhostUserVirtioFeatures::PROTOCOL_FEATURES.bits()
    }

    fn protocol_features(&self) -> VhostUserProtocolFeatures {
        debug!("Protocol features called");
        VhostUserProtocolFeatures::MQ
    }

    fn set_event_idx(&mut self, enabled: bool) {
        self.event_idx = enabled;
        debug!("Event idx set to: {}", enabled);
    }

    fn update_memory(&mut self, mem: GuestMemoryAtomic<GuestMemoryMmap>) -> IoResult<()> {
        debug!("Update memory called");
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
        debug!("Handle event called");
        if evset != EventSet::IN {
            warn!("Non-input event");
            return Err(VuScmiError::HandleEventNotEpollIn.into());
        }

        match device_event {
            COMMAND_QUEUE => {
                let vring = &vrings[COMMAND_QUEUE as usize];

                if self.event_idx {
                    // vm-virtio's Queue implementation only checks avail_index
                    // once, so to properly support EVENT_IDX we need to keep
                    // calling process_queue() until it stops finding new
                    // requests on the queue.
                    loop {
                        vring.disable_notification().unwrap();
                        self.process_command_queue(vring)?;
                        if !vring.enable_notification().unwrap() {
                            break;
                        }
                    }
                } else {
                    // Without EVENT_IDX, a single call is enough.
                    self.process_command_queue(vring)?;
                }
            }

            EVENT_QUEUE => {
                let vring = &vrings[EVENT_QUEUE as usize];

                if self.event_idx {
                    // vm-virtio's Queue implementation only checks avail_index
                    // once, so to properly support EVENT_IDX we need to keep
                    // calling process_queue() until it stops finding new
                    // requests on the queue.
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
                warn!("unhandled device_event: {}", device_event);
                return Err(VuScmiError::HandleEventUnknownEvent.into());
            }
        }
        debug!("Handle event finished");
        Ok(())
    }

    fn exit_event(&self, _thread_index: usize) -> Option<EventFd> {
        debug!("Exit event called");
        self.exit_event.try_clone().ok()
    }
}

#[cfg(test)]
mod tests {
    use virtio_bindings::virtio_ring::{VRING_DESC_F_NEXT, VRING_DESC_F_WRITE};
    use virtio_queue::{mock::MockSplitQueue, Descriptor, Queue};
    use vm_memory::{Address, GuestAddress, GuestMemoryAtomic, GuestMemoryMmap};

    use super::*;

    fn scmi_header(message_id: u8, protocol_id: u8) -> u32 {
        u32::from(message_id) | u32::from(protocol_id) << 10
    }

    fn build_cmd_desc_chain(
        protocol_id: u8,
        message_id: u8,
        parameters: Vec<u32>,
    ) -> ScmiDescriptorChain {
        let mem = &GuestMemoryMmap::<()>::from_ranges(&[(GuestAddress(0), 0x1000)]).unwrap();
        let vq = MockSplitQueue::new(mem, 16);
        let mut next_addr = vq.desc_table().total_size() + 0x100;
        let mut index = 0;
        let request_size: u32 = (4 + parameters.len() * 4) as u32;

        // Descriptor for the SCMI request
        let desc_request =
            Descriptor::new(next_addr, request_size, VRING_DESC_F_NEXT as u16, index + 1);
        let mut bytes: Vec<u8> = vec![];
        bytes.append(&mut scmi_header(message_id, protocol_id).to_le_bytes().to_vec());
        for p in parameters {
            bytes.append(&mut p.to_le_bytes().to_vec());
        }
        mem.write_slice(bytes.as_slice(), desc_request.addr())
            .unwrap();
        vq.desc_table().store(index, desc_request).unwrap();
        next_addr += u64::from(desc_request.len());
        index += 1;

        // Descriptor for the SCMI response
        let desc_response = Descriptor::new(next_addr, 0x100, VRING_DESC_F_WRITE as u16, 0);
        vq.desc_table().store(index, desc_response).unwrap();

        // Put the descriptor index 0 in the first available ring position.
        mem.write_obj(0u16, vq.avail_addr().unchecked_add(4))
            .unwrap();
        // Set `avail_idx` to 1.
        mem.write_obj(1u16, vq.avail_addr().unchecked_add(2))
            .unwrap();
        // Create descriptor chain from pre-filled memory.
        vq.create_queue::<Queue>()
            .unwrap()
            .iter(GuestMemoryAtomic::new(mem.clone()).memory())
            .unwrap()
            .next()
            .unwrap()
    }

    fn build_event_desc_chain() -> ScmiDescriptorChain {
        let mem = &GuestMemoryMmap::<()>::from_ranges(&[(GuestAddress(0), 0x1000)]).unwrap();
        let vq = MockSplitQueue::new(mem, 16);
        let next_addr = vq.desc_table().total_size() + 0x100;

        // Descriptor for the SCMI event
        let desc_response = Descriptor::new(next_addr, 0x100, VRING_DESC_F_WRITE as u16, 0);
        vq.desc_table().store(0, desc_response).unwrap();

        // Put the descriptor index 0 in the first available ring position.
        mem.write_obj(0u16, vq.avail_addr().unchecked_add(4))
            .unwrap();
        // Set `avail_idx` to 1.
        mem.write_obj(1u16, vq.avail_addr().unchecked_add(2))
            .unwrap();
        // Create descriptor chain from pre-filled memory.
        vq.create_queue::<Queue>()
            .unwrap()
            .iter(GuestMemoryAtomic::new(mem.clone()).memory())
            .unwrap()
            .next()
            .unwrap()
    }

    // Build just empty descriptors
    struct DescParameters {
        addr: Option<u64>,
        flags: u16,
        len: u32,
    }
    fn build_dummy_desc_chain(parameters: Vec<&DescParameters>) -> ScmiDescriptorChain {
        let mem = &GuestMemoryMmap::<()>::from_ranges(&[(GuestAddress(0), 0x1000)]).unwrap();
        let vq = MockSplitQueue::new(mem, 16);

        for (i, p) in parameters.iter().enumerate() {
            let mut f: u16 = if i == parameters.len() - 1 {
                0
            } else {
                VRING_DESC_F_NEXT as u16
            };
            f |= p.flags;
            let offset = match p.addr {
                Some(addr) => addr,
                _ => 0x100,
            };
            let desc = Descriptor::new(offset, p.len, f, (i + 1) as u16);
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

    fn validate_desc_chains(
        desc_chains: &[ScmiDescriptorChain],
        chain_index: usize,
        protocol_id: u8,
        message_id: u8,
        status: i32,
        data: Vec<u32>,
    ) {
        let desc_chain = &desc_chains[chain_index];
        let descriptors: Vec<_> = desc_chain.clone().collect();
        let mut response = vec![0; descriptors[1].len() as usize];

        desc_chain
            .memory()
            .read(&mut response, descriptors[1].addr())
            .unwrap();

        let mut result: Vec<u8> = scmi_header(message_id, protocol_id).to_le_bytes().to_vec();
        result.append(&mut status.to_le_bytes().to_vec());
        for d in &data {
            result.append(&mut d.to_le_bytes().to_vec());
        }
        assert_eq!(response[0..result.len()], result);
    }

    fn make_backend() -> VuScmiBackend {
        let config = VuScmiConfig {
            socket_path: "/foo/scmi.sock".into(),
            devices: vec![],
        };
        VuScmiBackend::new(&config).unwrap()
    }

    #[test]
    fn test_process_requests() {
        let backend = make_backend();
        let mem = GuestMemoryAtomic::new(
            GuestMemoryMmap::<()>::from_ranges(&[(GuestAddress(0), 0x1000)]).unwrap(),
        );
        let vring = VringRwLock::new(mem, 0x1000).unwrap();

        // Descriptor chain size zero, shouldn't fail
        backend
            .process_requests(Vec::<ScmiDescriptorChain>::new(), &vring)
            .unwrap();

        // Valid single SCMI request: base protocol version
        let desc_chains = vec![build_cmd_desc_chain(0x10, 0x0, vec![])];
        backend
            .process_requests(desc_chains.clone(), &vring)
            .unwrap();
        validate_desc_chains(&desc_chains, 0, 0x10, 0x0, 0, vec![0x20000]);

        // Valid multi SCMI request: base protocol version + implementation version
        let desc_chains = vec![
            build_cmd_desc_chain(0x10, 0x0, vec![]),
            build_cmd_desc_chain(0x10, 0x5, vec![]),
        ];
        backend
            .process_requests(desc_chains.clone(), &vring)
            .unwrap();
        validate_desc_chains(&desc_chains, 0, 0x10, 0x0, 0, vec![0x20000]);
        validate_desc_chains(&desc_chains, 1, 0x10, 0x5, 0, vec![0]);
    }

    #[test]
    fn test_process_requests_failure() {
        let backend = make_backend();
        let mem = GuestMemoryAtomic::new(
            GuestMemoryMmap::<()>::from_ranges(&[(GuestAddress(0), 0x1000)]).unwrap(),
        );
        let vring = VringRwLock::new(mem, 0x1000).unwrap();
        let default = DescParameters {
            addr: None,
            flags: 0,
            len: 0,
        };

        // Have only one descriptor, expected two.
        let parameters = vec![&default];
        let desc_chain = build_dummy_desc_chain(parameters);
        match backend
            .process_requests(vec![desc_chain], &vring)
            .unwrap_err()
        {
            VuScmiError::UnexpectedDescriptorCount(1) => (),
            other => panic!("Unexpected result: {:?}", other),
        }

        // Have three descriptors, expected two.
        let parameters = vec![&default, &default, &default];
        let desc_chain = build_dummy_desc_chain(parameters);
        match backend
            .process_requests(vec![desc_chain], &vring)
            .unwrap_err()
        {
            VuScmiError::UnexpectedDescriptorCount(3) => (),
            other => panic!("Unexpected result: {:?}", other),
        }

        // Write only descriptors.
        let p = DescParameters {
            addr: None,
            flags: VRING_DESC_F_WRITE as u16,
            len: 0,
        };
        let parameters = vec![&p, &p];
        let desc_chain = build_dummy_desc_chain(parameters);
        match backend
            .process_requests(vec![desc_chain], &vring)
            .unwrap_err()
        {
            VuScmiError::UnexpectedWriteOnlyDescriptor(0) => (),
            other => panic!("Unexpected result: {:?}", other),
        }

        // Invalid request address.
        let parameters = vec![
            &DescParameters {
                addr: Some(0x10000),
                flags: 0,
                len: 4,
            },
            &DescParameters {
                addr: None,
                flags: VRING_DESC_F_WRITE as u16,
                len: 4,
            },
        ];
        let desc_chain = build_dummy_desc_chain(parameters);
        match backend
            .process_requests(vec![desc_chain], &vring)
            .unwrap_err()
        {
            VuScmiError::DescriptorReadFailed => (),
            other => panic!("Unexpected result: {:?}", other),
        }

        // Invalid request length (very small).
        let parameters = vec![
            &DescParameters {
                addr: None,
                flags: 0,
                len: 2,
            },
            &DescParameters {
                addr: None,
                flags: VRING_DESC_F_WRITE as u16,
                len: 4,
            },
        ];
        let desc_chain = build_dummy_desc_chain(parameters);
        match backend
            .process_requests(vec![desc_chain], &vring)
            .unwrap_err()
        {
            VuScmiError::UnexpectedMinimumDescriptorSize(4, 2) => (),
            other => panic!("Unexpected result: {:?}", other),
        }

        // Invalid request length (too small).
        let desc_chain = build_cmd_desc_chain(0x10, 0x2, vec![]);
        match backend
            .process_requests(vec![desc_chain], &vring)
            .unwrap_err()
        {
            VuScmiError::UnexpectedDescriptorSize(8, 4) => (),
            other => panic!("Unexpected result: {:?}", other),
        }

        // Invalid request length (too large).
        let desc_chain = build_cmd_desc_chain(0x10, 0x0, vec![0]);
        match backend
            .process_requests(vec![desc_chain], &vring)
            .unwrap_err()
        {
            VuScmiError::UnexpectedDescriptorSize(4, 8) => (),
            other => panic!("Unexpected result: {:?}", other),
        }

        // Read only descriptors.
        let p = DescParameters {
            addr: None,
            flags: 0,
            len: 4,
        };
        let parameters = vec![&p, &p];
        let desc_chain = build_dummy_desc_chain(parameters);
        match backend
            .process_requests(vec![desc_chain], &vring)
            .unwrap_err()
        {
            VuScmiError::UnexpectedReadableDescriptor(1) => (),
            other => panic!("Unexpected result: {:?}", other),
        }

        // Invalid response address.
        let parameters = vec![
            &DescParameters {
                addr: None,
                flags: 0,
                len: 4,
            },
            &DescParameters {
                addr: Some(0x10000),
                flags: VRING_DESC_F_WRITE as u16,
                len: 8,
            },
        ];
        let desc_chain = build_dummy_desc_chain(parameters);
        match backend
            .process_requests(vec![desc_chain], &vring)
            .unwrap_err()
        {
            VuScmiError::DescriptorWriteFailed => (),
            other => panic!("Unexpected result: {:?}", other),
        }

        // Invalid response length.
        let parameters = vec![
            &DescParameters {
                addr: None,
                flags: 0,
                len: 4,
            },
            &DescParameters {
                addr: None,
                flags: VRING_DESC_F_WRITE as u16,
                len: 6,
            },
        ];
        let desc_chain = build_dummy_desc_chain(parameters);
        match backend
            .process_requests(vec![desc_chain], &vring)
            .unwrap_err()
        {
            VuScmiError::InsufficientDescriptorSize(8, 6) => (),
            other => panic!("Unexpected result: {:?}", other),
        }
    }

    #[test]
    fn test_event_requests() {
        let mut backend = make_backend();
        let mem = GuestMemoryAtomic::new(
            GuestMemoryMmap::<()>::from_ranges(&[(GuestAddress(0), 0x1000)]).unwrap(),
        );
        let vring = VringRwLock::new(mem, 0x1000).unwrap();

        // Descriptor chain size zero, shouldn't fail and should be no-op
        backend
            .process_event_requests(Vec::<ScmiDescriptorChain>::new(), &vring)
            .unwrap();
        assert_eq!(backend.event_descriptors.len(), 0);

        // Valid event descriptors, should get stored
        let desc_chains = vec![build_event_desc_chain(), build_event_desc_chain()];
        backend.process_event_requests(desc_chains, &vring).unwrap();
        assert_eq!(backend.event_descriptors.len(), 2);

        // Some more event descriptors
        let desc_chains = vec![
            build_event_desc_chain(),
            build_event_desc_chain(),
            build_event_desc_chain(),
        ];
        backend.process_event_requests(desc_chains, &vring).unwrap();
        assert_eq!(backend.event_descriptors.len(), 5);
    }

    #[test]
    fn test_event_requests_failure() {
        let mut backend = make_backend();
        let mem = GuestMemoryAtomic::new(
            GuestMemoryMmap::<()>::from_ranges(&[(GuestAddress(0), 0x1000)]).unwrap(),
        );
        let vring = VringRwLock::new(mem, 0x1000).unwrap();

        // Invalid number of desc chains
        let p = DescParameters {
            addr: None,
            flags: 0,
            len: 0,
        };
        let desc_chain = build_dummy_desc_chain(vec![&p, &p]);
        match backend
            .process_event_requests(vec![desc_chain], &vring)
            .unwrap_err()
        {
            VuScmiError::UnexpectedDescriptorCount(2) => (),
            other => panic!("Unexpected result: {:?}", other),
        }

        // Read only descriptor
        let p = DescParameters {
            addr: None,
            flags: 0,
            len: 0,
        };
        let desc_chain = build_dummy_desc_chain(vec![&p]);
        match backend
            .process_event_requests(vec![desc_chain], &vring)
            .unwrap_err()
        {
            VuScmiError::UnexpectedReadableDescriptor(0) => (),
            other => panic!("Unexpected result: {:?}", other),
        }
    }

    #[test]
    fn test_backend() {
        let mut backend = make_backend();

        assert_eq!(backend.num_queues(), NUM_QUEUES);
        assert_eq!(backend.max_queue_size(), QUEUE_SIZE);
        assert_eq!(backend.features(), 0x171000001);
        assert_eq!(backend.protocol_features(), VhostUserProtocolFeatures::MQ);

        assert_eq!(backend.queues_per_thread(), vec![0xffff_ffff]);

        backend.set_event_idx(true);
        assert!(backend.event_idx);

        assert!(backend.exit_event(0).is_some());

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
