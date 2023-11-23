// VIRTIO Input Emulation via vhost-user
//
// Copyright 2023 Linaro Ltd. All Rights Reserved.
// Leo Yan <leo.yan@linaro.org>
//
// SPDX-License-Identifier: Apache-2.0 or BSD-3-Clause

use log::error;
use nix::libc;
use std::collections::VecDeque;
use std::io::{self, Result as IoResult};
use thiserror::Error as ThisError;

use vhost::vhost_user::message::{VhostUserProtocolFeatures, VhostUserVirtioFeatures};
use vhost_user_backend::{VhostUserBackendMut, VringRwLock, VringT};
use virtio_bindings::bindings::virtio_config::VIRTIO_F_VERSION_1;
use virtio_bindings::bindings::virtio_ring::{
    VIRTIO_RING_F_EVENT_IDX, VIRTIO_RING_F_INDIRECT_DESC,
};
use virtio_queue::QueueT;
use vm_memory::{ByteValued, Bytes, GuestAddressSpace, GuestMemoryAtomic, GuestMemoryMmap};
use vmm_sys_util::epoll::EventSet;
use vmm_sys_util::eventfd::{EventFd, EFD_NONBLOCK};

use crate::input::*;

pub const EVENT_ID_IN_VRING_EPOLL: u64 = 3;

const QUEUE_SIZE: usize = 1024;
const NUM_QUEUES: usize = 2;

const VIRTIO_INPUT_CFG_ID_NAME: u8 = 0x01;
const VIRTIO_INPUT_CFG_ID_DEVIDS: u8 = 0x03;
const VIRTIO_INPUT_CFG_EV_BITS: u8 = 0x11;
const VIRTIO_INPUT_CFG_SIZE: usize = 128;

const EV_SYN: u8 = 0x00;
const EV_KEY: u8 = 0x01;
const EV_REL: u8 = 0x02;
const EV_ABS: u8 = 0x03;
const EV_MSC: u8 = 0x04;
const EV_SW: u8 = 0x05;

const SYN_REPORT: u8 = 0x00;

#[repr(C, packed)]
#[derive(Copy, Clone, Debug)]
pub(crate) struct VuInputConfig {
    select: u8,
    subsel: u8,
    size: u8,
    reserved: [u8; 5],
    val: [u8; VIRTIO_INPUT_CFG_SIZE],
}

// If deriving the 'Default' trait, an array is limited with a maximum size of 32 bytes,
// thus it cannot meet the length VIRTIO_INPUT_CFG_SIZE (128) for the 'val' array.
// Implement Default trait to accommodate array 'val'.
impl Default for VuInputConfig {
    fn default() -> VuInputConfig {
        VuInputConfig {
            select: 0,
            subsel: 0,
            size: 0,
            reserved: [0; 5],
            val: [0; VIRTIO_INPUT_CFG_SIZE],
        }
    }
}

// SAFETY: The layout of the structure is fixed and can be initialized by
// reading its content from byte array.
unsafe impl ByteValued for VuInputConfig {}

#[repr(C, packed)]
#[derive(Copy, Clone, Debug, Default)]
pub(crate) struct VuInputEvent {
    ev_type: u16,
    code: u16,
    value: u32,
}

// SAFETY: The layout of the structure is fixed and can be initialized by
// reading its content from byte array.
unsafe impl ByteValued for VuInputEvent {}

#[derive(Debug, Eq, PartialEq, ThisError)]
/// Errors related to vhost-device-input daemon.
pub(crate) enum VuInputError {
    #[error("Notification send failed")]
    SendNotificationFailed,
    #[error("Can't create eventFd")]
    EventFdError,
    #[error("Failed to handle event")]
    HandleEventNotEpollIn,
    #[error("Unknown device event")]
    HandleEventUnknownEvent,
    #[error("Unknown config request: {0}")]
    UnexpectedConfig(u8),
    #[error("Failed to fetch event")]
    UnexpectedFetchEventError,
    #[error("Too many descriptors: {0}")]
    UnexpectedDescriptorCount(usize),
    #[error("Failed to read from the input device")]
    UnexpectedInputDeviceError,
    #[error("Failed to write descriptor to vring")]
    UnexpectedWriteDescriptorError,
    #[error("Failed to write event to vring")]
    UnexpectedWriteVringError,
}

type Result<T> = std::result::Result<T, VuInputError>;

impl From<VuInputError> for io::Error {
    fn from(e: VuInputError) -> Self {
        Self::new(io::ErrorKind::Other, e)
    }
}

pub(crate) struct VuInputBackend<T: InputDevice> {
    event_idx: bool,
    ev_dev: T,
    pub exit_event: EventFd,
    select: u8,
    subsel: u8,
    mem: Option<GuestMemoryAtomic<GuestMemoryMmap>>,
    ev_list: VecDeque<VuInputEvent>,
}

impl<T: InputDevice> VuInputBackend<T> {
    pub fn new(ev_dev: T) -> std::result::Result<Self, std::io::Error> {
        Ok(VuInputBackend {
            event_idx: false,
            ev_dev,
            exit_event: EventFd::new(EFD_NONBLOCK).map_err(|_| VuInputError::EventFdError)?,
            select: 0,
            subsel: 0,
            mem: None,
            ev_list: VecDeque::new(),
        })
    }

    fn process_event(&mut self, vring: &VringRwLock) -> Result<bool> {
        let last_sync_index = self
            .ev_list
            .iter()
            .rposition(|event| event.ev_type == EV_SYN as u16 && event.code == SYN_REPORT as u16)
            .unwrap_or(0);

        if last_sync_index == 0 {
            log::warn!("No available events on the list!");
            return Ok(true);
        }

        let mut index = 0;
        while index <= last_sync_index {
            let event = self.ev_list.get(index).unwrap();
            index += 1;

            let mem = self.mem.as_ref().unwrap().memory();

            let desc = vring
                .get_mut()
                .get_queue_mut()
                .pop_descriptor_chain(mem.clone());

            if let Some(desc_chain) = desc {
                let descriptors: Vec<_> = desc_chain.clone().collect();
                if descriptors.len() != 1 {
                    return Err(VuInputError::UnexpectedDescriptorCount(descriptors.len()));
                }
                let descriptor = descriptors[0];

                desc_chain
                    .memory()
                    .write_obj(*event, descriptor.addr())
                    .map_err(|_| VuInputError::UnexpectedWriteDescriptorError)?;

                if vring
                    .add_used(desc_chain.head_index(), event.as_slice().len() as u32)
                    .is_err()
                {
                    log::error!("Couldn't write event data to the ring");
                    return Err(VuInputError::UnexpectedWriteVringError);
                }
            } else {
                // Now cannot get available descriptor, which means the host cannot process
                // event data in time and overrun happens in the backend. In this case,
                // we simply drop the incomping input event and notify guest for handling
                // events. At the end, it returns Ok(false) so can avoid exiting the thread loop.
                self.ev_list.clear();

                vring
                    .signal_used_queue()
                    .map_err(|_| VuInputError::SendNotificationFailed)?;

                return Ok(false);
            }
        }

        // Sent the events [0..last_sync_index] to vring and remove them from the list.
        // The range end parameter is an exclusive value, so use 'last_sync_index + 1'.
        self.ev_list.drain(0..last_sync_index + 1);
        Ok(true)
    }

    /// Process the requests in the vring and dispatch replies
    fn process_queue(&mut self, vring: &VringRwLock) -> Result<bool> {
        let events = self
            .ev_dev
            .fetch_events()
            .map_err(|_| VuInputError::UnexpectedFetchEventError)?;

        for event in events {
            let ev_raw_data = VuInputEvent {
                ev_type: event.event_type().0,
                code: event.code(),
                value: event.value() as u32,
            };
            self.ev_list.push_back(ev_raw_data);
        }

        self.process_event(vring)?;

        vring
            .signal_used_queue()
            .map_err(|_| VuInputError::SendNotificationFailed)?;

        Ok(true)
    }

    pub fn read_event_config(&self) -> Result<VuInputConfig> {
        let mut cfg: [u8; VIRTIO_INPUT_CFG_SIZE] = [0; VIRTIO_INPUT_CFG_SIZE];

        let func: unsafe fn(nix::libc::c_int, &mut [u8]) -> nix::Result<libc::c_int> =
            match self.subsel {
                EV_KEY => eviocgbit_key,
                EV_ABS => eviocgbit_absolute,
                EV_REL => eviocgbit_relative,
                EV_MSC => eviocgbit_misc,
                EV_SW => eviocgbit_switch,
                _ => {
                    return Err(VuInputError::HandleEventUnknownEvent);
                }
            };

        // SAFETY: Safe as the file is a valid event device, the kernel will only
        // update the correct amount of memory in func.
        if unsafe { func(self.ev_dev.get_raw_fd(), &mut cfg) }.is_err() {
            return Err(VuInputError::UnexpectedInputDeviceError);
        }

        let mut size: u8 = 0;
        for (index, val) in cfg.iter().enumerate() {
            if *val != 0 {
                size = (index + 1) as u8;
            }
        }

        Ok(VuInputConfig {
            select: self.select,
            subsel: self.subsel,
            size,
            reserved: [0; 5],
            val: cfg,
        })
    }

    pub fn read_name_config(&self) -> Result<VuInputConfig> {
        let mut name: [u8; VIRTIO_INPUT_CFG_SIZE] = [0; VIRTIO_INPUT_CFG_SIZE];

        // SAFETY: Safe as the file is a valid event device, the kernel will only
        // update the correct amount of memory in func.
        match unsafe { eviocgname(self.ev_dev.get_raw_fd(), name.as_mut_slice()) } {
            Ok(len) if len as usize > name.len() => {
                return Err(VuInputError::UnexpectedInputDeviceError);
            }
            Ok(len) if len <= 1 => {
                return Err(VuInputError::UnexpectedInputDeviceError);
            }
            Err(_) => {
                return Err(VuInputError::UnexpectedInputDeviceError);
            }
            _ => (),
        }

        let size = String::from_utf8(name.to_vec()).unwrap().len();

        Ok(VuInputConfig {
            select: self.select,
            subsel: 0,
            size: size as u8,
            reserved: [0; 5],
            val: name,
        })
    }

    pub fn read_id_config(&self) -> Result<VuInputConfig> {
        let input_id = self.ev_dev.input_id();

        let mut dev_id = [
            input_id.bus_type().0.as_slice(),
            input_id.vendor().as_slice(),
            input_id.product().as_slice(),
            input_id.version().as_slice(),
        ]
        .concat();

        dev_id.resize(VIRTIO_INPUT_CFG_SIZE, 0);

        Ok(VuInputConfig {
            select: VIRTIO_INPUT_CFG_ID_DEVIDS,
            subsel: 0,
            size: VIRTIO_INPUT_CFG_SIZE as u8,
            reserved: [0; 5],
            val: dev_id.try_into().unwrap(),
        })
    }
}

/// VhostUserBackend trait methods
impl<T: 'static + InputDevice + Sync + Send> VhostUserBackendMut for VuInputBackend<T> {
    type Bitmap = ();
    type Vring = VringRwLock;

    fn num_queues(&self) -> usize {
        NUM_QUEUES
    }

    fn max_queue_size(&self) -> usize {
        QUEUE_SIZE
    }

    fn features(&self) -> u64 {
        1 << VIRTIO_F_VERSION_1
            | 1 << VIRTIO_RING_F_INDIRECT_DESC
            | 1 << VIRTIO_RING_F_EVENT_IDX
            | VhostUserVirtioFeatures::PROTOCOL_FEATURES.bits()
    }

    fn protocol_features(&self) -> VhostUserProtocolFeatures {
        VhostUserProtocolFeatures::MQ | VhostUserProtocolFeatures::CONFIG
    }

    fn get_config(&self, offset: u32, size: u32) -> Vec<u8> {
        let cfg = match self.select {
            VIRTIO_INPUT_CFG_ID_NAME => self.read_name_config(),
            VIRTIO_INPUT_CFG_ID_DEVIDS => self.read_id_config(),
            VIRTIO_INPUT_CFG_EV_BITS => self.read_event_config(),
            _ => Err(VuInputError::UnexpectedConfig(self.select)),
        };

        let val = match cfg {
            Ok(v) => v.as_slice().to_vec(),
            _ => vec![0; size as usize],
        };

        let mut result: Vec<_> = val
            .as_slice()
            .iter()
            .skip(offset as usize)
            .take(size as usize)
            .copied()
            .collect();
        // pad with 0s up to `size`
        result.resize(size as usize, 0);
        result
    }

    // In virtio spec https://docs.oasis-open.org/virtio/virtio/v1.2/cs01/virtio-v1.2-cs01.pdf,
    // section "5.8.5.1 Driver Requirements: Device Initialization", it doesn't mention to
    // use 'offset' argument, so set it as unused.
    fn set_config(&mut self, _offset: u32, buf: &[u8]) -> io::Result<()> {
        self.select = buf[0];
        self.subsel = buf[1];

        Ok(())
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
        if !self.event_idx {
            self.ev_dev.fetch_events()?;
            return Ok(());
        }

        if evset != EventSet::IN {
            return Err(VuInputError::HandleEventNotEpollIn.into());
        }

        if device_event == EVENT_ID_IN_VRING_EPOLL as u16 {
            let vring = &vrings[0];

            if self.event_idx {
                vring.disable_notification().unwrap();
                self.process_queue(vring)?;
                vring.enable_notification().unwrap();
            } else {
                // Without EVENT_IDX, a single call is enough.
                self.process_queue(vring)?;
            }
        }

        Ok(())
    }

    fn exit_event(&self, _thread_index: usize) -> Option<EventFd> {
        self.exit_event.try_clone().ok()
    }
}
