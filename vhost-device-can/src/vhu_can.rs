// vhost device can
//
// Copyright 2023-2024 VIRTUAL OPEN SYSTEMS SAS. All Rights Reserved.
//          Timos Ampelikiotis <t.ampelikiotis@virtualopensystems.com>
//
// SPDX-License-Identifier: Apache-2.0 or BSD-3-Clause

use crate::can::CanController;
use crate::can::Error::QueueEmpty;
use crate::virtio_can::{
    VirtioCanCtrlRequest, VirtioCanFrame, VirtioCanHeader, CANFD_VALID_LENGTHS, CAN_CS_STARTED,
    CAN_CS_STOPPED, CAN_EFF_FLAG, CAN_EFF_MASK, CAN_ERR_BUSOFF, CAN_ERR_FLAG, CAN_FRMF_TYPE_FD,
    CAN_RTR_FLAG, CAN_SFF_MASK, VIRTIO_CAN_FLAGS_EXTENDED, VIRTIO_CAN_FLAGS_FD,
    VIRTIO_CAN_FLAGS_RTR, VIRTIO_CAN_FLAGS_VALID_MASK, VIRTIO_CAN_F_CAN_CLASSIC,
    VIRTIO_CAN_F_CAN_FD, VIRTIO_CAN_F_RTR_FRAMES, VIRTIO_CAN_RESULT_NOT_OK, VIRTIO_CAN_RESULT_OK,
    VIRTIO_CAN_RX, VIRTIO_CAN_SET_CTRL_MODE_START, VIRTIO_CAN_SET_CTRL_MODE_STOP,
    VIRTIO_CAN_S_CTRL_BUSOFF, VIRTIO_CAN_TX,
};
use log::{error, trace, warn};
use std::os::fd::AsRawFd;
use std::slice::from_raw_parts;
use std::sync::{Arc, RwLock};
use std::{
    convert,
    io::{self, Result as IoResult},
};
use thiserror::Error as ThisError;
use vhost::vhost_user::message::{VhostUserProtocolFeatures, VhostUserVirtioFeatures};
use vhost_user_backend::VringEpollHandler;
use vhost_user_backend::{VhostUserBackendMut, VringRwLock, VringT};
use virtio_bindings::bindings::virtio_config::{VIRTIO_F_NOTIFY_ON_EMPTY, VIRTIO_F_VERSION_1};
use virtio_bindings::bindings::virtio_ring::{
    VIRTIO_RING_F_EVENT_IDX, VIRTIO_RING_F_INDIRECT_DESC,
};
use virtio_queue::{DescriptorChain, QueueOwnedT};
use vm_memory::{
    ByteValued, GuestAddressSpace, GuestMemoryAtomic, GuestMemoryLoadGuard, GuestMemoryMmap,
};
use vmm_sys_util::epoll::EventSet;
use vmm_sys_util::eventfd::{EventFd, EFD_NONBLOCK};

/// Virtio configuration
const QUEUE_SIZE: usize = 64;
const NUM_QUEUES: usize = 3;

/// Queues
const TX_QUEUE: u16 = 0;
const RX_QUEUE: u16 = 1;
const CTRL_QUEUE: u16 = 2;
const BACKEND_EFD: u16 = (NUM_QUEUES + 1) as u16;

type Result<T> = std::result::Result<T, Error>;

#[derive(Copy, Clone, Debug, PartialEq, ThisError)]
/// Errors related to vhost-device-can-daemon.
pub(crate) enum Error {
    #[error("Failed to handle event, didn't match EPOLLIN")]
    HandleEventNotEpollIn,
    #[error("Failed to handle unknown event")]
    HandleEventUnknown,
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
    #[error("Unknown can message type: {0}")]
    UnexpectedCanMsgType(u16),
    #[error("RTR frames not negotiated")]
    UnexpectedRtrFlag,
    #[error("Can FD frames not negotiated")]
    UnexpectedFdFlag,
    #[error("Unexpected CAN ID bigger than: {0} bits")]
    UnexpectedCanId(u16),
    #[error("Invalid CAN flags: {0}")]
    InvalidCanFlags(u32),
    #[error("Invalid CAN[FD] length: {0}")]
    InvalidCanLength(u32),
    #[error("Classic CAN frames not negotiated")]
    UnexpectedClassicFlag,
    #[error("Bus off error received")]
    BusoffRxFrame,
    #[error("Rx CAN frame has unknown error")]
    RxFrameUnknownFail,
}

impl convert::From<Error> for io::Error {
    fn from(e: Error) -> Self {
        io::Error::new(io::ErrorKind::Other, e)
    }
}

pub(crate) struct VhostUserCanBackend {
    controller: Arc<RwLock<CanController>>,
    acked_features: u64,
    event_idx: bool,
    pub(crate) exit_event: EventFd,
    mem: Option<GuestMemoryAtomic<GuestMemoryMmap>>,
}

type CanDescriptorChain = DescriptorChain<GuestMemoryLoadGuard<GuestMemoryMmap<()>>>;

impl VhostUserCanBackend {
    pub(crate) fn new(controller: Arc<RwLock<CanController>>) -> Result<Self> {
        Ok(VhostUserCanBackend {
            controller,
            event_idx: false,
            acked_features: 0x0,
            exit_event: EventFd::new(EFD_NONBLOCK).map_err(|_| Error::EventFdFailed)?,
            mem: None,
        })
    }

    fn check_features(&self, features: u16) -> bool {
        (self.acked_features & (1 << features)) != 0
    }

    fn check_tx_frame(&self, request: VirtioCanFrame) -> Result<VirtioCanFrame> {
        let msg_type = request.msg_type.to_native();
        let mut can_id = request.can_id.to_native();
        let length = request.length.to_native();
        let mut flags = 0;

        if msg_type != VIRTIO_CAN_TX {
            warn!("TX: Message type 0x{:x} unknown\n", msg_type);
            return Err(Error::UnexpectedCanMsgType(msg_type));
        }

        // Check for undefined bits in frame's flags
        let invalid_can_flags: u32 = request.flags.to_native() & !VIRTIO_CAN_FLAGS_VALID_MASK;
        if invalid_can_flags != 0 {
            return Err(Error::InvalidCanFlags(invalid_can_flags));
        }

        // If VIRTIO_CAN_FLAGS_EXTENDED has negotiated then use extended CAN ID
        if (request.flags.to_native() & VIRTIO_CAN_FLAGS_EXTENDED) != 0 {
            // If we have a extended frame there is no way to check if
            // can_id > 29 bits. The reason is that bit 29, 30, 31 are
            // dedicated to CAN specific flags (EFF, RTR, ERR).
            if can_id > CAN_EFF_MASK {
                return Err(Error::UnexpectedCanId(29_u16));
            }
            can_id |= CAN_EFF_FLAG;
        } else {
            // If we have a standard frame and can_id > 11 bits then fail
            if can_id > CAN_SFF_MASK {
                return Err(Error::UnexpectedCanId(11_u16));
            }
        }

        // Remote transfer request is used only with classic CAN
        if (request.flags.to_native() & VIRTIO_CAN_FLAGS_RTR) != 0 {
            if !self.check_features(VIRTIO_CAN_F_CAN_CLASSIC)
                || !self.check_features(VIRTIO_CAN_F_RTR_FRAMES)
            {
                warn!("TX: RTR frames not negotiated");
                return Err(Error::UnexpectedRtrFlag);
            }
            can_id |= CAN_RTR_FLAG;
        }

        // One of VIRTIO_CAN_F_CAN_CLASSIC and VIRTIO_CAN_F_CAN_FD must be negotiated
        // Check if VIRTIO_CAN_F_CAN_FD is negotiated when the frame is CANFD
        if (request.flags.to_native() & VIRTIO_CAN_FLAGS_FD) != 0 {
            if !self.check_features(VIRTIO_CAN_F_CAN_FD) {
                warn!("TX: FD frames not negotiated\n");
                return Err(Error::UnexpectedFdFlag);
            }
            flags = CAN_FRMF_TYPE_FD;
        } else {
            // Check if VIRTIO_CAN_F_CAN_CLASSIC is negotiated when the frame is CAN
            if !self.check_features(VIRTIO_CAN_F_CAN_CLASSIC) {
                warn!("TX: Classic frames not negotiated\n");
                return Err(Error::UnexpectedClassicFlag);
            }
        }

        // Check if CAN/FD length is out-of-range (based on negotiated features)
        if (request.flags.to_native() & VIRTIO_CAN_FLAGS_FD) != 0 {
            if length > 8 && !CANFD_VALID_LENGTHS.contains(&length.into()) {
                return Err(Error::InvalidCanLength(length.into()));
            }
        } else if length > 8 {
            return Err(Error::InvalidCanLength(length.into()));
        }

        Ok(VirtioCanFrame {
            msg_type: msg_type.into(),
            can_id: can_id.into(),
            length: length.into(),
            reserved: 0.into(),
            flags: flags.into(),
            sdu: request.sdu[0..64].try_into().unwrap(),
        })
    }

    fn check_rx_frame(&self, response: VirtioCanFrame) -> Result<VirtioCanFrame> {
        CanController::print_can_frame(response);

        let mut can_rx = VirtioCanFrame {
            msg_type: VIRTIO_CAN_RX.into(),
            can_id: response.can_id,
            length: response.length,
            reserved: 0.into(),
            flags: response.flags,
            sdu: [0; 64],
        };
        let res_len = response.length.to_native();
        let res_can_id = response.can_id.to_native();
        let mut res_flags = response.flags.to_native();

        // If we receive an error message check if that's a busoff.
        // If no just drop the message, otherwise update config and return.
        if (res_can_id & CAN_ERR_FLAG) != 0 {
            if (res_can_id & CAN_ERR_BUSOFF) != 0 {
                // TODO: Trigger a config_change notification
                self.controller.write().unwrap().config.status = VIRTIO_CAN_S_CTRL_BUSOFF.into();
                self.controller.write().unwrap().ctrl_state = CAN_CS_STOPPED;
                warn!("Got BusOff error frame, device does a local bus off\n");
                return Err(Error::BusoffRxFrame);
            } else {
                trace!("Dropping error frame 0x{:x}\n", response.can_id.to_native());
                return Err(Error::RxFrameUnknownFail);
            }
        }

        // One of VIRTIO_CAN_F_CAN_CLASSIC and VIRTIO_CAN_F_CAN_FD must be negotiated
        if (res_flags & CAN_FRMF_TYPE_FD) != 0 {
            if !self.check_features(VIRTIO_CAN_F_CAN_FD) {
                warn!("Drop non-supported CAN FD frame");
                return Err(Error::UnexpectedFdFlag);
            }
        } else if !self.check_features(VIRTIO_CAN_F_CAN_CLASSIC) {
            warn!("Drop non-supported CAN classic frame");
            return Err(Error::UnexpectedClassicFlag);
        }

        // Add VIRTIO_CAN_FLAGS_EXTENDED in flag if the received frame
        // had an extended CAN ID.
        // Based on virtio-spec v1.4, the 3 MSB of can_id should be set to 0.
        if (res_can_id & CAN_EFF_FLAG) != 0 {
            can_rx.flags = VIRTIO_CAN_FLAGS_EXTENDED.into();
            can_rx.can_id = (res_can_id & CAN_EFF_MASK).into();
        } else {
            can_rx.flags = 0.into();
            can_rx.can_id = (res_can_id & CAN_SFF_MASK).into();
        }

        // Remote transfer request is used only with classic CAN
        if (res_can_id & CAN_RTR_FLAG) != 0 {
            if !self.check_features(VIRTIO_CAN_F_RTR_FRAMES)
                || !self.check_features(VIRTIO_CAN_F_CAN_CLASSIC)
            {
                warn!("Drop non-supported RTR frame");
                return Err(Error::UnexpectedRtrFlag);
            }
            // If remote transfer request is enabled add the according flag
            can_rx.flags = (can_rx.flags.to_native() | VIRTIO_CAN_FLAGS_RTR).into();
        }

        // Treat Vcan interface as CANFD if MTU is set to 64 bytes.
        //
        // Vcan can not be configured as CANFD interface, but it is
        // possible to configure its MTU to 64 bytes. So if a messages
        // bigger than 8 bytes is being received we consider it as
        // CANFD message.
        let can_name = self.controller.read().unwrap().can_name.clone();
        if self.check_features(VIRTIO_CAN_F_CAN_FD) && res_len > 8 && can_name == "vcan0" {
            res_flags |= CAN_FRMF_TYPE_FD;
            warn!("\n\n\nCANFD VCAN0\n\n");
        }

        // Check if CAN/FD length is out-of-range (based on negotiated features)
        if (res_flags & CAN_FRMF_TYPE_FD) != 0 {
            if res_len > 8 && !CANFD_VALID_LENGTHS.contains(&res_len.into()) {
                return Err(Error::InvalidCanLength(res_len.into()));
            }
            can_rx.flags = (can_rx.flags.to_native() | VIRTIO_CAN_FLAGS_FD).into();
        } else if res_len > 8 {
            return Err(Error::InvalidCanLength(res_len.into()));
        }

        can_rx.sdu.copy_from_slice(&response.sdu[0..64]);
        CanController::print_can_frame(can_rx);

        Ok(can_rx)
    }

    fn process_ctrl_requests(
        &self,
        requests: Vec<CanDescriptorChain>,
        vring: &VringRwLock,
    ) -> Result<bool> {
        if requests.is_empty() {
            return Ok(true);
        }

        for desc_chain in requests {
            let atomic_mem = self.mem.as_ref().unwrap().memory();

            let mut reader = desc_chain
                .clone()
                .reader(&atomic_mem)
                .map_err(|_| Error::DescriptorReadFailed)?;

            let mut writer = desc_chain
                .clone()
                .writer(&atomic_mem)
                .map_err(|_| Error::DescriptorWriteFailed)?;

            let request = reader
                .read_obj::<VirtioCanCtrlRequest>()
                .map_err(|_| Error::DescriptorReadFailed)?;

            // This implementation requires the CAN devices to be already in UP state
            // before starting. This code does not trigger state changes [UP/DOWN] of
            // the host CAN devices.
            let response = match request.msg_type.into() {
                VIRTIO_CAN_SET_CTRL_MODE_START => {
                    if self.controller.write().unwrap().ctrl_state == CAN_CS_STARTED {
                        VIRTIO_CAN_RESULT_NOT_OK
                    } else {
                        // TODO: Trigger a config_change notification (optional)
                        self.controller.write().unwrap().config.status = 0.into();
                        self.controller.write().unwrap().ctrl_state = CAN_CS_STARTED;
                        VIRTIO_CAN_RESULT_OK
                    }
                }
                VIRTIO_CAN_SET_CTRL_MODE_STOP => {
                    if self.controller.write().unwrap().ctrl_state == CAN_CS_STOPPED {
                        VIRTIO_CAN_RESULT_NOT_OK
                    } else {
                        // TODO: Trigger a config_change notification (optional)
                        self.controller.write().unwrap().config.status = 0.into();
                        self.controller.write().unwrap().ctrl_state = CAN_CS_STOPPED;
                        VIRTIO_CAN_RESULT_OK
                    }
                }
                _ => {
                    trace!("Ctrl queue: msg type 0x{:?} unknown", request.msg_type);
                    VIRTIO_CAN_RESULT_NOT_OK
                }
            };

            writer
                .write_obj(response)
                .map_err(|_| Error::DescriptorWriteFailed)?;

            if vring
                .add_used(desc_chain.head_index(), writer.bytes_written() as u32)
                .is_err()
            {
                warn!("Couldn't return used descriptors to the ring");
            }
        }

        Ok(true)
    }

    fn process_tx_requests(
        &self,
        requests: Vec<CanDescriptorChain>,
        vring: &VringRwLock,
    ) -> Result<bool> {
        if requests.is_empty() {
            return Ok(true);
        }

        for desc_chain in requests {
            let atomic_mem = self.mem.as_ref().unwrap().memory();

            let mut reader = desc_chain
                .clone()
                .reader(&atomic_mem)
                .map_err(|_| Error::DescriptorReadFailed)?;

            let mut writer = desc_chain
                .clone()
                .writer(&atomic_mem)
                .map_err(|_| Error::DescriptorWriteFailed)?;

            let request_header = reader
                .read_obj::<VirtioCanHeader>()
                .map_err(|_| Error::DescriptorReadFailed)?;

            let data_len = request_header.length.to_native() as usize;
            let mut request_data: Vec<u8> = Vec::new();
            for _i in 0..data_len {
                let data_byte = reader
                    .read_obj::<u8>()
                    .map_err(|_| Error::DescriptorReadFailed)?;
                request_data.push(data_byte);
            }

            let request = VirtioCanFrame {
                msg_type: request_header.msg_type,
                can_id: request_header.can_id,
                length: request_header.length,
                reserved: request_header.reserved,
                flags: request_header.flags,
                sdu: {
                    let mut sdu_data: [u8; 64] = [0; 64];
                    sdu_data[..request_header.length.to_native() as usize]
                        .copy_from_slice(request_data.as_slice());
                    sdu_data
                },
            };
            CanController::print_can_frame(request);

            let response = if self.controller.read().unwrap().ctrl_state == CAN_CS_STOPPED {
                trace!("Device is stopped!");
                VIRTIO_CAN_RESULT_NOT_OK
            } else {
                let _response = match self.check_tx_frame(request) {
                    Ok(frame) => {
                        CanController::print_can_frame(frame);

                        // If the VIRTIO_CAN_F_CAN_LATE_TX_ACK is negotiated sent the
                        // frame and wait for it to be sent.
                        // TODO: Otherwise send it asynchronously.
                        match self.controller.write().unwrap().can_out(frame) {
                            Ok(_) => VIRTIO_CAN_RESULT_OK,
                            Err(_) => {
                                warn!("we got an error from controller send func");
                                VIRTIO_CAN_RESULT_NOT_OK
                            }
                        }
                    }
                    Err(e) => {
                        warn!("The tx frame had the following error: {}", e);
                        VIRTIO_CAN_RESULT_NOT_OK
                    }
                };

                // If the device cannot send the frame either because socket does not
                // exist or the writing the frame fails for another unknown reason
                // then behave as receiving a busoff error.
                if _response == VIRTIO_CAN_RESULT_NOT_OK {
                    trace!("Change controller status to STOPPED and busoff to true");
                    // TODO: Trigger a config_change notification
                    self.controller.write().unwrap().config.status =
                        VIRTIO_CAN_S_CTRL_BUSOFF.into();
                    self.controller.write().unwrap().ctrl_state = CAN_CS_STOPPED;
                }

                _response
            };

            writer
                .write_obj(response)
                .map_err(|_| Error::DescriptorWriteFailed)?;

            if vring
                .add_used(desc_chain.head_index(), writer.bytes_written() as u32)
                .is_err()
            {
                warn!("Couldn't return used descriptors to the ring");
            }
        }

        Ok(true)
    }

    pub fn process_rx_requests(
        &mut self,
        requests: Vec<CanDescriptorChain>,
        vring: &VringRwLock,
    ) -> Result<bool> {
        if requests.is_empty() {
            return Ok(true);
        }

        // This flag, if true, requests a new tx buffer from the front-end
        let mut req_rx_buf = false;

        for desc_chain in requests {
            let atomic_mem = self.mem.as_ref().unwrap().memory();
            let mut writer = desc_chain
                .clone()
                .writer(&atomic_mem)
                .map_err(|_| Error::DescriptorWriteFailed)?;

            let response = match self.controller.write().unwrap().pop() {
                Ok(item) => {
                    // If one or more frames have been received then request
                    // a new rx buffer.
                    req_rx_buf = true;
                    item
                }
                Err(QueueEmpty) => {
                    return Ok(req_rx_buf);
                }
                Err(_) => {
                    return Err(Error::HandleEventUnknown);
                }
            };

            let can_rx = match self.check_rx_frame(response) {
                Ok(frame) => frame,
                Err(e) => {
                    warn!("The tx frame had the following error: {}", e);
                    return Err(e);
                }
            };

            writer
                .write_obj(can_rx)
                .map_err(|_| Error::DescriptorWriteFailed)?;

            if vring
                .add_used(desc_chain.head_index(), writer.bytes_written() as u32)
                .is_err()
            {
                warn!("Couldn't return used descriptors to the ring");
            }
        }

        Ok(true)
    }

    /// Process the messages in the vring and dispatch replies
    fn process_ctrl_queue(&mut self, vring: &VringRwLock) -> Result<()> {
        let requests: Vec<CanDescriptorChain> = vring
            .get_mut()
            .get_queue_mut()
            .iter(self.mem.as_ref().unwrap().memory())
            .map_err(|_| Error::DescriptorNotFound)?
            .collect();

        if self.process_ctrl_requests(requests, vring)? {
            // Send notification once all the requests are processed
            vring
                .signal_used_queue()
                .map_err(|_| Error::NotificationFailed)?;
        }
        Ok(())
    }

    /// Process the messages in the vring and dispatch replies
    fn process_tx_queue(&self, vring: &VringRwLock) -> Result<()> {
        let requests: Vec<CanDescriptorChain> = vring
            .get_mut()
            .get_queue_mut()
            .iter(self.mem.as_ref().unwrap().memory())
            .map_err(|_| Error::DescriptorNotFound)?
            .collect();

        if self.process_tx_requests(requests, vring)? {
            // Send notification once all the requests are processed
            vring
                .signal_used_queue()
                .map_err(|_| Error::NotificationFailed)?;
        }

        Ok(())
    }

    /// Process the messages in the vring and dispatch replies
    fn process_rx_queue(&mut self, vring: &VringRwLock) -> Result<()> {
        let requests: Vec<CanDescriptorChain> = vring
            .get_mut()
            .get_queue_mut()
            .iter(self.mem.as_ref().unwrap().memory())
            .map_err(|_| Error::DescriptorNotFound)?
            .collect();

        if self.process_rx_requests(requests, vring)? {
            // Send notification once all the requests are processed
            vring
                .signal_used_queue()
                .map_err(|_| Error::NotificationFailed)?;
        }
        Ok(())
    }

    /// Set self's VringWorker.
    pub(crate) fn set_vring_worker(
        &self,
        vring_worker: &Arc<VringEpollHandler<Arc<RwLock<VhostUserCanBackend>>>>,
    ) {
        let rx_event_fd = self.controller.read().unwrap().rx_event_fd.as_raw_fd();
        vring_worker
            .register_listener(rx_event_fd, EventSet::IN, u64::from(BACKEND_EFD))
            .expect("Fail to register new handler");
    }
}

/// VhostUserBackendMut trait methods
impl VhostUserBackendMut for VhostUserCanBackend {
    type Vring = VringRwLock;
    type Bitmap = ();

    fn num_queues(&self) -> usize {
        NUM_QUEUES
    }

    fn max_queue_size(&self) -> usize {
        QUEUE_SIZE
    }

    fn features(&self) -> u64 {
        (1 << VIRTIO_F_VERSION_1)
            | (1 << VIRTIO_F_NOTIFY_ON_EMPTY)
            | (1 << VIRTIO_RING_F_EVENT_IDX)
            | (1 << VIRTIO_CAN_F_CAN_CLASSIC)
            | (1 << VIRTIO_CAN_F_CAN_FD)
            | (1 << VIRTIO_RING_F_INDIRECT_DESC)
            | VhostUserVirtioFeatures::PROTOCOL_FEATURES.bits()
    }

    fn acked_features(&mut self, _features: u64) {
        self.acked_features = _features;
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
                    .write()
                    .unwrap()
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

        // If the device is in STOPPED state only TX and CTRL messages can be handled
        if (self.controller.read().unwrap().ctrl_state == CAN_CS_STOPPED)
            && ((device_event == RX_QUEUE) || (device_event == BACKEND_EFD))
        {
            trace!("Device is stopped!");
            if device_event == BACKEND_EFD {
                let _ = self.controller.write().unwrap().rx_event_fd.read();
            }
            return Ok(());
        }

        if device_event == RX_QUEUE && self.controller.write().unwrap().rx_is_empty() {
            return Ok(());
        };

        let vring = if device_event != BACKEND_EFD {
            &vrings[device_event as usize]
        } else {
            let _ = self.controller.write().unwrap().rx_event_fd.read();
            &vrings[RX_QUEUE as usize]
        };

        if self.event_idx {
            // vm-virtio's Queue implementation only checks avail_index
            // once, so to properly support EVENT_IDX we need to keep
            // calling process_request_queue() until it stops finding
            // new requests on the queue.
            loop {
                vring.disable_notification().unwrap();
                match device_event {
                    CTRL_QUEUE => self.process_ctrl_queue(vring),
                    TX_QUEUE => self.process_tx_queue(vring),
                    RX_QUEUE => self.process_rx_queue(vring),
                    BACKEND_EFD => self.process_rx_queue(vring),
                    _ => Err(Error::HandleEventUnknown),
                }?;
                if !vring.enable_notification().unwrap() {
                    break;
                }
            }
        } else {
            // Without EVENT_IDX, a single call is enough.
            match device_event {
                CTRL_QUEUE => self.process_ctrl_queue(vring),
                TX_QUEUE => self.process_tx_queue(vring),
                RX_QUEUE => self.process_rx_queue(vring),
                BACKEND_EFD => self.process_rx_queue(vring),
                _ => Err(Error::HandleEventUnknown),
            }?;
        }
        Ok(())
    }

    fn exit_event(&self, _thread_index: usize) -> Option<EventFd> {
        self.exit_event.try_clone().ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::virtio_can::{VirtioCanCtrlResponse, VirtioCanTxResponse};
    use std::mem::size_of;
    use virtio_bindings::virtio_ring::{VRING_DESC_F_NEXT, VRING_DESC_F_WRITE};
    use virtio_queue::{
        desc::{split::Descriptor as SplitDescriptor, RawDescriptor},
        mock::MockSplitQueue,
        Queue,
    };
    use vm_memory::{Bytes, GuestAddress, GuestMemoryAtomic, GuestMemoryMmap, Le16, Le32};

    #[test]
    fn test_virtio_can_tx_response_default() {
        let response = VirtioCanTxResponse::default();
        assert_eq!(response.result, 0);
    }

    #[test]
    fn test_virtio_can_ctrl_request_default() {
        let request = VirtioCanCtrlRequest::default();
        assert_eq!(request.msg_type, Le16::default());
    }

    #[test]
    fn test_virtio_can_ctrl_response_default() {
        let response = VirtioCanCtrlResponse::default();
        assert_eq!(response.result, 0);
    }

    #[test]
    fn test_virtio_can_frame_default() {
        let frame = VirtioCanFrame::default();
        assert_eq!(frame.msg_type, Le16::default());
        assert_eq!(frame.length, Le16::default());
        assert_eq!(frame.reserved, Le32::default());
        assert_eq!(frame.flags, Le32::default());
        assert_eq!(frame.can_id, Le32::default());
        assert_eq!(frame.sdu, [0; 64]);
    }

    #[test]
    fn test_virtio_can_empty_requests() {
        let controller =
            CanController::new("can0".to_string()).expect("Could not build controller");
        let controller = Arc::new(RwLock::new(controller));
        let mut vu_can_backend =
            VhostUserCanBackend::new(controller.clone()).expect("Could not build vhucan device");
        let mem = GuestMemoryAtomic::new(
            GuestMemoryMmap::<()>::from_ranges(&[(GuestAddress(0), 0x1000)]).unwrap(),
        );
        let vring = VringRwLock::new(mem.clone(), 0x1000).unwrap();

        // Empty descriptor chain should be ignored
        assert!(vu_can_backend
            .process_rx_requests(Vec::<CanDescriptorChain>::new(), &vring)
            .expect("Fail to examin empty rx vring"));
        assert!(vu_can_backend
            .process_tx_requests(Vec::<CanDescriptorChain>::new(), &vring)
            .expect("Fail to examin empty tx vring"));
        assert!(vu_can_backend
            .process_ctrl_requests(Vec::<CanDescriptorChain>::new(), &vring)
            .expect("Fail to examin empty ctrl vring"));
    }

    #[test]
    fn test_virtio_can_empty_handle_request() {
        let controller =
            CanController::new("can0".to_string()).expect("Could not build controller");
        let controller = Arc::new(RwLock::new(controller));
        let mut vu_can_backend =
            VhostUserCanBackend::new(controller.clone()).expect("Could not build vhucan device");
        let mem = GuestMemoryAtomic::new(
            GuestMemoryMmap::<()>::from_ranges(&[(GuestAddress(0), 0x1000)]).unwrap(),
        );
        vu_can_backend.update_memory(mem.clone()).unwrap();

        let vring = VringRwLock::new(mem, 0x1000).unwrap();
        vring.set_queue_info(0x100, 0x200, 0x300).unwrap();
        vring.set_queue_ready(true);
        let list_vrings = [vring.clone(), vring.clone(), vring.clone(), vring.clone()];

        vu_can_backend
            .handle_event(RX_QUEUE, EventSet::IN, &list_vrings, 0)
            .unwrap();

        vu_can_backend
            .handle_event(TX_QUEUE, EventSet::IN, &list_vrings, 0)
            .unwrap();

        vu_can_backend
            .handle_event(CTRL_QUEUE, EventSet::IN, &list_vrings, 0)
            .unwrap();

        vu_can_backend
            .handle_event(BACKEND_EFD, EventSet::IN, &list_vrings, 0)
            .unwrap();
    }

    fn build_desc_chain_mem(
        mem: &GuestMemoryMmap,
        count: u16,
        flags: Vec<u16>,
        len: u32,
    ) -> CanDescriptorChain {
        let vq = MockSplitQueue::new(mem, 16);
        let mut desc_vec = Vec::new();

        //Create a descriptor chain with count descriptors.
        for i in 0..count {
            let desc_flags = if i < count - 1 {
                flags[i as usize] | VRING_DESC_F_NEXT as u16
            } else {
                flags[i as usize] & !VRING_DESC_F_NEXT as u16
            };

            let desc = RawDescriptor::from(SplitDescriptor::new(
                (0x100 * (i + 1)) as u64,
                len,
                desc_flags,
                i + 1,
            ));
            desc_vec.push(desc);
        }

        vq.add_desc_chains(&desc_vec, 0).unwrap();

        // Create descriptor chain from pre-filled memory
        vq.create_queue::<Queue>()
            .unwrap()
            .iter(GuestMemoryAtomic::new(mem.clone()).memory())
            .unwrap()
            .next()
            .unwrap()
    }

    #[test]
    fn test_virtio_can_ctrl_request() {
        // Initialize can device and vhost-device-can backend
        let controller =
            CanController::new("can0".to_string()).expect("Could not build controller");
        let controller = Arc::new(RwLock::new(controller));
        let mut vu_can_backend =
            VhostUserCanBackend::new(controller.clone()).expect("Could not build vhucan device");
        let mem = GuestMemoryMmap::<()>::from_ranges(&[(GuestAddress(0), 0x1000)]).unwrap();

        // Test 1: Since we provide only one write only, an error will be trigger
        //         the reader will have 0 data.
        let can_mes_len = size_of::<VirtioCanCtrlRequest>();
        let desc_chain = build_desc_chain_mem(
            &mem,
            1,
            vec![VRING_DESC_F_WRITE as u16],
            can_mes_len.try_into().unwrap(),
        );
        let mem1 = GuestMemoryAtomic::new(mem.clone());
        let vring = VringRwLock::new(mem1.clone(), 0x1000).unwrap();
        vu_can_backend.update_memory(mem1).unwrap();

        assert_eq!(
            vu_can_backend
                .process_ctrl_requests(vec![desc_chain], &vring)
                .unwrap_err(),
            Error::DescriptorReadFailed
        );

        // Test 2: Two write only descriptors are available, so the reader
        //         will complain for having 0 data
        let can_mes_len = size_of::<VirtioCanCtrlRequest>();
        let desc_chain = build_desc_chain_mem(
            &mem,
            2,
            vec![VRING_DESC_F_WRITE as u16, VRING_DESC_F_WRITE as u16],
            can_mes_len.try_into().unwrap(),
        );
        let mem1 = GuestMemoryAtomic::new(mem.clone());
        let vring = VringRwLock::new(mem1.clone(), 0x1000).unwrap();
        vu_can_backend.update_memory(mem1).unwrap();

        assert_eq!(
            vu_can_backend
                .process_ctrl_requests(vec![desc_chain], &vring)
                .unwrap_err(),
            Error::DescriptorReadFailed
        );

        // Test 3: The reader descriptor has two bytes of data
        //         but are initialized to 0 -> Unknown control message
        let can_mes_len = size_of::<VirtioCanCtrlRequest>();
        let desc_chain = build_desc_chain_mem(
            &mem,
            2,
            vec![0, VRING_DESC_F_WRITE as u16],
            can_mes_len.try_into().unwrap(),
        );
        let mem1 = GuestMemoryAtomic::new(mem.clone());
        let vring = VringRwLock::new(mem1.clone(), 0x1000).unwrap();
        vu_can_backend.update_memory(mem1).unwrap();

        assert!(vu_can_backend
            .process_ctrl_requests(vec![desc_chain.clone()], &vring)
            .unwrap());

        let can_frame_res = desc_chain
            .memory()
            .read_obj::<u8>(vm_memory::GuestAddress(0x200_u64))
            .map_err(|_| Error::DescriptorReadFailed)
            .unwrap();

        assert_eq!(VIRTIO_CAN_RESULT_NOT_OK, can_frame_res);

        // Test 4: Successfull test for VIRTIO_CAN_SET_CTRL_MODE_START
        let can_mes_len = size_of::<VirtioCanCtrlRequest>();
        let desc_chain = build_desc_chain_mem(
            &mem,
            2,
            vec![0, VRING_DESC_F_WRITE as u16],
            can_mes_len.try_into().unwrap(),
        );
        let mem1 = GuestMemoryAtomic::new(mem.clone());
        let vring = VringRwLock::new(mem1.clone(), 0x1000).unwrap();
        vu_can_backend.update_memory(mem1).unwrap();

        let ctrl_msg: u16 = VIRTIO_CAN_SET_CTRL_MODE_START;
        desc_chain
            .memory()
            .write_obj(ctrl_msg, vm_memory::GuestAddress(0x100_u64))
            .unwrap();

        // Write a value on the writer which does not represent known messages
        desc_chain
            .memory()
            .write_obj(5, vm_memory::GuestAddress(0x200_u64))
            .unwrap();

        assert!(vu_can_backend
            .process_ctrl_requests(vec![desc_chain.clone()], &vring)
            .unwrap());

        let can_frame_res = desc_chain
            .memory()
            .read_obj::<u8>(vm_memory::GuestAddress(0x200_u64))
            .map_err(|_| Error::DescriptorReadFailed)
            .unwrap();

        assert_eq!(VIRTIO_CAN_RESULT_OK, can_frame_res);

        // Test 5: Successfull test for VIRTIO_CAN_SET_CTRL_MODE_STOP
        let can_mes_len = size_of::<VirtioCanCtrlRequest>();
        let desc_chain = build_desc_chain_mem(
            &mem,
            2,
            vec![0, VRING_DESC_F_WRITE as u16],
            can_mes_len.try_into().unwrap(),
        );
        let mem1 = GuestMemoryAtomic::new(mem.clone());
        let vring = VringRwLock::new(mem1.clone(), 0x1000).unwrap();
        vu_can_backend.update_memory(mem1).unwrap();

        let ctrl_msg: u16 = VIRTIO_CAN_SET_CTRL_MODE_STOP;
        desc_chain
            .memory()
            .write_obj(ctrl_msg, vm_memory::GuestAddress(0x100_u64))
            .unwrap();

        // Write a value on the writer which does not represent known messages
        desc_chain
            .memory()
            .write_obj(5, vm_memory::GuestAddress(0x200_u64))
            .unwrap();

        assert!(vu_can_backend
            .process_ctrl_requests(vec![desc_chain.clone()], &vring)
            .unwrap());

        let can_frame_res = desc_chain
            .memory()
            .read_obj::<u8>(vm_memory::GuestAddress(0x200_u64))
            .map_err(|_| Error::DescriptorReadFailed)
            .unwrap();

        assert_eq!(VIRTIO_CAN_RESULT_OK, can_frame_res);

        // Test 6: Since we provide only one read only, an error will be trigger
        //         about the writer having 0 data
        let can_mes_len = size_of::<VirtioCanCtrlRequest>();
        let desc_chain = build_desc_chain_mem(&mem, 1, vec![0], can_mes_len.try_into().unwrap());
        let mem1 = GuestMemoryAtomic::new(mem.clone());
        let vring = VringRwLock::new(mem1.clone(), 0x1000).unwrap();
        vu_can_backend.update_memory(mem1).unwrap();

        let ctrl_msg: u16 = VIRTIO_CAN_SET_CTRL_MODE_START;
        desc_chain
            .memory()
            .write_obj(ctrl_msg, vm_memory::GuestAddress(0x100_u64))
            .unwrap();

        assert_eq!(
            vu_can_backend
                .process_ctrl_requests(vec![desc_chain], &vring)
                .unwrap_err(),
            Error::DescriptorWriteFailed
        );

        // Test 7: Two read only descriptors are available, so the writer
        //         will complain for having 0 data
        let can_mes_len = size_of::<VirtioCanCtrlRequest>();
        let desc_chain = build_desc_chain_mem(&mem, 2, vec![0, 0], can_mes_len.try_into().unwrap());
        let mem1 = GuestMemoryAtomic::new(mem.clone());
        let vring = VringRwLock::new(mem1.clone(), 0x1000).unwrap();
        vu_can_backend.update_memory(mem1).unwrap();

        let ctrl_msg: u16 = VIRTIO_CAN_SET_CTRL_MODE_STOP;
        desc_chain
            .memory()
            .write_obj(ctrl_msg, vm_memory::GuestAddress(0x100_u64))
            .unwrap();

        assert_eq!(
            vu_can_backend
                .process_ctrl_requests(vec![desc_chain], &vring)
                .unwrap_err(),
            Error::DescriptorWriteFailed
        );

        // Test 8: If we interchange the write read descriptors then
        //         it will fail!

        let can_mes_len = size_of::<VirtioCanCtrlRequest>();
        let desc_chain = build_desc_chain_mem(
            &mem,
            2,
            vec![VRING_DESC_F_WRITE as u16, 0],
            can_mes_len.try_into().unwrap(),
        );
        let mem1 = GuestMemoryAtomic::new(mem.clone());
        let vring = VringRwLock::new(mem1.clone(), 0x1000).unwrap();
        vu_can_backend.update_memory(mem1).unwrap();

        let ctrl_msg: u16 = VIRTIO_CAN_SET_CTRL_MODE_START;
        desc_chain
            .memory()
            .write_obj(ctrl_msg, vm_memory::GuestAddress(0x200_u64))
            .unwrap();

        // Write a value on the writer which does not represent known messages
        desc_chain
            .memory()
            .write_obj(5, vm_memory::GuestAddress(0x100_u64))
            .unwrap();

        assert!(vu_can_backend
            .process_ctrl_requests(vec![desc_chain.clone()], &vring)
            .unwrap());

        let can_frame_res = desc_chain
            .memory()
            .read_obj::<u8>(vm_memory::GuestAddress(0x100_u64))
            .map_err(|_| Error::DescriptorReadFailed)
            .unwrap();

        assert_eq!(VIRTIO_CAN_RESULT_OK, can_frame_res);
    }

    #[test]
    fn test_virtio_can_check_tx_unknown_frame() {
        let controller =
            CanController::new("can0".to_string()).expect("Could not build controller");
        let controller = Arc::new(RwLock::new(controller));
        let vu_can_backend =
            VhostUserCanBackend::new(controller.clone()).expect("Could not build vhucan device");

        let frame = VirtioCanFrame {
            msg_type: 0.into(),
            can_id: 0.into(),
            length: 0.into(),
            reserved: 0.into(),
            flags: 0.into(),
            sdu: [0; 64],
        };

        assert_eq!(
            vu_can_backend.check_tx_frame(frame).unwrap_err(),
            Error::UnexpectedCanMsgType(0)
        );
    }

    #[test]
    fn test_virtio_can_check_tx_can_frame() {
        let controller =
            CanController::new("can0".to_string()).expect("Could not build controller");
        let controller = Arc::new(RwLock::new(controller));
        let mut vu_can_backend =
            VhostUserCanBackend::new(controller.clone()).expect("Could not build vhucan device");

        // Test 1: UnexpectedClassicFlag
        let frame = VirtioCanFrame {
            msg_type: VIRTIO_CAN_TX.into(),
            can_id: 0.into(),
            length: 4.into(),
            reserved: 0.into(),
            flags: 0.into(),
            sdu: [0; 64],
        };

        assert_eq!(
            vu_can_backend.check_tx_frame(frame).unwrap_err(),
            Error::UnexpectedClassicFlag
        );

        // Test 2: Return the same length
        vu_can_backend.acked_features(1 << VIRTIO_CAN_F_CAN_CLASSIC);

        assert_eq!(
            vu_can_backend.check_tx_frame(frame).unwrap().length,
            frame.length
        );

        // Test 3: Return Error::InvalidCanLength(frame_length) when length is out-of-range (>8)
        let frame = VirtioCanFrame {
            msg_type: VIRTIO_CAN_TX.into(),
            can_id: 0.into(),
            length: 40.into(),
            reserved: 0.into(),
            flags: 0.into(),
            sdu: [0; 64],
        };

        assert_eq!(
            vu_can_backend.check_tx_frame(frame).unwrap_err(),
            Error::InvalidCanLength(40)
        );
    }

    #[test]
    fn test_virtio_can_check_tx_canfd_frame() {
        let controller =
            CanController::new("can0".to_string()).expect("Could not build controller");
        let controller = Arc::new(RwLock::new(controller));
        let mut vu_can_backend =
            VhostUserCanBackend::new(controller).expect("Could not build vhucan device");

        // Enable VIRTIO_CAN_F_CAN_FD feature
        vu_can_backend.acked_features(1 << VIRTIO_CAN_F_CAN_FD);

        // Test 1: If no VIRTIO_CAN_FLAGS_FD in flag return UnexpectedClassicFlag
        let frame = VirtioCanFrame {
            msg_type: VIRTIO_CAN_TX.into(),
            can_id: 0.into(),
            length: 12.into(),
            reserved: 0.into(),
            flags: 0.into(),
            sdu: [0; 64],
        };

        assert_eq!(
            vu_can_backend.check_tx_frame(frame).unwrap_err(),
            Error::UnexpectedClassicFlag
        );

        // Test 2: If VIRTIO_CAN_FLAGS_FD is in flag check if return message has
        //         CAN_FRMF_TYPE_FD in flags.
        let frame = VirtioCanFrame {
            msg_type: VIRTIO_CAN_TX.into(),
            can_id: 0.into(),
            length: 12.into(),
            reserved: 0.into(),
            flags: VIRTIO_CAN_FLAGS_FD.into(),
            sdu: [0; 64],
        };

        assert_eq!(
            vu_can_backend
                .check_tx_frame(frame)
                .unwrap()
                .flags
                .to_native()
                & CAN_FRMF_TYPE_FD,
            CAN_FRMF_TYPE_FD
        );

        // Test 3: If 1 is not a valid CAN flag return InvalidCanFlags(1).
        let frame = VirtioCanFrame {
            msg_type: VIRTIO_CAN_TX.into(),
            can_id: 1.into(),
            length: 12.into(),
            reserved: 0.into(),
            flags: 0x1.into(),
            sdu: [0; 64],
        };

        assert_eq!(
            vu_can_backend.check_tx_frame(frame).unwrap_err(),
            Error::InvalidCanFlags(1)
        );

        // Test 4: receive frame with the same length if length is < 64 but not
        //         one of [12, 16, 20, 24, 32, 48, 64] -> InvalidCanLength(40)]
        let frame = VirtioCanFrame {
            msg_type: VIRTIO_CAN_TX.into(),
            can_id: 0.into(),
            length: 40.into(),
            reserved: 0.into(),
            flags: VIRTIO_CAN_FLAGS_FD.into(),
            sdu: [0; 64],
        };

        assert_eq!(
            vu_can_backend.check_tx_frame(frame).unwrap_err(),
            Error::InvalidCanLength(40)
        );

        // Test 5: receive frame with length is > 64
        //         then -> InvalidCanLength(frame_length).
        let frame = VirtioCanFrame {
            msg_type: VIRTIO_CAN_TX.into(),
            can_id: 0.into(),
            length: 80.into(),
            reserved: 0.into(),
            flags: VIRTIO_CAN_FLAGS_FD.into(),
            sdu: [0; 64],
        };

        assert_eq!(
            vu_can_backend.check_tx_frame(frame).unwrap_err(),
            Error::InvalidCanLength(80)
        );

        // Test 6: receive frame with length in [12, 16, 20, 24, 32, 48, 64]
        let frame = VirtioCanFrame {
            msg_type: VIRTIO_CAN_TX.into(),
            can_id: 0.into(),
            length: 48.into(),
            reserved: 0.into(),
            flags: VIRTIO_CAN_FLAGS_FD.into(),
            sdu: [0; 64],
        };

        assert_eq!(vu_can_backend.check_tx_frame(frame).unwrap().length, 48);
    }

    #[test]
    fn test_virtio_can_check_tx_rtr_frame() {
        let controller =
            CanController::new("can0".to_string()).expect("Could not build controller");
        let controller = Arc::new(RwLock::new(controller));
        let mut vu_can_backend =
            VhostUserCanBackend::new(controller.clone()).expect("Could not build vhucan device");

        // Test 1: Take a valid CAN / CANFD message and try to enable RTR in flags.
        //         the test should fail because VIRTIO_CAN_F_CAN_CLASSIC and
        //         VIRTIO_CAN_F_RTR_FRAMES are not negotiated.
        let frame = VirtioCanFrame {
            msg_type: VIRTIO_CAN_TX.into(),
            can_id: 0.into(),
            length: 8.into(),
            reserved: 0.into(),
            flags: VIRTIO_CAN_FLAGS_RTR.into(),
            sdu: [0; 64],
        };

        assert_eq!(
            vu_can_backend.check_tx_frame(frame).unwrap_err(),
            Error::UnexpectedRtrFlag
        );

        // Test 2: Take a valid CAN / CANFD message and try to enable RTR in flags.
        //         the test should fail because VIRTIO_CAN_F_CAN_CLASSIC is not negotiated.
        vu_can_backend.acked_features(1 << VIRTIO_CAN_F_RTR_FRAMES);

        assert_eq!(
            vu_can_backend.check_tx_frame(frame).unwrap_err(),
            Error::UnexpectedRtrFlag
        );

        // Test 3: Take a valid CAN / CANFD message and try to enable RTR in flags.
        //         the test should succeed because VIRTIO_CAN_F_CAN_CLASSIC is negotiated.
        vu_can_backend
            .acked_features((1 << VIRTIO_CAN_F_RTR_FRAMES) | (1 << VIRTIO_CAN_F_CAN_CLASSIC));

        assert_eq!(
            vu_can_backend
                .check_tx_frame(frame)
                .unwrap()
                .can_id
                .to_native()
                & CAN_RTR_FLAG,
            CAN_RTR_FLAG
        );

        // Test 4: Take a valid CAN / CANFD message and try to enable RTR in flags.
        //         the test should fail because VIRTIO_CAN_F_CAN_CLASSIC is not negotiated,
        //         and RTR does not work with VIRTIO_CAN_F_CAN_FD.
        vu_can_backend.acked_features((1 << VIRTIO_CAN_F_RTR_FRAMES) | (1 << VIRTIO_CAN_F_CAN_FD));

        assert_eq!(
            vu_can_backend.check_tx_frame(frame).unwrap_err(),
            Error::UnexpectedRtrFlag
        );
    }

    #[test]
    fn test_virtio_can_check_tx_eff_frame() {
        let controller =
            CanController::new("can0".to_string()).expect("Could not build controller");
        let controller = Arc::new(RwLock::new(controller));
        let mut vu_can_backend =
            VhostUserCanBackend::new(controller.clone()).expect("Could not build vhucan device");

        // This test is valid for both CAN & CANFD messages, so for simplicity
        // we will check only CAN case.
        vu_can_backend.acked_features(1 << VIRTIO_CAN_F_CAN_CLASSIC);

        // Test 1: Received message should not have CAN_EFF_FLAG in can_id
        let mut frame = VirtioCanFrame {
            msg_type: VIRTIO_CAN_TX.into(),
            can_id: 0.into(),
            length: 8.into(),
            reserved: 0.into(),
            flags: 0.into(),
            sdu: [0; 64],
        };

        assert_eq!(
            vu_can_backend
                .check_tx_frame(frame)
                .unwrap()
                .can_id
                .to_native()
                & CAN_EFF_FLAG,
            0
        );

        // Test 2: If VIRTIO_CAN_FLAGS_EXTENDED is NOT enabled, CAN ID should
        //         be smaller than 11 bits
        frame.can_id = (CAN_SFF_MASK + 1).into(); // CAN_SFF_MASK = 0x7FFU
        assert_eq!(
            vu_can_backend.check_tx_frame(frame).unwrap_err(),
            Error::UnexpectedCanId(11)
        );

        // Test 3: Received message should have CAN_EFF_MASK in can_id
        frame.flags = VIRTIO_CAN_FLAGS_EXTENDED.into();
        assert_eq!(
            vu_can_backend
                .check_tx_frame(frame)
                .unwrap()
                .can_id
                .to_native()
                & CAN_EFF_FLAG,
            CAN_EFF_FLAG
        );

        // Test 4: If VIRTIO_CAN_FLAGS_EXTENDED is enabled, CAN ID should be
        //         smaller than 29 bits
        frame.can_id = (CAN_EFF_MASK + 1).into(); // CAN_EFF_MASK = 0x1FFFFFFFU
        assert_eq!(
            vu_can_backend.check_tx_frame(frame).unwrap_err(),
            Error::UnexpectedCanId(29)
        );
    }

    #[test]
    fn test_virtio_can_tx_general_tests() {
        let controller =
            CanController::new("can0".to_string()).expect("Could not build controller");
        let controller = Arc::new(RwLock::new(controller));
        let mut vu_can_backend =
            VhostUserCanBackend::new(controller.clone()).expect("Could not build vhucan device");
        let mem = GuestMemoryMmap::<()>::from_ranges(&[(GuestAddress(0), 0x1000)]).unwrap();

        // Any number of descriptor different than 2 will generate an error
        let count = 1;

        // Test 1: Provide only write only descriptor -> Fail
        let desc_chain = build_desc_chain_mem(&mem, count, vec![VRING_DESC_F_WRITE as u16], 0x200);
        let mem1 = GuestMemoryAtomic::new(mem.clone());
        let vring = VringRwLock::new(mem1.clone(), 0x1000).unwrap();
        vu_can_backend.update_memory(mem1).unwrap();

        assert_eq!(
            vu_can_backend
                .process_tx_requests(vec![desc_chain.clone()], &vring)
                .unwrap_err(),
            Error::DescriptorReadFailed
        );

        // Test 2: Provide only read only descriptor -> Fail
        let desc_chain = build_desc_chain_mem(&mem, 1, vec![0], 0x200);
        let mem1 = GuestMemoryAtomic::new(mem.clone());
        let vring = VringRwLock::new(mem1.clone(), 0x1000).unwrap();
        vu_can_backend.update_memory(mem1).unwrap();

        assert_eq!(
            vu_can_backend
                .process_tx_requests(vec![desc_chain.clone()], &vring)
                .unwrap_err(),
            Error::DescriptorWriteFailed
        );

        // Test 3: Provide only write only descriptors -> Fail
        let desc_chain = build_desc_chain_mem(
            &mem,
            2,
            vec![VRING_DESC_F_WRITE as u16, VRING_DESC_F_WRITE as u16],
            0x200,
        );
        let mem1 = GuestMemoryAtomic::new(mem.clone());
        let vring = VringRwLock::new(mem1.clone(), 0x1000).unwrap();
        vu_can_backend.update_memory(mem1).unwrap();

        assert_eq!(
            vu_can_backend
                .process_tx_requests(vec![desc_chain.clone()], &vring)
                .unwrap_err(),
            Error::DescriptorReadFailed
        );

        // Test 4: Provide only read only descriptors -> Fail
        let desc_chain = build_desc_chain_mem(&mem, 2, vec![0, 0], 0x200);
        let mem1 = GuestMemoryAtomic::new(mem.clone());
        let vring = VringRwLock::new(mem1.clone(), 0x1000).unwrap();
        vu_can_backend.update_memory(mem1).unwrap();
        assert_eq!(
            vu_can_backend
                .process_tx_requests(vec![desc_chain.clone()], &vring)
                .unwrap_err(),
            Error::DescriptorWriteFailed
        );

        // Test 5: Provide correct descriptors but 0 size -> Fail
        let desc_chain = build_desc_chain_mem(&mem, 2, vec![0, VRING_DESC_F_WRITE as u16], 0x0);
        let mem1 = GuestMemoryAtomic::new(mem.clone());
        let vring = VringRwLock::new(mem1.clone(), 0x1000).unwrap();
        vu_can_backend.update_memory(mem1).unwrap();

        assert_eq!(
            vu_can_backend
                .process_tx_requests(vec![desc_chain.clone()], &vring)
                .unwrap_err(),
            Error::DescriptorReadFailed
        );

        // Test 6: Provide correct descriptors and size
        let can_mes_len = size_of::<VirtioCanFrame>();
        let desc_chain = build_desc_chain_mem(
            &mem,
            2,
            vec![0, VRING_DESC_F_WRITE as u16],
            can_mes_len.try_into().unwrap(),
        );
        let mem1 = GuestMemoryAtomic::new(mem.clone());
        let vring = VringRwLock::new(mem1.clone(), 0x1000).unwrap();
        vu_can_backend.update_memory(mem1).unwrap();
        assert!(vu_can_backend
            .process_tx_requests(vec![desc_chain], &vring)
            .unwrap());
    }

    #[test]
    fn test_virtio_can_tx_device_stopped_test() {
        let controller =
            CanController::new("can0".to_string()).expect("Could not build controller");
        let controller = Arc::new(RwLock::new(controller));
        let mut vu_can_backend =
            VhostUserCanBackend::new(controller.clone()).expect("Could not build vhucan device");
        let mem = GuestMemoryMmap::<()>::from_ranges(&[(GuestAddress(0), 0x1000)]).unwrap();

        // Enable VIRTIO_CAN_F_CAN_CLASSIC feature
        vu_can_backend.acked_features(1 << VIRTIO_CAN_F_CAN_CLASSIC);

        let can_mes_len = size_of::<VirtioCanFrame>();
        let desc_chain = build_desc_chain_mem(
            &mem,
            2,
            vec![0, VRING_DESC_F_WRITE as u16],
            can_mes_len.try_into().unwrap(),
        );
        let mem1 = GuestMemoryAtomic::new(mem.clone());
        let vring = VringRwLock::new(mem1.clone(), 0x1000).unwrap();
        vu_can_backend.update_memory(mem1).unwrap();

        let frame = VirtioCanFrame {
            msg_type: VIRTIO_CAN_TX.into(),
            can_id: 123.into(),
            length: 8.into(),
            reserved: 0.into(),
            flags: 0.into(),
            sdu: [0; 64],
        };

        desc_chain
            .memory()
            .write_obj(frame, vm_memory::GuestAddress(0x100_u64))
            .unwrap();

        desc_chain
            .memory()
            .write_obj(5, vm_memory::GuestAddress(0x200_u64))
            .unwrap();

        assert!(vu_can_backend
            .process_tx_requests(vec![desc_chain.clone()], &vring)
            .unwrap());

        let can_frame_res = desc_chain
            .memory()
            .read_obj::<u8>(vm_memory::GuestAddress(0x200_u64))
            .map_err(|_| Error::DescriptorReadFailed)
            .unwrap();

        assert_eq!(VIRTIO_CAN_RESULT_NOT_OK, can_frame_res);
    }

    #[test]
    fn test_virtio_can_tx_device_started_test_send_fail() {
        let controller =
            CanController::new("can0".to_string()).expect("Could not build controller");
        let controller = Arc::new(RwLock::new(controller));
        let mut vu_can_backend =
            VhostUserCanBackend::new(controller.clone()).expect("Could not build vhucan device");
        let mem = GuestMemoryMmap::<()>::from_ranges(&[(GuestAddress(0), 0x1000)]).unwrap();

        // Enable VIRTIO_CAN_F_CAN_CLASSIC feature
        vu_can_backend.acked_features(1 << VIRTIO_CAN_F_CAN_CLASSIC);

        // Start the device
        controller.write().unwrap().ctrl_state = CAN_CS_STARTED;

        let can_mes_len = size_of::<VirtioCanFrame>();
        let desc_chain = build_desc_chain_mem(
            &mem,
            2,
            vec![0, VRING_DESC_F_WRITE as u16],
            can_mes_len.try_into().unwrap(),
        );
        let mem1 = GuestMemoryAtomic::new(mem.clone());
        let vring = VringRwLock::new(mem1.clone(), 0x1000).unwrap();
        vu_can_backend.update_memory(mem1).unwrap();

        let frame = VirtioCanFrame {
            msg_type: VIRTIO_CAN_TX.into(),
            can_id: 123.into(),
            length: 8.into(),
            reserved: 0.into(),
            flags: 0.into(),
            sdu: [0; 64],
        };

        desc_chain
            .memory()
            .write_obj(frame, vm_memory::GuestAddress(0x100_u64))
            .unwrap();

        desc_chain
            .memory()
            .write_obj(5, vm_memory::GuestAddress(0x200_u64))
            .unwrap();

        assert!(vu_can_backend
            .process_tx_requests(vec![desc_chain.clone()], &vring)
            .unwrap());

        let can_frame_res = desc_chain
            .memory()
            .read_obj::<u8>(vm_memory::GuestAddress(0x200_u64))
            .map_err(|_| Error::DescriptorReadFailed)
            .unwrap();

        assert_eq!(VIRTIO_CAN_RESULT_NOT_OK, can_frame_res);
    }

    #[test]
    fn test_virtio_can_tx_device_started_check_frame_fail() {
        let controller =
            CanController::new("can0".to_string()).expect("Could not build controller");
        let controller = Arc::new(RwLock::new(controller));
        let mut vu_can_backend =
            VhostUserCanBackend::new(controller.clone()).expect("Could not build vhucan device");
        let mem = GuestMemoryMmap::<()>::from_ranges(&[(GuestAddress(0), 0x1000)]).unwrap();

        // Start the device
        controller.write().unwrap().ctrl_state = CAN_CS_STARTED;

        let can_mes_len = size_of::<VirtioCanFrame>();
        let desc_chain = build_desc_chain_mem(
            &mem,
            2,
            vec![0, VRING_DESC_F_WRITE as u16],
            can_mes_len.try_into().unwrap(),
        );
        let mem1 = GuestMemoryAtomic::new(mem.clone());
        let vring = VringRwLock::new(mem1.clone(), 0x1000).unwrap();
        vu_can_backend.update_memory(mem1).unwrap();

        let frame = VirtioCanFrame {
            msg_type: 0.into(),
            can_id: 123.into(),
            length: 8.into(),
            reserved: 0.into(),
            flags: 0.into(),
            sdu: [0; 64],
        };

        desc_chain
            .memory()
            .write_obj(frame, vm_memory::GuestAddress(0x100_u64))
            .unwrap();

        desc_chain
            .memory()
            .write_obj(5, vm_memory::GuestAddress(0x200_u64))
            .unwrap();

        assert!(vu_can_backend
            .process_tx_requests(vec![desc_chain.clone()], &vring)
            .unwrap());

        let can_frame_res = desc_chain
            .memory()
            .read_obj::<u8>(vm_memory::GuestAddress(0x200_u64))
            .map_err(|_| Error::DescriptorReadFailed)
            .unwrap();

        assert_eq!(VIRTIO_CAN_RESULT_NOT_OK, can_frame_res);
    }

    #[test]
    fn test_virtio_can_check_rx_err_frame() {
        let controller =
            CanController::new("can0".to_string()).expect("Could not build controller");
        let controller = Arc::new(RwLock::new(controller));
        let vu_can_backend =
            VhostUserCanBackend::new(controller.clone()).expect("Could not build vhucan device");

        let frame = VirtioCanFrame {
            msg_type: 0.into(),
            can_id: CAN_ERR_FLAG.into(),
            length: 0.into(),
            reserved: 0.into(),
            flags: 0.into(),
            sdu: [0; 64],
        };

        assert_eq!(
            vu_can_backend.check_rx_frame(frame).unwrap_err(),
            Error::RxFrameUnknownFail
        );

        let frame = VirtioCanFrame {
            msg_type: 0.into(),
            can_id: (CAN_ERR_FLAG | CAN_ERR_BUSOFF).into(),
            length: 0.into(),
            reserved: 0.into(),
            flags: 0.into(),
            sdu: [0; 64],
        };

        assert_eq!(
            vu_can_backend.check_rx_frame(frame).unwrap_err(),
            Error::BusoffRxFrame
        );

        assert_eq!(
            controller.read().unwrap().config.status.to_native(),
            VIRTIO_CAN_S_CTRL_BUSOFF
        );
        assert_eq!(controller.read().unwrap().ctrl_state, CAN_CS_STOPPED);
    }

    #[test]
    fn test_virtio_can_check_rx_features_not_negotiated() {
        let controller =
            CanController::new("can0".to_string()).expect("Could not build controller");
        let controller = Arc::new(RwLock::new(controller));
        let vu_can_backend =
            VhostUserCanBackend::new(controller.clone()).expect("Could not build vhucan device");

        let frame = VirtioCanFrame {
            msg_type: 0.into(),
            can_id: 0.into(),
            length: 0.into(),
            reserved: 0.into(),
            flags: CAN_FRMF_TYPE_FD.into(),
            sdu: [0; 64],
        };

        assert_eq!(
            vu_can_backend.check_rx_frame(frame).unwrap_err(),
            Error::UnexpectedFdFlag
        );

        let frame = VirtioCanFrame {
            msg_type: 0.into(),
            can_id: 0.into(),
            length: 0.into(),
            reserved: 0.into(),
            flags: 0.into(),
            sdu: [0; 64],
        };

        assert_eq!(
            vu_can_backend.check_rx_frame(frame).unwrap_err(),
            Error::UnexpectedClassicFlag
        );
    }

    #[test]
    fn test_virtio_can_check_rx_eff_frame() {
        let controller =
            CanController::new("can0".to_string()).expect("Could not build controller");
        let controller = Arc::new(RwLock::new(controller));
        let mut vu_can_backend =
            VhostUserCanBackend::new(controller.clone()).expect("Could not build vhucan device");

        // This test is valid for both CAN & CANFD messages, so for simplicity
        // we will check only CAN case.
        vu_can_backend.acked_features(1 << VIRTIO_CAN_F_CAN_CLASSIC);

        // Test 1: Received message should not have CAN_EFF_FLAG in can_id
        let mut frame = VirtioCanFrame {
            msg_type: VIRTIO_CAN_TX.into(),
            can_id: 0.into(),
            length: 8.into(),
            reserved: 0.into(),
            flags: 0.into(),
            sdu: [0; 64],
        };

        assert_eq!(
            vu_can_backend
                .check_rx_frame(frame)
                .unwrap()
                .can_id
                .to_native()
                & CAN_EFF_FLAG,
            0
        );

        // Test 2: Received message's can_id should be smaller than CAN_SFF_MASK
        frame.can_id = (CAN_SFF_MASK + 1).into(); // CAN_SFF_MASK = 0x7FFU
        assert!(
            vu_can_backend
                .check_rx_frame(frame)
                .unwrap()
                .can_id
                .to_native()
                < CAN_SFF_MASK,
        );

        // Test 3: Received message should have CAN_EFF_MASK in can_id
        frame.can_id = CAN_EFF_FLAG.into();
        assert_eq!(
            vu_can_backend
                .check_rx_frame(frame)
                .unwrap()
                .flags
                .to_native()
                & VIRTIO_CAN_FLAGS_EXTENDED,
            VIRTIO_CAN_FLAGS_EXTENDED
        );

        // Test 4: Received message's can_id should be equal to CAN_EFF_MASK,
        //         since the 3 MSB have been zeroed.
        frame.can_id = (frame.can_id.to_native() | CAN_EFF_MASK).into(); // CAN_EFF_MASK = 0x1FFFFFFFU
        assert!(
            vu_can_backend
                .check_rx_frame(frame)
                .unwrap()
                .can_id
                .to_native()
                == CAN_EFF_MASK
        );
    }

    #[test]
    fn test_virtio_can_check_rx_rtr_frame() {
        let controller =
            CanController::new("can0".to_string()).expect("Could not build controller");
        let controller = Arc::new(RwLock::new(controller));
        let mut vu_can_backend =
            VhostUserCanBackend::new(controller.clone()).expect("Could not build vhucan device");

        let frame = VirtioCanFrame {
            msg_type: 0.into(),
            can_id: CAN_RTR_FLAG.into(),
            length: 8.into(),
            reserved: 0.into(),
            flags: 0.into(),
            sdu: [0; 64],
        };

        // Test 1: Take a valid CAN / CANFD message and try to enable RTR in flags.
        //         the test should fail because VIRTIO_CAN_F_CAN_CLASSIC is not negotiated.
        vu_can_backend.acked_features(1 << VIRTIO_CAN_F_CAN_CLASSIC);

        assert_eq!(
            vu_can_backend.check_rx_frame(frame).unwrap_err(),
            Error::UnexpectedRtrFlag
        );

        // Test 2: Take a valid CAN / CANFD message and try to enable RTR in flags.
        //         the test should succeed because VIRTIO_CAN_F_CAN_CLASSIC is negotiated.
        vu_can_backend
            .acked_features((1 << VIRTIO_CAN_F_RTR_FRAMES) | (1 << VIRTIO_CAN_F_CAN_CLASSIC));

        assert_eq!(
            vu_can_backend
                .check_rx_frame(frame)
                .unwrap()
                .flags
                .to_native()
                & VIRTIO_CAN_FLAGS_RTR,
            VIRTIO_CAN_FLAGS_RTR
        );

        // Test 3: Take a valid CAN / CANFD message and try to enable RTR in flags.
        //         the test should fail because VIRTIO_CAN_F_CAN_CLASSIC is not negotiated,
        //         and RTR does not work with VIRTIO_CAN_F_CAN_FD.

        let frame = VirtioCanFrame {
            msg_type: 0.into(),
            can_id: CAN_RTR_FLAG.into(),
            length: 8.into(),
            reserved: 0.into(),
            flags: CAN_FRMF_TYPE_FD.into(), // Mark it as CAN FD frame
            sdu: [0; 64],
        };

        vu_can_backend.acked_features((1 << VIRTIO_CAN_F_RTR_FRAMES) | (1 << VIRTIO_CAN_F_CAN_FD));

        assert_eq!(
            vu_can_backend.check_rx_frame(frame).unwrap_err(),
            Error::UnexpectedRtrFlag
        );
    }

    #[test]
    fn test_virtio_can_check_rx_can_frame() {
        let controller =
            CanController::new("can0".to_string()).expect("Could not build controller");
        let controller = Arc::new(RwLock::new(controller));
        let mut vu_can_backend =
            VhostUserCanBackend::new(controller.clone()).expect("Could not build vhucan device");

        // Test 1: UnexpectedClassicFlag
        let frame = VirtioCanFrame {
            msg_type: VIRTIO_CAN_TX.into(),
            can_id: 0.into(),
            length: 4.into(),
            reserved: 0.into(),
            flags: 0.into(),
            sdu: [0; 64],
        };

        assert_eq!(
            vu_can_backend.check_rx_frame(frame).unwrap_err(),
            Error::UnexpectedClassicFlag
        );

        // Test 2: Return the same length
        vu_can_backend.acked_features(1 << VIRTIO_CAN_F_CAN_CLASSIC);

        assert_eq!(
            vu_can_backend.check_tx_frame(frame).unwrap().length,
            frame.length
        );

        // Test 3: Return the length equal to 8
        let frame = VirtioCanFrame {
            msg_type: VIRTIO_CAN_TX.into(),
            can_id: 0.into(),
            length: 40.into(),
            reserved: 0.into(),
            flags: 0.into(),
            sdu: [0; 64],
        };

        assert_eq!(
            vu_can_backend.check_tx_frame(frame).unwrap_err(),
            Error::InvalidCanLength(40)
        );
    }

    #[test]
    fn test_virtio_can_check_rx_canfd_frame() {
        let controller =
            CanController::new("can0".to_string()).expect("Could not build controller");
        let controller = Arc::new(RwLock::new(controller));
        let mut vu_can_backend =
            VhostUserCanBackend::new(controller.clone()).expect("Could not build vhucan device");

        // Enable VIRTIO_CAN_F_CAN_FD feature
        vu_can_backend.acked_features(1 << VIRTIO_CAN_F_CAN_FD);

        // Test 1: If no CAN_FRMF_TYPE_FD in flags return UnexpectedClassicFlag
        let frame = VirtioCanFrame {
            msg_type: 0.into(),
            can_id: 0.into(),
            length: 40.into(),
            reserved: 0.into(),
            flags: 0.into(),
            sdu: [0; 64],
        };

        assert_eq!(
            vu_can_backend.check_rx_frame(frame).unwrap_err(),
            Error::UnexpectedClassicFlag
        );

        // Test 2: If VIRTIO_CAN_FLAGS_FD is in flag check if return message has
        //         VIRTIO_CAN_FLAGS_FD in flags.
        let frame = VirtioCanFrame {
            msg_type: 0.into(),
            can_id: 0.into(),
            length: 48.into(),
            reserved: 0.into(),
            flags: CAN_FRMF_TYPE_FD.into(),
            sdu: [0; 64],
        };

        assert_eq!(
            vu_can_backend
                .check_rx_frame(frame)
                .unwrap()
                .flags
                .to_native()
                & VIRTIO_CAN_FLAGS_FD,
            VIRTIO_CAN_FLAGS_FD
        );

        // Test 3: receive frame with the same length if length is < 64
        assert_eq!(
            vu_can_backend.check_rx_frame(frame).unwrap().length,
            frame.length
        );

        // Test 4: receive frame with length out-of-range: length is > 64
        let frame = VirtioCanFrame {
            msg_type: 0.into(),
            can_id: 0.into(),
            length: 80.into(),
            reserved: 0.into(),
            flags: CAN_FRMF_TYPE_FD.into(),
            sdu: [0; 64],
        };

        assert_eq!(
            vu_can_backend.check_rx_frame(frame).unwrap_err(),
            Error::InvalidCanLength(80)
        );

        // Test 5: receive frame with length out-of-range: length no in
        //         list: [12, 16, 20, 24, 32, 48, 64]
        let frame = VirtioCanFrame {
            msg_type: 0.into(),
            can_id: 0.into(),
            length: 62.into(),
            reserved: 0.into(),
            flags: CAN_FRMF_TYPE_FD.into(),
            sdu: [0; 64],
        };

        assert_eq!(
            vu_can_backend.check_rx_frame(frame).unwrap_err(),
            Error::InvalidCanLength(62)
        );
    }

    #[test]
    fn test_virtio_can_check_rx_canfd_vcan0() {
        let controller =
            CanController::new("vcan0".to_string()).expect("Could not build controller");
        let controller = Arc::new(RwLock::new(controller));
        let mut vu_can_backend =
            VhostUserCanBackend::new(controller.clone()).expect("Could not build vhucan device");

        // Enable VIRTIO_CAN_F_CAN_FD feature
        vu_can_backend.acked_features((1 << VIRTIO_CAN_F_CAN_FD) | (1 << VIRTIO_CAN_F_CAN_CLASSIC));

        // If VIRTIO_CAN_F_CAN_FD  and VIRTIO_CAN_F_CAN_CLASSIC are negotiated
        // and interface is "vcan0" check if return message has
        // VIRTIO_CAN_FLAGS_FD in flags and has been treated as CANFD frame.
        let frame = VirtioCanFrame {
            msg_type: 0.into(),
            can_id: 0.into(),
            length: 48.into(),
            reserved: 0.into(),
            flags: 0.into(),
            sdu: [0; 64],
        };

        assert_eq!(
            vu_can_backend
                .check_rx_frame(frame)
                .unwrap()
                .flags
                .to_native()
                & VIRTIO_CAN_FLAGS_FD,
            VIRTIO_CAN_FLAGS_FD
        );

        assert_eq!(
            vu_can_backend.check_rx_frame(frame).unwrap().length,
            frame.length
        );
    }

    #[test]
    fn test_virtio_can_rx_request() {
        let controller =
            CanController::new("can0".to_string()).expect("Could not build controller");
        let controller = Arc::new(RwLock::new(controller));
        let mut vu_can_backend =
            VhostUserCanBackend::new(controller.clone()).expect("Could not build vhucan device");
        let mem = GuestMemoryMmap::<()>::from_ranges(&[(GuestAddress(0), 0x1000)]).unwrap();

        // Note: The following test are focusing only to simple CAN messages.

        // Test 1: This should succeed because there is no element inserted in the
        //         CAN/FD frames' queue
        let desc_chain = build_desc_chain_mem(&mem, 1, vec![VRING_DESC_F_WRITE as u16], 0x200);
        let mem1 = GuestMemoryAtomic::new(mem.clone());
        let vring = VringRwLock::new(mem1.clone(), 0x1000).unwrap();
        vu_can_backend.update_memory(mem1).unwrap();
        assert!(!vu_can_backend
            .process_rx_requests(vec![desc_chain], &vring)
            .unwrap(),);

        // Test 2: This should fail because there is a simple CAN frame
        //         inserted in the CAN/FD frames' queue, but this does not
        //         pass the checks.

        // Push a new can message into the can.rs queue
        let frame = VirtioCanFrame {
            msg_type: 0.into(),
            can_id: 123.into(),
            length: 64.into(),
            reserved: 0.into(),
            flags: 0.into(),
            sdu: [0; 64],
        };

        controller.write().unwrap().push(frame).unwrap();

        let desc_chain = build_desc_chain_mem(&mem, 1, vec![VRING_DESC_F_WRITE as u16], 0x200);
        let mem1 = GuestMemoryAtomic::new(mem.clone());
        let vring = VringRwLock::new(mem1.clone(), 0x1000).unwrap();
        vu_can_backend.update_memory(mem1).unwrap();
        assert_eq!(
            vu_can_backend
                .process_rx_requests(vec![desc_chain], &vring)
                .unwrap_err(),
            Error::UnexpectedClassicFlag
        );

        // Test 3: This should succeed because there is a simple CAN frame
        //         inserted in the CAN/FD frames' queue, and this does
        //         pass the checks.

        // Enable VIRTIO_CAN_F_CAN_CLASSIC feature
        vu_can_backend.acked_features(1 << VIRTIO_CAN_F_CAN_CLASSIC);

        // Push a new can message into the can.rs queue
        let frame = VirtioCanFrame {
            msg_type: 0.into(),
            can_id: 123.into(),
            length: 8.into(),
            reserved: 0.into(),
            flags: 0.into(),
            sdu: [0; 64],
        };

        controller.write().unwrap().push(frame).unwrap();

        let desc_chain = build_desc_chain_mem(&mem, 1, vec![VRING_DESC_F_WRITE as u16], 0x200);
        let mem1 = GuestMemoryAtomic::new(mem.clone());
        let vring = VringRwLock::new(mem1.clone(), 0x1000).unwrap();
        vu_can_backend.update_memory(mem1).unwrap();
        assert!(vu_can_backend
            .process_rx_requests(vec![desc_chain], &vring)
            .unwrap());

        // Test 4: This should fail because the descriptor is read-only
        let desc_chain = build_desc_chain_mem(&mem, 1, vec![0], 0x200);
        let mem1 = GuestMemoryAtomic::new(mem.clone());
        let vring = VringRwLock::new(mem1.clone(), 0x1000).unwrap();
        vu_can_backend.update_memory(mem1).unwrap();

        // Push a new can message into the can.rs queue
        let frame = VirtioCanFrame {
            msg_type: 0.into(),
            can_id: 123.into(),
            length: 8.into(),
            reserved: 0.into(),
            flags: 0.into(),
            sdu: [0; 64],
        };
        controller.write().unwrap().push(frame).unwrap();

        assert_eq!(
            vu_can_backend
                .process_rx_requests(vec![desc_chain.clone()], &vring)
                .unwrap_err(),
            Error::DescriptorWriteFailed
        );

        // Test 5: This should fail because the descriptor length is less
        //         than VirtioCanFrame size.
        let desc_chain = build_desc_chain_mem(&mem, 1, vec![VRING_DESC_F_WRITE as u16], 0x10);
        let mem1 = GuestMemoryAtomic::new(mem.clone());
        let vring = VringRwLock::new(mem1.clone(), 0x1000).unwrap();
        vu_can_backend.update_memory(mem1).unwrap();

        // Push a new can message into the can.rs queue
        let frame = VirtioCanFrame {
            msg_type: 0.into(),
            can_id: 123.into(),
            length: 8.into(),
            reserved: 0.into(),
            flags: 0.into(),
            sdu: [0; 64],
        };
        controller.write().unwrap().push(frame).unwrap();

        assert_eq!(
            vu_can_backend
                .process_rx_requests(vec![desc_chain.clone()], &vring)
                .unwrap_err(),
            Error::DescriptorWriteFailed
        );
    }
}
