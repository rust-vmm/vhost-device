// CAN backend device
//
// Copyright 2023-2024 VIRTUAL OPEN SYSTEMS SAS. All Rights Reserved.
//          Timos Ampelikiotis <t.ampelikiotis@virtualopensystems.com>
//
// SPDX-License-Identifier: Apache-2.0 or BSD-3-Clause

use log::{error, info, trace, warn};
use std::sync::{Arc, RwLock};

use thiserror::Error as ThisError;
use vm_memory::{ByteValued, Le16};

extern crate socketcan;
use socketcan::{CanAnyFrame, CanFdFrame, CanFdSocket, EmbeddedFrame, Frame, Socket, StandardId};

use std::thread::{spawn, JoinHandle};
use vmm_sys_util::eventfd::{EventFd, EFD_NONBLOCK};

extern crate queues;
use queues::*;

use crate::vhu_can::{VirtioCanFrame, VIRTIO_CAN_RESULT_OK, VIRTIO_CAN_S_CTRL_BUSOFF};

type Result<T> = std::result::Result<T, Error>;

#[derive(Copy, Clone, Debug, PartialEq, ThisError)]
/// Errors related to low level can helpers
pub(crate) enum Error {
    #[error("Can open socket operation failed")]
    SocketOpen,
    #[error("Can write socket operation failed")]
    SocketWrite,
    #[error("Can read socket operation failed")]
    SocketRead,
    #[error("Pop can element operation failed")]
    PopFailed,
    #[error("Queue is empty")]
    QueueEmpty,
    #[error("Creating Eventfd for CAN events failed")]
    EventFdFailed,
    #[error("Push can element operation failed")]
    PushFailed,
    #[error("No output interface available")]
    NoOutputInterface,
}

/* CAN flags to determine type of CAN Id */
pub(crate) const VIRTIO_CAN_FLAGS_EXTENDED: u32 = 0x8000;
pub(crate) const VIRTIO_CAN_FLAGS_FD: u32 = 0x4000;
pub(crate) const VIRTIO_CAN_FLAGS_RTR: u32 = 0x2000;

pub(crate) const VIRTIO_CAN_TX: u16 = 0x0001;
pub(crate) const VIRTIO_CAN_RX: u16 = 0x0101;

pub(crate) const CAN_EFF_FLAG: u32 = 0x80000000; /* EFF/SFF is set in the MSB */
pub(crate) const CAN_RTR_FLAG: u32 = 0x40000000; /* remote transmission request */
pub(crate) const CAN_ERR_FLAG: u32 = 0x20000000; /* error message frame */

pub(crate) const CAN_SFF_MASK: u32 = 0x000007FF; /* standard frame format (SFF) */
pub(crate) const CAN_EFF_MASK: u32 = 0x1FFFFFFF; /* extended frame format (EFF) */

#[allow(dead_code)]
pub(crate) const CAN_FRMF_BRS: u32 = 0x01; /* bit rate switch (2nd bitrate for data) */
#[allow(dead_code)]
pub(crate) const CAN_FRMF_ESI: u32 = 0x02; /* error state ind. of transmitting node */
pub(crate) const CAN_FRMF_TYPE_FD: u32 = 0x10; /* internal bit ind. of CAN FD frame */
pub(crate) const CAN_ERR_BUSOFF: u32 = 0x00000040; /* bus off */

/* CAN controller states */
pub(crate) const CAN_CS_UNINIT: u8 = 0x00;
pub(crate) const CAN_CS_STARTED: u8 = 0x01;
pub(crate) const CAN_CS_STOPPED: u8 = 0x02;

/// Virtio Can Configuration
#[derive(Copy, Clone, Debug, Default, PartialEq)]
#[repr(C)]
pub(crate) struct VirtioCanConfig {
    /* CAN controller status */
    pub(crate) status: Le16,
}

// SAFETY: The layout of the structure is fixed and can be initialized by
// reading its content from byte array.
unsafe impl ByteValued for VirtioCanConfig {}

#[derive(Debug)]
pub(crate) struct CanController {
    config: VirtioCanConfig,
    pub can_in_name: String,
    #[allow(unused)]
    can_out_name: String,
    can_out_socket: Option<CanFdSocket>,
    pub rx_event_fd: EventFd,
    rx_fifo: Queue<VirtioCanFrame>,
    pub status: bool,
    pub busoff: bool,
    pub ctrl_state: u8,
}

impl CanController {
    // Creates a new controller corresponding to `device`.
    pub(crate) fn new(can_in_name: String, can_out_name: String) -> Result<CanController> {
        let can_in_name = can_in_name.to_owned();
        info!("can_in_name: {:?}", can_in_name);

        let can_out_name = can_out_name.to_owned();
        info!("can_out_name: {:?}", can_out_name);

        let rx_fifo = Queue::new();
        let rx_efd = EventFd::new(EFD_NONBLOCK).map_err(|_| Error::EventFdFailed)?;

        Ok(CanController {
            config: VirtioCanConfig { status: 0x0.into() },
            can_in_name,
            can_out_name,
            can_out_socket: None,
            rx_event_fd: rx_efd,
            rx_fifo,
            status: true,
            busoff: false,
            ctrl_state: CAN_CS_UNINIT,
        })
    }

    pub fn print_can_frame(canframe: VirtioCanFrame) {
        trace!("canframe.msg_type 0x{:x}", canframe.msg_type.to_native());
        trace!("canframe.can_id 0x{:x}", canframe.can_id.to_native());
        trace!("canframe.length {}", canframe.length.to_native());
        trace!("canframe.flags 0x{:x}", canframe.flags.to_native());
        if canframe.length.to_native() == 0 {
            trace!("[]");
            return;
        }
        trace!("[");
        let last_elem = canframe.length.to_native() as usize - 1;
        for (index, sdu) in canframe.sdu.iter().enumerate() {
            if index == last_elem {
                trace!("0x{:x}", sdu);
                break;
            }
            trace!("0x{:x}, ", sdu);
        }
        trace!("]");
    }

    pub fn start_read_thread(controller: Arc<RwLock<CanController>>) -> JoinHandle<Result<()>> {
        spawn(move || CanController::read_can_socket(controller))
    }

    pub fn push(&mut self, rx_elem: VirtioCanFrame) -> Result<()> {
        match self.rx_fifo.add(rx_elem) {
            Ok(_) => Ok(()),
            _ => Err(Error::PushFailed),
        }
    }

    pub fn rx_is_empty(&mut self) -> bool {
        self.rx_fifo.size() == 0
    }

    pub fn pop(&mut self) -> Result<VirtioCanFrame> {
        if self.rx_fifo.size() < 1 {
            return Err(Error::QueueEmpty);
        }

        match self.rx_fifo.remove() {
            Ok(item) => Ok(item),
            _ => Err(Error::PopFailed),
        }
    }

    pub fn open_can_out_socket(&mut self) -> Result<()> {
        self.can_out_socket = match CanFdSocket::open(&self.can_out_name) {
            Ok(socket) => Some(socket),
            Err(_) => {
                warn!("Error opening CAN socket");
                return Err(Error::SocketOpen);
            }
        };
        Ok(())
    }

    pub fn read_can_socket(controller: Arc<RwLock<CanController>>) -> Result<()> {
        let can_in_name = &controller.read().unwrap().can_in_name.clone();
        dbg!("Start reading from {} socket!", &can_in_name);
        let socket = match CanFdSocket::open(can_in_name) {
            Ok(socket) => socket,
            Err(_) => {
                warn!("Error opening CAN socket");
                return Err(Error::SocketOpen);
            }
        };

        // Set non-blocking otherwise the device will not restart immediatelly
        // when the VM closes, and a new canfd messages needs to be received for
        // restart to happen.
        // This caused by the fact that the thread is stacked in read function
        // and does not go to the next loop to check the status condition.
        socket
            .set_nonblocking(true)
            .expect("Cannot set nonblocking");

        // Receive CAN messages
        loop {
            // If the status variable is false then break and exit.
            if !controller.read().unwrap().status {
                dbg!("exit read can thread");
                return Ok(());
            }

            if let Ok(frame) = socket.read_frame() {
                // If ctrl_state is stopped, consume the received CAN/FD frame
                // and loop till the ctrl_state changes to started or the thread
                // to exit.
                if controller.read().unwrap().ctrl_state != CAN_CS_STARTED {
                    trace!("CAN/FD frame is received but not saved!");
                    continue;
                }

                let mut controller = controller.write().unwrap();
                match frame {
                    CanAnyFrame::Normal(frame) => {
                        // Regular CAN frame
                        trace!("Received CAN message: {:?}", frame);

                        let read_can_frame = VirtioCanFrame {
                            msg_type: VIRTIO_CAN_RX.into(),
                            can_id: frame.raw_id().into(),
                            length: (frame.data().len() as u16).into(),
                            reserved: 0.into(),
                            flags: frame.id_flags().bits().into(),
                            sdu: {
                                let mut sdu_data: [u8; 64] = [0; 64];
                                sdu_data[..frame.data().len()].copy_from_slice(frame.data());
                                sdu_data
                            },
                        };

                        match controller.push(read_can_frame) {
                            Ok(_) => warn!("New Can frame was received"),
                            Err(_) => {
                                warn!("Error read/push CAN frame");
                                return Err(Error::SocketRead);
                            }
                        }
                    }
                    CanAnyFrame::Fd(frame) => {
                        // CAN FD frame
                        trace!("Received CAN FD message: {:?}", frame);

                        let read_can_frame = VirtioCanFrame {
                            msg_type: VIRTIO_CAN_RX.into(),
                            can_id: frame.raw_id().into(),
                            length: (frame.data().len() as u16).into(),
                            reserved: 0.into(),
                            flags: frame.id_flags().bits().into(),
                            sdu: {
                                let mut sdu_data: [u8; 64] = [0; 64];
                                sdu_data[..frame.data().len()].copy_from_slice(frame.data());
                                sdu_data
                            },
                        };

                        match controller.push(read_can_frame) {
                            Ok(_) => warn!("New Can frame was received"),
                            Err(_) => {
                                warn!("Error read/push CAN frame");
                                return Err(Error::SocketRead);
                            }
                        }
                    }
                    CanAnyFrame::Remote(frame) => {
                        // Remote CAN frame
                        trace!("Received Remote CAN message: {:?}", frame);
                    }
                    CanAnyFrame::Error(frame) => {
                        // Error frame
                        trace!("Received Error frame: {:?}", frame);
                    }
                }

                controller
                    .rx_event_fd
                    .write(1)
                    .expect("Fail to write on rx_event_fd");
            }
        }
    }

    pub(crate) fn exit_read_thread(&mut self) {
        trace!("Exit can read thread\n");
        self.status = false;
    }

    pub(crate) fn config(&mut self) -> &VirtioCanConfig {
        trace!("Get config\n");
        if self.busoff {
            self.config.status = VIRTIO_CAN_S_CTRL_BUSOFF.into();
        }
        &self.config
    }

    pub(crate) fn can_out(&self, tx_request: VirtioCanFrame) -> Result<u8> {
        trace!("Can out\n");

        // Create a CAN frame with a specific CAN-ID and the data buffer
        let can_id = StandardId::new(tx_request.can_id.to_native().try_into().unwrap())
            .expect("Fail to create StandardId");
        let data_len = tx_request.length.to_native() as usize;

        let data: Vec<u8> = tx_request.sdu.iter().cloned().take(data_len).collect();
        let frame = CanFdFrame::new(can_id, &data).expect("Fail to create CanFdFrame");

        // Send the CAN frame
        let socket = self.can_out_socket.as_ref().ok_or("No available device");

        match socket {
            Ok(socket) => match socket.write_frame(&frame) {
                Ok(_) => Ok(VIRTIO_CAN_RESULT_OK),
                Err(_) => {
                    warn!("Error write CAN socket");
                    Err(Error::SocketWrite)
                }
            },
            Err(_) => Err(Error::NoOutputInterface),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vhu_can::VhostUserCanBackend;
    use std::sync::{Arc, RwLock};

    #[test]
    fn test_can_controller_creation() {
        let can_in_name = "can_in".to_string();
        let can_out_name = "can_out".to_string();

        let controller = CanController::new(can_in_name.clone(), can_out_name.clone()).unwrap();
        assert_eq!(controller.can_in_name, can_in_name);
        assert_eq!(controller.can_out_name, can_out_name);
    }

    #[test]
    fn test_can_controller_push_and_pop() {
        let can_in_name = "can_in".to_string();
        let can_out_name = "can_out".to_string();
        let mut controller = CanController::new(can_in_name.clone(), can_out_name.clone()).unwrap();

        let frame = VirtioCanFrame {
            msg_type: VIRTIO_CAN_RX.into(),
            can_id: 123.into(),
            length: 64.into(),
            reserved: 0.into(),
            flags: 0.into(),
            sdu: [0; 64],
        };

        // Test push
        controller.push(frame).unwrap();

        // Test pop
        let pop_result = controller.pop().unwrap();
        assert_eq!(pop_result, frame);
    }

    #[test]
    fn test_can_controller_config() {
        let can_in_name = "can_in".to_string();
        let can_out_name = "can_out".to_string();
        let mut controller = CanController::new(can_in_name.clone(), can_out_name.clone()).unwrap();

        // Test config
        let config = controller.config();
        assert_eq!(config.status.to_native(), 0);
    }

    #[test]
    fn test_can_controller_operation() {
        let can_in_name = "can_in".to_string();
        let can_out_name = "can_out".to_string();
        let mut controller = CanController::new(can_in_name.clone(), can_out_name.clone()).unwrap();

        let frame = VirtioCanFrame {
            msg_type: VIRTIO_CAN_RX.into(),
            can_id: 123.into(),
            length: 64.into(),
            reserved: 0.into(),
            flags: 0.into(),
            sdu: [0; 64],
        };

        match controller.open_can_out_socket() {
            Ok(_) => {
                // Test operation
                let operation_result = controller.can_out(frame).unwrap();
                assert_eq!(operation_result, VIRTIO_CAN_RESULT_OK);
            }
            Err(_) => warn!("There is no CAN interface with {} name", can_out_name),
        }
    }

    #[test]
    fn test_can_controller_start_read_thread() {
        let can_in_name = "can_in".to_string();
        let can_out_name = "can_out".to_string();
        let controller = CanController::new(can_in_name.clone(), can_out_name.clone()).unwrap();
        let arc_controller = Arc::new(RwLock::new(controller));

        // Test start_read_thread
        let thread_handle = CanController::start_read_thread(arc_controller.clone());
        assert!(thread_handle.join().is_ok());
    }

    #[test]
    fn test_can_open_socket_fail() {
        let controller = CanController::new("can0".to_string(), "can1".to_string())
            .expect("Could not build controller");
        let controller = Arc::new(RwLock::new(controller));
        VhostUserCanBackend::new(controller.clone()).expect("Could not build vhucan device");

        assert_eq!(
            controller.write().unwrap().open_can_out_socket(),
            Err(Error::SocketOpen)
        );
    }

    #[test]
    fn test_can_read_socket_fail() {
        let controller = CanController::new("can0".to_string(), "can1".to_string())
            .expect("Could not build controller");
        let controller = Arc::new(RwLock::new(controller));
        VhostUserCanBackend::new(controller.clone()).expect("Could not build vhucan device");

        assert_eq!(
            CanController::read_can_socket(controller),
            Err(Error::SocketOpen)
        );
    }
}
