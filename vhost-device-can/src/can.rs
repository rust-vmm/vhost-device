// CAN backend device
//
// Copyright 2023-2024 VIRTUAL OPEN SYSTEMS SAS. All Rights Reserved.
//          Timos Ampelikiotis <t.ampelikiotis@virtualopensystems.com>
//
// SPDX-License-Identifier: Apache-2.0 or BSD-3-Clause

use log::{error, info, trace, warn};
use std::sync::{Arc, RwLock};

use std::thread::{spawn, JoinHandle};
use thiserror::Error as ThisError;
use vmm_sys_util::eventfd::{EventFd, EFD_NONBLOCK};
extern crate queues;
use queues::*;
extern crate socketcan;
use crate::virtio_can::{
    VirtioCanConfig, VirtioCanFrame, CAN_CS_STARTED, CAN_CS_STOPPED, CAN_EFF_FLAG,
    CAN_FRMF_TYPE_FD, VIRTIO_CAN_RX,
};
use socketcan::{
    CanAnyFrame, CanDataFrame, CanFdFrame, CanFdSocket, EmbeddedFrame, ExtendedId, Frame, Id,
    Socket, StandardId,
};

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

#[derive(Debug)]
pub(crate) struct CanController {
    pub config: VirtioCanConfig,
    pub can_name: String,
    pub can_socket: Option<CanFdSocket>,
    pub rx_event_fd: EventFd,
    rx_fifo: Queue<VirtioCanFrame>,
    pub status: bool,
    pub ctrl_state: u8,
}

impl CanController {
    // Creates a new controller corresponding to `device`.
    pub(crate) fn new(can_name: String) -> Result<CanController> {
        let can_name = can_name.to_owned();
        info!("can_name: {:?}", can_name);

        let rx_fifo = Queue::new();
        let rx_efd = EventFd::new(EFD_NONBLOCK).map_err(|_| Error::EventFdFailed)?;

        Ok(CanController {
            config: VirtioCanConfig { status: 0x0.into() },
            can_name,
            can_socket: None,
            rx_event_fd: rx_efd,
            rx_fifo,
            status: true,
            ctrl_state: CAN_CS_STOPPED,
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

    pub fn open_can_socket(&mut self) -> Result<()> {
        self.can_socket = match CanFdSocket::open(&self.can_name) {
            Ok(socket) => Some(socket),
            Err(_) => {
                warn!("Error opening CAN socket");
                return Err(Error::SocketOpen);
            }
        };
        Ok(())
    }

    // Helper function to process frame
    fn process_frame<F: Frame>(frame: F, is_fd: bool) -> VirtioCanFrame {
        VirtioCanFrame {
            msg_type: VIRTIO_CAN_RX.into(),
            can_id: frame.id_word().into(),
            length: (frame.data().len() as u16).into(),
            reserved: 0.into(),
            flags: if is_fd {
                CAN_FRMF_TYPE_FD.into()
            } else {
                0.into()
            },
            sdu: {
                let mut sdu_data: [u8; 64] = [0; 64];
                sdu_data[..frame.data().len()].copy_from_slice(frame.data());
                sdu_data
            },
        }
    }

    pub fn read_can_socket(controller: Arc<RwLock<CanController>>) -> Result<()> {
        let can_name = &controller.read().unwrap().can_name.clone();
        dbg!("Start reading from {} socket!", &can_name);
        let socket = match CanFdSocket::open(can_name) {
            Ok(socket) => socket,
            Err(_) => {
                warn!("Error opening CAN socket");
                return Err(Error::SocketOpen);
            }
        };

        // Set non-blocking otherwise the device will not restart immediatelly
        // when the VM closes, and a new canfd message needs to be received for
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

                // Match and process frame variants
                let read_can_frame = match frame {
                    CanAnyFrame::Normal(frame) => {
                        trace!("Received CAN frame: {:?}", frame);
                        Self::process_frame(frame, false)
                    }
                    CanAnyFrame::Fd(frame) => {
                        trace!("Received CAN FD frame: {:?}", frame);
                        Self::process_frame(frame, true)
                    }
                    CanAnyFrame::Remote(frame) => {
                        trace!("Received Remote CAN frame: {:?}", frame);
                        Self::process_frame(frame, false)
                    }
                    CanAnyFrame::Error(frame) => {
                        trace!("Received Error frame: {:?}", frame);
                        Self::process_frame(frame, false)
                    }
                };

                match controller.write().unwrap().push(read_can_frame) {
                    Ok(_) => warn!("New Can frame was received"),
                    Err(_) => {
                        warn!("Error read/push CAN frame");
                        return Err(Error::SocketRead);
                    }
                };

                controller
                    .write()
                    .unwrap()
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
        &self.config
    }

    pub(crate) fn can_out(&self, tx_request: VirtioCanFrame) -> Result<()> {
        // Create a CAN frame with a specific CAN-ID and the data buffer
        let can_id: Id = if (tx_request.can_id.to_native() & CAN_EFF_FLAG) != 0 {
            // SAFETY: Use new_unchecked cause checks have been taken place
            // to prior stage. Also flags have beem already added on can_id
            // so tnew will fail (can_id + can_flags) > 29 bits
            unsafe { Id::Extended(ExtendedId::new_unchecked(tx_request.can_id.into())) }
        } else {
            // SAFETY: Use new_unchecked cause checks have been taken place
            // to prior stage. Also flags have beem already added on can_id
            // so tnew will fail (can_id + can_flags) > 11 bits
            unsafe {
                Id::Standard(StandardId::new_unchecked(
                    tx_request.can_id.to_native() as u16
                ))
            }
        };

        // Grab the data to be tranfered
        let data_len = tx_request.length.to_native() as usize;
        let data: Vec<u8> = tx_request.sdu.iter().cloned().take(data_len).collect();

        // Format CAN/FD frame
        let frame: CanAnyFrame = if (tx_request.flags.to_native() & CAN_FRMF_TYPE_FD) != 0 {
            CanAnyFrame::Fd(CanFdFrame::new(can_id, &data).expect("Fail to create CanFdFrame"))
        } else {
            CanAnyFrame::Normal(CanDataFrame::new(can_id, &data).expect("Fail to create CanFrame"))
        };

        // Send the CAN/FD frame
        let socket = self.can_socket.as_ref().ok_or("No available device");

        match socket {
            Ok(socket) => match socket.write_frame(&frame) {
                Ok(_) => Ok(()),
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
        let can_name = "can".to_string();

        let controller = CanController::new(can_name.clone()).unwrap();
        assert_eq!(controller.can_name, can_name);
    }

    #[test]
    fn test_can_controller_push_and_pop() {
        let can_name = "can".to_string();
        let mut controller = CanController::new(can_name.clone()).unwrap();

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
        let can_name = "can".to_string();
        let mut controller = CanController::new(can_name.clone()).unwrap();

        // Test config
        let config = controller.config();
        assert_eq!(config.status.to_native(), 0);
    }

    #[test]
    fn test_can_controller_operation() {
        let can_name = "can".to_string();
        let mut controller = CanController::new(can_name.clone()).unwrap();

        let frame = VirtioCanFrame {
            msg_type: VIRTIO_CAN_RX.into(),
            can_id: 123.into(),
            length: 64.into(),
            reserved: 0.into(),
            flags: 0.into(),
            sdu: [0; 64],
        };

        match controller.open_can_socket() {
            Ok(_) => {
                // Test operation
                let operation_result = controller.can_out(frame);
                assert!(operation_result.is_ok());
            }
            Err(_) => warn!("There is no CAN interface with {} name", can_name),
        }
    }

    #[test]
    fn test_can_controller_start_read_thread() {
        let can_name = "can".to_string();
        let controller = CanController::new(can_name.clone()).unwrap();
        let arc_controller = Arc::new(RwLock::new(controller));

        // Test start_read_thread
        let thread_handle = CanController::start_read_thread(arc_controller.clone());
        assert!(thread_handle.join().is_ok());
    }

    #[test]
    fn test_can_open_socket_fail() {
        let controller =
            CanController::new("can0".to_string()).expect("Could not build controller");
        let controller = Arc::new(RwLock::new(controller));
        VhostUserCanBackend::new(controller.clone()).expect("Could not build vhucan device");

        assert_eq!(
            controller.write().unwrap().open_can_socket(),
            Err(Error::SocketOpen)
        );
    }

    #[test]
    fn test_can_read_socket_fail() {
        let controller =
            CanController::new("can0".to_string()).expect("Could not build controller");
        let controller = Arc::new(RwLock::new(controller));
        VhostUserCanBackend::new(controller.clone()).expect("Could not build vhucan device");

        assert_eq!(
            CanController::read_can_socket(controller),
            Err(Error::SocketOpen)
        );
    }
}
