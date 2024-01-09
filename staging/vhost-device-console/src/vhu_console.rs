// vhost device console
//
// Copyright 2023-2024 VIRTUAL OPEN SYSTEMS SAS. All Rights Reserved.
//          Timos Ampelikiotis <t.ampelikiotis@virtualopensystems.com>
//
// SPDX-License-Identifier: Apache-2.0 or BSD-3-Clause

use crate::console::{BackendType, ConsoleController};
use console::Key;
use crossterm::terminal::{disable_raw_mode, enable_raw_mode};
use log::{error, trace, warn};
use nix::sys::select::{select, FdSet};
use std::mem::size_of;
use std::os::fd::AsRawFd;
use std::slice::from_raw_parts;
use std::sync::{Arc, RwLock};
use std::thread::JoinHandle;
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
    ByteValued, Bytes, GuestAddressSpace, GuestMemoryAtomic, GuestMemoryLoadGuard, GuestMemoryMmap,
    Le16, Le32,
};
use vmm_sys_util::epoll::EventSet;
use vmm_sys_util::eventfd::{EventFd, EFD_NONBLOCK};

use console::Term;
use queues::{IsQueue, Queue};
use std::io::Read;
use std::net::TcpListener;
use std::thread::spawn;

/// Feature bit numbers
#[allow(dead_code)]
pub const VIRTIO_CONSOLE_F_SIZE: u16 = 0;
#[allow(dead_code)]
pub const VIRTIO_CONSOLE_F_MULTIPORT: u16 = 1;
pub const VIRTIO_CONSOLE_F_EMERG_WRITE: u16 = 2;

/// Virtio configuration
const QUEUE_SIZE: usize = 128;
const NUM_QUEUES: usize = 4;

/// Queue events
const RX_QUEUE: u16 = 0;
const TX_QUEUE: u16 = 1;
const CTRL_RX_QUEUE: u16 = 2;
const CTRL_TX_QUEUE: u16 = 3;

/// The two following events are used to help the vhu_console
/// backend trigger events to itself. For example:
/// a) BACKEND_RX_EFD is being triggered when the backend
///    has new data to send to the RX queue.
/// b) BACKEND_CTRL_RX_EFD event is used when the backend
///    needs to write to the RX control queue.
const BACKEND_RX_EFD: u16 = (NUM_QUEUES + 1) as u16;
const BACKEND_CTRL_RX_EFD: u16 = (NUM_QUEUES + 2) as u16;

/// Console virtio control messages
const VIRTIO_CONSOLE_DEVICE_READY: u16 = 0;
const VIRTIO_CONSOLE_PORT_ADD: u16 = 1;
#[allow(dead_code)]
const VIRTIO_CONSOLE_PORT_REMOVE: u16 = 2;
const VIRTIO_CONSOLE_PORT_READY: u16 = 3;
const VIRTIO_CONSOLE_CONSOLE_PORT: u16 = 4;
#[allow(dead_code)]
const VIRTIO_CONSOLE_RESIZE: u16 = 5;
const VIRTIO_CONSOLE_PORT_OPEN: u16 = 6;
const VIRTIO_CONSOLE_PORT_NAME: u16 = 7;

type Result<T> = std::result::Result<T, Error>;

#[derive(Copy, Clone, Debug, PartialEq, ThisError)]
pub(crate) enum Error {
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
    #[error("Failed to send notification")]
    NotificationFailed,
    #[error("Descriptor read failed")]
    DescriptorReadFailed,
    #[error("Descriptor write failed")]
    DescriptorWriteFailed,
    #[error("Failed to create new EventFd")]
    EventFdFailed,
}

impl convert::From<Error> for io::Error {
    fn from(e: Error) -> Self {
        io::Error::new(io::ErrorKind::Other, e)
    }
}

/// Virtio Console Config
#[derive(Copy, Clone, Debug, Default, PartialEq)]
#[repr(C)]
pub(crate) struct VirtioConsoleConfig {
    pub cols: Le16,
    pub rows: Le16,
    pub max_nr_ports: Le32,
    pub emerg_wr: Le32,
}

// SAFETY: The layout of the structure is fixed and can be initialized by
// reading its content from byte array.
unsafe impl ByteValued for VirtioConsoleConfig {}

#[derive(Copy, Clone, Debug, Default, PartialEq)]
#[repr(C)]
pub(crate) struct VirtioConsoleControl {
    pub id: Le32,
    pub event: Le16,
    pub value: Le16,
}

use std::io::Write;

impl VirtioConsoleControl {
    fn to_le_bytes(self) -> Vec<u8> {
        let mut buffer = Vec::new();

        buffer.extend_from_slice(&self.id.to_native().to_le_bytes());
        buffer.extend_from_slice(&self.event.to_native().to_le_bytes());
        buffer.extend_from_slice(&self.value.to_native().to_le_bytes());
        buffer
    }
}

// SAFETY: The layout of the structure is fixed and can be initialized by
// reading its content from byte array.
unsafe impl ByteValued for VirtioConsoleControl {}

pub(crate) struct VhostUserConsoleBackend {
    controller: Arc<RwLock<ConsoleController>>,
    acked_features: u64,
    event_idx: bool,
    rx_ctrl_fifo: Queue<VirtioConsoleControl>,
    rx_data_fifo: Queue<String>,
    pub(crate) ready: bool,
    pub(crate) ready_to_write: bool,
    pub(crate) output_buffer: String,
    pub(crate) output_flag: bool,
    pub(crate) rx_event: EventFd,
    pub(crate) rx_ctrl_event: EventFd,
    pub(crate) exit_event: EventFd,
    mem: Option<GuestMemoryAtomic<GuestMemoryMmap>>,
}

type ConsoleDescriptorChain = DescriptorChain<GuestMemoryLoadGuard<GuestMemoryMmap<()>>>;

impl VhostUserConsoleBackend {
    pub(crate) fn new(controller: Arc<RwLock<ConsoleController>>) -> Result<Self> {
        Ok(VhostUserConsoleBackend {
            controller,
            event_idx: false,
            rx_ctrl_fifo: Queue::new(),
            rx_data_fifo: Queue::new(),
            acked_features: 0x0,
            ready: false,
            ready_to_write: false,
            output_buffer: String::new(),
            output_flag: false,
            rx_event: EventFd::new(EFD_NONBLOCK).map_err(|_| Error::EventFdFailed)?,
            rx_ctrl_event: EventFd::new(EFD_NONBLOCK).map_err(|_| Error::EventFdFailed)?,
            exit_event: EventFd::new(EFD_NONBLOCK).map_err(|_| Error::EventFdFailed)?,
            mem: None,
        })
    }

    fn print_console_frame(&self, control_msg: VirtioConsoleControl) {
        trace!("id 0x{:x}", control_msg.id.to_native());
        trace!("event 0x{:x}", control_msg.event.to_native());
        trace!("value 0x{:x}", control_msg.value.to_native());
    }

    fn process_rx_requests(
        &mut self,
        requests: Vec<ConsoleDescriptorChain>,
        vring: &VringRwLock,
    ) -> Result<bool> {
        trace!("process_rx_requests");

        if requests.is_empty() {
            trace!("requests.is_empty");
            return Ok(true);
        }

        let desc_chain = &requests[0];
        let descriptors: Vec<_> = desc_chain.clone().collect();

        if descriptors.len() != 1 {
            return Err(Error::UnexpectedDescriptorCount(descriptors.len()));
        }

        let desc_request = descriptors[0];
        if !desc_request.is_write_only() {
            return Err(Error::UnexpectedReadableDescriptor(0));
        }

        let response: String = match self.rx_data_fifo.remove() {
            Ok(item) => item,
            _ => {
                trace!("No rx elements");
                return Ok(false);
            }
        };

        desc_chain
            .memory()
            .write_slice(response.as_bytes(), desc_request.addr())
            .map_err(|_| Error::DescriptorWriteFailed)?;

        if vring
            .add_used(desc_chain.head_index(), response.as_bytes().len() as u32)
            .is_err()
        {
            warn!("Couldn't return used descriptors to the ring");
        }

        Ok(true)
    }

    fn process_tx_requests(
        &mut self,
        requests: Vec<ConsoleDescriptorChain>,
        vring: &VringRwLock,
    ) -> Result<()> {
        trace!("process_tx_requests");

        if requests.is_empty() {
            trace!("requests.is_empty");
            return Ok(());
        }

        for desc_chain in requests {
            let descriptors: Vec<_> = desc_chain.clone().collect();

            if descriptors.len() != 1 {
                return Err(Error::UnexpectedDescriptorCount(descriptors.len()));
            }

            let desc_request = descriptors[0];
            if desc_request.is_write_only() {
                return Err(Error::UnexpectedWriteOnlyDescriptor(0));
            }

            let desc_len = desc_request.len();
            let mut buffer: Vec<u8> = vec![0; desc_len as usize];

            desc_chain
                .memory()
                .read_slice(&mut buffer, desc_request.addr())
                .map_err(|_| Error::DescriptorReadFailed)?;

            let my_string = String::from_utf8(buffer).unwrap();
            trace!("{}", my_string);
            if self.controller.read().unwrap().backend == BackendType::Nested {
                print!("{}", my_string);
                io::stdout().flush().unwrap();
            } else {
                self.output_buffer = my_string.clone();
                self.output_flag = true;
            }

            if vring
                .add_used(desc_chain.head_index(), desc_request.len())
                .is_err()
            {
                warn!("Couldn't return used descriptors to the ring");
            }
        }

        Ok(())
    }

    fn process_ctrl_rx_requests(
        &mut self,
        requests: Vec<ConsoleDescriptorChain>,
        vring: &VringRwLock,
    ) -> Result<bool> {
        trace!("process_ctrl_rx_requests");
        let mut used_flag = false;

        if requests.is_empty() {
            trace!("Control rx queue is_empty");
            return Ok(true);
        }

        for desc_chain in requests {
            let descriptors: Vec<_> = desc_chain.clone().collect();

            // TODO: Is that test usefull?
            if descriptors.is_empty() {
                return Err(Error::UnexpectedDescriptorCount(descriptors.len()));
            }

            let desc_request = descriptors[0];
            if !desc_request.is_write_only() {
                return Err(Error::UnexpectedWriteOnlyDescriptor(0));
            }

            if (desc_request.len() as usize) < size_of::<VirtioConsoleControl>() {
                return Err(Error::UnexpectedDescriptorSize(
                    size_of::<VirtioConsoleControl>(),
                    desc_request.len(),
                ));
            }

            let ctrl_msg: VirtioConsoleControl = match self.rx_ctrl_fifo.remove() {
                Ok(item) => {
                    used_flag = true;
                    item
                }
                _ => {
                    trace!("No rx elements");
                    return Ok(used_flag);
                }
            };

            self.print_console_frame(ctrl_msg);

            let mut buffer: Vec<u8> = Vec::new();
            buffer.extend_from_slice(&ctrl_msg.to_le_bytes());

            if ctrl_msg.event.to_native() == VIRTIO_CONSOLE_PORT_NAME {
                buffer.extend_from_slice(b"org.test.foo!");
            };

            desc_chain
                .memory()
                .write_slice(&buffer, desc_request.addr())
                .map_err(|_| Error::DescriptorWriteFailed)?;

            if vring
                .add_used(desc_chain.head_index(), desc_request.len())
                .is_err()
            {
                warn!("Couldn't return used descriptors to the ring");
            }
        }

        Ok(true)
    }

    fn handle_control_msg(&mut self, ctrl_msg: VirtioConsoleControl) -> Result<()> {
        let mut ctrl_msg_reply = VirtioConsoleControl {
            id: 0.into(),
            event: 0.into(),
            value: 1.into(),
        };
        match ctrl_msg.event.to_native() {
            VIRTIO_CONSOLE_DEVICE_READY => {
                trace!("VIRTIO_CONSOLE_DEVICE_READY");
                self.ready = true;
                ctrl_msg_reply.event = VIRTIO_CONSOLE_PORT_ADD.into();
                self.rx_ctrl_fifo
                    .add(ctrl_msg_reply)
                    .expect("Control message could not be added into queue");
            }
            VIRTIO_CONSOLE_PORT_READY => {
                trace!("VIRTIO_CONSOLE_PORT_READY");
                ctrl_msg_reply.event = VIRTIO_CONSOLE_CONSOLE_PORT.into();
                self.rx_ctrl_fifo
                    .add(ctrl_msg_reply)
                    .expect("Control message could not be added into queue");

                ctrl_msg_reply.event = VIRTIO_CONSOLE_PORT_NAME.into();
                self.rx_ctrl_fifo
                    .add(ctrl_msg_reply)
                    .expect("Control message could not be added into queue");

                ctrl_msg_reply.event = VIRTIO_CONSOLE_PORT_OPEN.into();
                self.rx_ctrl_fifo
                    .add(ctrl_msg_reply)
                    .expect("Control message could not be added into queue");
            }
            VIRTIO_CONSOLE_PORT_OPEN => {
                trace!("VIRTIO_CONSOLE_PORT_OPEN");
            }
            _ => {
                trace!("Uknown control event");
                return Err(Error::HandleEventUnknown);
            }
        };
        Ok(())
    }

    fn process_ctrl_tx_requests(
        &mut self,
        requests: Vec<ConsoleDescriptorChain>,
        vring: &VringRwLock,
    ) -> Result<bool> {
        trace!("process_ctrl_tx_requests");

        // TODO: Is that test usefull?
        if requests.is_empty() {
            trace!("Control tx queue is_empty");
            return Ok(true);
        }

        for desc_chain in requests {
            let descriptors: Vec<_> = desc_chain.clone().collect();

            if descriptors.is_empty() {
                return Err(Error::UnexpectedDescriptorCount(descriptors.len()));
            }

            let desc_request = descriptors[0];
            if desc_request.is_write_only() {
                return Err(Error::UnexpectedWriteOnlyDescriptor(0));
            }

            if desc_request.len() as usize != size_of::<VirtioConsoleControl>() {
                return Err(Error::UnexpectedDescriptorSize(
                    size_of::<VirtioConsoleControl>(),
                    desc_request.len(),
                ));
            }

            let request = desc_chain
                .memory()
                .read_obj::<VirtioConsoleControl>(desc_request.addr())
                .map_err(|_| Error::DescriptorReadFailed)?;

            self.print_console_frame(request);

            if self.handle_control_msg(request).is_ok() {
                trace!("Trigger a kick");
                self.rx_ctrl_event.write(1).unwrap();
            } else {
                trace!("EventFd is not available.");
            }

            if vring
                .add_used(desc_chain.head_index(), desc_request.len())
                .is_err()
            {
                warn!("Couldn't return used descriptors to the ring");
            }
        }

        Ok(true)
    }

    /// Process the messages in the vring and dispatch replies
    fn process_rx_queue(&mut self, vring: &VringRwLock) -> Result<()> {
        trace!("process_rx_queue");
        let requests: Vec<_> = vring
            .get_mut()
            .get_queue_mut()
            .iter(self.mem.as_ref().unwrap().memory())
            .map_err(|_| Error::DescriptorNotFound)?
            .collect();

        if self.process_rx_requests(requests, vring)? {
            // Send notification once all the requests are processed
            trace!("Send notification once all the requests of queue 0 are processed");
            vring
                .signal_used_queue()
                .map_err(|_| Error::NotificationFailed)?;
        }
        Ok(())
    }

    /// Process the messages in the vring and dispatch replies
    fn process_tx_queue(&mut self, vring: &VringRwLock) -> Result<()> {
        trace!("process_tx_queue");
        let requests: Vec<_> = vring
            .get_mut()
            .get_queue_mut()
            .iter(self.mem.as_ref().unwrap().memory())
            .map_err(|_| Error::DescriptorNotFound)?
            .collect();

        self.process_tx_requests(requests, vring)?;
        // Send notification once all the requests are processed
        vring
            .signal_used_queue()
            .map_err(|_| Error::NotificationFailed)?;

        Ok(())
    }

    /// Process the messages in the vring and dispatch replies
    fn process_ctrl_rx_queue(&mut self, vring: &VringRwLock) -> Result<()> {
        trace!("process_ctrl_rx_queue");
        let requests: Vec<_> = vring
            .get_mut()
            .get_queue_mut()
            .iter(self.mem.as_ref().unwrap().memory())
            .map_err(|_| Error::DescriptorNotFound)?
            .collect();

        if self.process_ctrl_rx_requests(requests, vring)? {
            trace!("Send notification once all the requests of queue 2 are processed");
            // Send notification once all the requests are processed
            vring
                .signal_used_queue()
                .map_err(|_| Error::NotificationFailed)?;
        }
        Ok(())
    }

    /// Process the messages in the vring and dispatch replies
    fn process_ctrl_tx_queue(&mut self, vring: &VringRwLock) -> Result<()> {
        trace!("process_ctrl_tx_queue");
        let requests: Vec<_> = vring
            .get_mut()
            .get_queue_mut()
            .iter(self.mem.as_ref().unwrap().memory())
            .map_err(|_| Error::DescriptorNotFound)?
            .collect();

        if self.process_ctrl_tx_requests(requests, vring)? {
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
        vring_worker: &Arc<VringEpollHandler<Arc<RwLock<VhostUserConsoleBackend>>>>,
    ) {
        let rx_event_fd = self.rx_event.as_raw_fd();
        vring_worker
            .register_listener(rx_event_fd, EventSet::IN, u64::from(BACKEND_RX_EFD))
            .unwrap();

        let rx_ctrl_event_fd = self.rx_ctrl_event.as_raw_fd();
        vring_worker
            .register_listener(
                rx_ctrl_event_fd,
                EventSet::IN,
                u64::from(BACKEND_CTRL_RX_EFD),
            )
            .unwrap();
    }

    pub(crate) fn start_tcp_console_thread(
        vhu_console: &Arc<RwLock<VhostUserConsoleBackend>>,
        tcplisener_str: String,
    ) -> JoinHandle<Result<()>> {
        let vhu_console = Arc::clone(vhu_console);
        spawn(move || {
            loop {
                let ready = vhu_console.read().unwrap().ready_to_write;
                let exit = vhu_console.read().unwrap().controller.read().unwrap().exit;

                if exit {
                    dbg!("Thread exits!");
                    break;
                } else if ready {
                    println!("Server listening on address: {}", tcplisener_str.clone());
                    let listener = TcpListener::bind(tcplisener_str.clone()).unwrap();
                    listener.set_nonblocking(true).expect("Non-blocking error");

                    for stream in listener.incoming() {
                        match stream {
                            Ok(mut stream) => {
                                println!("New connection");
                                stream.set_nonblocking(true).expect("Non-blocking error");

                                let mut buffer = [0; 1024];
                                loop {
                                    let exit =
                                        vhu_console.read().unwrap().controller.read().unwrap().exit;
                                    if exit {
                                        dbg!("Thread exits!");
                                        return Ok(());
                                    }
                                    // Write to the stream
                                    if vhu_console.read().unwrap().output_flag {
                                        let byte_stream = vhu_console
                                            .read()
                                            .unwrap()
                                            .output_buffer
                                            .clone()
                                            .into_bytes();
                                        if let Err(e) = stream.write_all(&byte_stream) {
                                            eprintln!("Error writing to stream: {}", e);
                                            panic!("Writing to stream fails");
                                        }
                                        vhu_console.write().unwrap().output_flag = false;
                                    }
                                    match stream.read(&mut buffer) {
                                        Ok(bytes_read) => {
                                            if bytes_read == 0 {
                                                println!("Close connection");
                                                break;
                                            }
                                            trace!(
                                                "Received: {}",
                                                String::from_utf8_lossy(&buffer[..bytes_read])
                                            );
                                            let input_buffer =
                                                String::from_utf8_lossy(&buffer[..bytes_read])
                                                    .to_string();
                                            let _ = vhu_console
                                                .write()
                                                .unwrap()
                                                .rx_data_fifo
                                                .add(input_buffer);
                                            vhu_console.write().unwrap().rx_event.write(1).unwrap();
                                        }
                                        Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                                            continue;
                                        }
                                        Err(ref e)
                                            if e.kind() == io::ErrorKind::BrokenPipe
                                                || e.kind() == io::ErrorKind::ConnectionReset =>
                                        {
                                            dbg!("Stream has been closed.");
                                            break;
                                        }
                                        Err(e) => {
                                            eprintln!("Error reading from socket: {}", e);
                                            panic!("Reading from stream fails");
                                        }
                                    }
                                }
                            }
                            Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                                let exit =
                                    vhu_console.read().unwrap().controller.read().unwrap().exit;
                                if exit {
                                    dbg!("Thread exits!");
                                    return Ok(());
                                }
                                continue;
                            }
                            Err(e) => {
                                eprintln!("Error accepting connection: {}", e);
                                panic!("Error stream");
                            }
                        }
                    }
                }
            }
            Ok(())
        })
    }

    /// Start console thread.
    pub(crate) fn start_console_thread(
        vhu_console: &Arc<RwLock<VhostUserConsoleBackend>>,
    ) -> JoinHandle<Result<()>> {
        let vhu_console = Arc::clone(vhu_console);
        trace!("Enter text and press Enter: ");

        let exit_eventfd = vhu_console.read().unwrap().exit_event.as_raw_fd();
        // Spawn a new thread to handle input.
        spawn(move || {
            let term = Term::stdout();
            let mut fdset = FdSet::new();
            fdset.insert(term.as_raw_fd());
            fdset.insert(exit_eventfd);
            let max_fd = fdset.highest().expect("Failed to read fdset!") + 1;

            loop {
                let ready = vhu_console.read().unwrap().ready_to_write;
                let exit = vhu_console.read().unwrap().controller.read().unwrap().exit;

                if exit {
                    dbg!("Exit!");
                    break;
                } else if ready {
                    let mut fdset_clone = fdset;
                    enable_raw_mode().expect("Raw mode error");

                    match select(Some(max_fd), Some(&mut fdset_clone), None, None, None) {
                        Ok(_num_fds) => {
                            disable_raw_mode().expect("Raw mode error");
                            let exit = vhu_console.read().unwrap().controller.read().unwrap().exit;
                            if (fdset_clone.contains(exit_eventfd)) && exit {
                                dbg!("Exit!");
                                break;
                            }

                            if fdset_clone.contains(term.as_raw_fd()) {
                                let character =
                                    match term.read_key().expect("Error reading character!") {
                                        Key::Char(character) => Some(character),
                                        Key::Enter => Some('\n'),
                                        Key::Tab => Some('\t'),
                                        Key::Backspace => Some('\u{8}'),
                                        _ => None,
                                    };

                                if character.is_some() {
                                    // Pass the data to vhu_console and trigger an EventFd
                                    let input_buffer =
                                        character.expect("Unexpected character!").to_string();
                                    let _ =
                                        vhu_console.write().unwrap().rx_data_fifo.add(input_buffer);
                                    vhu_console.write().unwrap().rx_event.write(1).unwrap();
                                }
                            }
                        }
                        Err(e) => {
                            disable_raw_mode().expect("Raw mode error");
                            panic!("Error in select: {}", e);
                        }
                    }
                }
            }

            Ok(())
        })
    }
    pub fn kill_console_thread(&self) {
        dbg!("Kill thread\n");
        disable_raw_mode().expect("Raw mode error");
        self.controller.write().unwrap().exit = true;
        self.exit_event.write(1).unwrap();
    }
}

/// VhostUserBackendMut trait methods
impl VhostUserBackendMut for VhostUserConsoleBackend {
    type Vring = VringRwLock;
    type Bitmap = ();

    fn num_queues(&self) -> usize {
        trace!("num_queues: {:?}", NUM_QUEUES);
        NUM_QUEUES
    }

    fn max_queue_size(&self) -> usize {
        trace!("max_queue_size: {:?}", QUEUE_SIZE);
        QUEUE_SIZE
    }

    fn features(&self) -> u64 {
        // VIRTIO_CONSOLE_F_MULTIPORT is supported but is disabled by default
        let features = 1 << VIRTIO_F_VERSION_1
            | 1 << VIRTIO_F_NOTIFY_ON_EMPTY
            | 1 << VIRTIO_RING_F_EVENT_IDX
            | 1 << VIRTIO_CONSOLE_F_EMERG_WRITE
            | 1 << VIRTIO_RING_F_INDIRECT_DESC
            | 1 << VIRTIO_CONSOLE_F_MULTIPORT
            | VhostUserVirtioFeatures::PROTOCOL_FEATURES.bits();

        trace!("vhu_console->features: {:x}", features);
        features
    }

    fn acked_features(&mut self, features: u64) {
        trace!("\nacked_features: 0x{:x}\n", features);
        self.acked_features = features;
    }

    fn protocol_features(&self) -> VhostUserProtocolFeatures {
        let protocol_features = VhostUserProtocolFeatures::MQ
            | VhostUserProtocolFeatures::CONFIG
            | VhostUserProtocolFeatures::REPLY_ACK;

        trace!("protocol_features: {:x}", protocol_features);
        protocol_features
    }

    fn get_config(&self, offset: u32, size: u32) -> Vec<u8> {
        trace!("get_config");
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
        _evset: EventSet,
        vrings: &[VringRwLock],
        _thread_id: usize,
    ) -> IoResult<()> {
        trace!("\nhandle_event:");

        if device_event == RX_QUEUE {
            trace!("RX_QUEUE\n");
            // Check if there are any available data
            if self.rx_data_fifo.size() == 0 {
                return Ok(());
            }
        };

        if device_event == CTRL_RX_QUEUE {
            trace!("CTRL_RX_QUEUE\n");
            // Check if there are any available data and the device is ready
            if (!self.ready) || (self.rx_ctrl_fifo.size() == 0) {
                return Ok(());
            }
        };

        let vring = if device_event == BACKEND_RX_EFD {
            trace!("BACKEND_RX_EFD\n");
            &vrings[RX_QUEUE as usize]
        } else if device_event == BACKEND_CTRL_RX_EFD {
            trace!("BACKEND_CTRL_RX_EFD\n");
            &vrings[CTRL_RX_QUEUE as usize]
        } else {
            &vrings[device_event as usize]
        };

        if self.event_idx {
            trace!("Event FD enabled!");
            loop {
                vring.disable_notification().unwrap();
                match device_event {
                    RX_QUEUE => self.process_rx_queue(vring),
                    TX_QUEUE => {
                        self.ready_to_write = true;
                        self.process_tx_queue(vring)
                    }
                    CTRL_RX_QUEUE => self.process_ctrl_rx_queue(vring),
                    CTRL_TX_QUEUE => self.process_ctrl_tx_queue(vring),
                    BACKEND_RX_EFD => {
                        let _ = self.rx_event.read();
                        self.process_rx_queue(vring)
                    }
                    BACKEND_CTRL_RX_EFD => {
                        let _ = self.rx_ctrl_event.read();
                        self.process_ctrl_rx_queue(vring)
                    }
                    _ => Err(Error::HandleEventUnknown),
                }?;
                if !vring.enable_notification().unwrap() {
                    break;
                }
            }
        } else {
            trace!("Event FD NOT enabled!");
            match device_event {
                RX_QUEUE => self.process_rx_queue(vring),
                TX_QUEUE => {
                    self.ready_to_write = true;
                    self.process_tx_queue(vring)
                }
                CTRL_RX_QUEUE => self.process_ctrl_rx_queue(vring),
                CTRL_TX_QUEUE => self.process_ctrl_tx_queue(vring),
                BACKEND_RX_EFD => {
                    let _ = self.rx_event.read();
                    self.process_rx_queue(vring)
                }
                BACKEND_CTRL_RX_EFD => {
                    let _ = self.rx_ctrl_event.read();
                    self.process_ctrl_rx_queue(vring)
                }
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
    use virtio_bindings::virtio_ring::{VRING_DESC_F_NEXT, VRING_DESC_F_WRITE};
    use virtio_queue::{mock::MockSplitQueue, Descriptor, Queue};
    use vm_memory::{Bytes, GuestAddress, GuestMemoryAtomic, GuestMemoryMmap};

    #[test]
    fn test_vhost_user_console_backend_creation() {
        let console_controller = Arc::new(RwLock::new(ConsoleController::new(BackendType::Nested)));
        let vhost_user_console_backend = VhostUserConsoleBackend::new(console_controller)
            .expect("Failed create vhuconsole backend");

        assert_eq!(vhost_user_console_backend.acked_features, 0);
        assert!(!vhost_user_console_backend.event_idx);
        assert!(!vhost_user_console_backend.ready);
        assert!(!vhost_user_console_backend.ready_to_write);
    }

    #[test]
    fn test_virtio_console_empty_handle_request() {
        let console_controller = Arc::new(RwLock::new(ConsoleController::new(BackendType::Nested)));
        let mut vu_console_backend = VhostUserConsoleBackend::new(console_controller)
            .expect("Failed create vhuconsole backend");

        // Artificial memory
        let mem = GuestMemoryAtomic::new(
            GuestMemoryMmap::<()>::from_ranges(&[(GuestAddress(0), 0x1000)]).unwrap(),
        );

        // Update memory
        vu_console_backend.update_memory(mem.clone()).unwrap();

        // Artificial Vring
        let vring = VringRwLock::new(mem, 0x1000).unwrap();
        vring.set_queue_info(0x100, 0x200, 0x300).unwrap();
        vring.set_queue_ready(true);
        let list_vrings = [vring.clone(), vring.clone(), vring.clone(), vring.clone()];

        vu_console_backend
            .handle_event(RX_QUEUE, EventSet::IN, &list_vrings, 0)
            .unwrap();

        vu_console_backend
            .handle_event(TX_QUEUE, EventSet::IN, &list_vrings, 0)
            .unwrap();

        vu_console_backend
            .handle_event(CTRL_RX_QUEUE, EventSet::IN, &list_vrings, 0)
            .unwrap();

        vu_console_backend
            .handle_event(CTRL_TX_QUEUE, EventSet::IN, &list_vrings, 0)
            .unwrap();

        vu_console_backend
            .handle_event(BACKEND_RX_EFD, EventSet::IN, &list_vrings, 0)
            .unwrap();

        vu_console_backend
            .handle_event(BACKEND_CTRL_RX_EFD, EventSet::IN, &list_vrings, 0)
            .unwrap();
    }

    #[test]
    fn test_virtio_console_empty_requests() {
        let console_controller = Arc::new(RwLock::new(ConsoleController::new(BackendType::Nested)));
        let mut vu_console_backend = VhostUserConsoleBackend::new(console_controller)
            .expect("Failed create vhuconsole backend");

        // Artificial memory
        let mem = GuestMemoryAtomic::new(
            GuestMemoryMmap::<()>::from_ranges(&[(GuestAddress(0), 0x1000)]).unwrap(),
        );

        // Artificial Vring
        let vring = VringRwLock::new(mem.clone(), 0x1000).unwrap();

        // Empty descriptor chain should be ignored
        assert!(vu_console_backend
            .process_rx_requests(Vec::<ConsoleDescriptorChain>::new(), &vring)
            .is_ok());
        assert!(vu_console_backend
            .process_tx_requests(Vec::<ConsoleDescriptorChain>::new(), &vring)
            .is_ok());
        assert!(vu_console_backend
            .process_ctrl_rx_requests(Vec::<ConsoleDescriptorChain>::new(), &vring)
            .is_ok());
        assert!(vu_console_backend
            .process_ctrl_tx_requests(Vec::<ConsoleDescriptorChain>::new(), &vring)
            .is_ok());
    }

    fn build_desc_chain(
        mem: &GuestMemoryMmap,
        count: u16,
        flags: Vec<u16>,
        len: u32,
    ) -> ConsoleDescriptorChain {
        let vq = MockSplitQueue::new(mem, 16);
        let mut desc_vec = Vec::new();

        //Create a descriptor chain with @count descriptors.
        for i in 0..count {
            let desc_flags = if i < count - 1 {
                flags[i as usize] | VRING_DESC_F_NEXT as u16
            } else {
                flags[i as usize] & !VRING_DESC_F_NEXT as u16
            };

            let desc = Descriptor::new((0x100 * (i + 1)) as u64, len, desc_flags, i + 1);
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
    fn test_virtio_console_ctrl_rx_request() {
        let console_controller = Arc::new(RwLock::new(ConsoleController::new(BackendType::Nested)));
        let mut vu_console_backend = VhostUserConsoleBackend::new(console_controller)
            .expect("Failed create vhuconsole backend");

        // Artificial memory
        let mem = GuestMemoryMmap::<()>::from_ranges(&[(GuestAddress(0), 0x1000)]).unwrap();

        // Test 1: Empty queue
        let mem1 = GuestMemoryAtomic::new(mem.clone());
        let vring = VringRwLock::new(mem1.clone(), 0x1000).unwrap();
        assert!(vu_console_backend
            .process_ctrl_rx_requests(vec![], &vring)
            .unwrap());

        // Test 2: Found no descriptors
        let desc_chain = build_desc_chain(&mem, 1, vec![0], 0x200);
        let mem1 = GuestMemoryAtomic::new(mem.clone());
        let vring = VringRwLock::new(mem1.clone(), 0x1000).unwrap();
        vu_console_backend.update_memory(mem1).unwrap();

        assert_eq!(
            vu_console_backend
                .process_ctrl_rx_requests(vec![desc_chain], &vring)
                .unwrap_err(),
            Error::UnexpectedWriteOnlyDescriptor(0)
        );

        // Test 3: empty queue
        let desc_chain = build_desc_chain(&mem, 1, vec![VRING_DESC_F_WRITE as u16], 0x200);
        let mem1 = GuestMemoryAtomic::new(mem.clone());
        let vring = VringRwLock::new(mem1.clone(), 0x1000).unwrap();
        vu_console_backend.update_memory(mem1).unwrap();
        assert!(!vu_console_backend
            .process_ctrl_rx_requests(vec![desc_chain.clone()], &vring)
            .unwrap());

        // Test 4: the written desc reply
        let ctrl_msg = VirtioConsoleControl {
            id: 0.into(),
            event: VIRTIO_CONSOLE_PORT_ADD.into(),
            value: 1.into(),
        };
        let _ = vu_console_backend.rx_ctrl_fifo.add(ctrl_msg);

        assert!(vu_console_backend
            .process_ctrl_rx_requests(vec![desc_chain.clone()], &vring)
            .unwrap());

        let ctrl_msg_reply = desc_chain
            .memory()
            .read_obj::<VirtioConsoleControl>(vm_memory::GuestAddress(0x100_u64))
            .map_err(|_| Error::DescriptorReadFailed)
            .unwrap();

        assert_eq!(ctrl_msg.id, ctrl_msg_reply.id);
        assert_eq!(ctrl_msg.event, ctrl_msg_reply.event);
        assert_eq!(ctrl_msg.value, ctrl_msg_reply.value);

        // Test 5: if message is VIRTIO_CONSOLE_PORT_NAME
        let desc_chain = build_desc_chain(&mem, 1, vec![VRING_DESC_F_WRITE as u16], 0x200);
        let mem1 = GuestMemoryAtomic::new(mem.clone());
        let vring = VringRwLock::new(mem1.clone(), 0x1000).unwrap();
        vu_console_backend.update_memory(mem1).unwrap();

        let ctrl_msg = VirtioConsoleControl {
            id: 0.into(),
            event: VIRTIO_CONSOLE_PORT_NAME.into(),
            value: 1.into(),
        };
        let _ = vu_console_backend.rx_ctrl_fifo.add(ctrl_msg);

        assert!(vu_console_backend
            .process_ctrl_rx_requests(vec![desc_chain.clone()], &vring)
            .unwrap());
    }

    #[test]
    fn test_virtio_console_ctrl_tx_request() {
        let console_controller = Arc::new(RwLock::new(ConsoleController::new(BackendType::Nested)));
        let mut vu_console_backend = VhostUserConsoleBackend::new(console_controller)
            .expect("Failed create vhuconsole backend");

        // Artificial memory
        let mem = GuestMemoryMmap::<()>::from_ranges(&[(GuestAddress(0), 0x1000)]).unwrap();

        // Test 1: Empty queue
        let mem1 = GuestMemoryAtomic::new(mem.clone());
        let vring = VringRwLock::new(mem1.clone(), 0x1000).unwrap();
        assert!(vu_console_backend
            .process_ctrl_tx_requests(vec![], &vring)
            .unwrap());

        // Test 2: Found no descriptors
        let desc_chain = build_desc_chain(&mem, 1, vec![VRING_DESC_F_WRITE as u16], 0x200);
        let mem1 = GuestMemoryAtomic::new(mem.clone());
        let vring = VringRwLock::new(mem1.clone(), 0x1000).unwrap();
        vu_console_backend.update_memory(mem1).unwrap();

        assert_eq!(
            vu_console_backend
                .process_ctrl_tx_requests(vec![desc_chain], &vring)
                .unwrap_err(),
            Error::UnexpectedWriteOnlyDescriptor(0)
        );

        // Test 3: Bigger descriptor len than a console ctrl message
        let desc_chain = build_desc_chain(&mem, 1, vec![0], 0x200);
        let mem1 = GuestMemoryAtomic::new(mem.clone());
        let vring = VringRwLock::new(mem1.clone(), 0x1000).unwrap();
        vu_console_backend.update_memory(mem1).unwrap();
        assert_eq!(
            vu_console_backend
                .process_ctrl_tx_requests(vec![desc_chain.clone()], &vring)
                .unwrap_err(),
            Error::UnexpectedDescriptorSize(8, 512)
        );

        // Test 4: Empty ctrl vring
        let desc_chain = build_desc_chain(&mem, 1, vec![0], 0x8);
        let mem1 = GuestMemoryAtomic::new(mem.clone());
        let vring = VringRwLock::new(mem1.clone(), 0x1000).unwrap();
        vu_console_backend.update_memory(mem1).unwrap();
        assert!(vu_console_backend
            .process_ctrl_tx_requests(vec![desc_chain.clone()], &vring)
            .unwrap());
    }

    #[test]
    fn test_virtio_console_handle_control_msg() {
        let console_controller = Arc::new(RwLock::new(ConsoleController::new(BackendType::Nested)));
        let mut vu_console_backend = VhostUserConsoleBackend::new(console_controller)
            .expect("Failed create vhuconsole backend");

        // Artificial memory & update device's memory
        let mem = GuestMemoryMmap::<()>::from_ranges(&[(GuestAddress(0), 0x1000)]).unwrap();
        let mem_1 = GuestMemoryAtomic::new(mem.clone());
        vu_console_backend.update_memory(mem_1.clone()).unwrap();

        // Test 1: Empty queue
        let ctrl_msg_1 = VirtioConsoleControl {
            id: 0.into(),
            event: VIRTIO_CONSOLE_DEVICE_READY.into(),
            value: 1.into(),
        };

        let ctrl_msg_2 = VirtioConsoleControl {
            id: 0.into(),
            event: VIRTIO_CONSOLE_PORT_READY.into(),
            value: 1.into(),
        };

        let ctrl_msg_3 = VirtioConsoleControl {
            id: 0.into(),
            event: VIRTIO_CONSOLE_PORT_OPEN.into(),
            value: 1.into(),
        };

        let ctrl_msg_err = VirtioConsoleControl {
            id: 0.into(),
            event: 4.into(),
            value: 1.into(),
        };

        assert!(vu_console_backend.handle_control_msg(ctrl_msg_3).is_ok());

        assert_eq!(
            vu_console_backend
                .handle_control_msg(ctrl_msg_err)
                .unwrap_err(),
            Error::HandleEventUnknown
        );

        assert!(vu_console_backend.handle_control_msg(ctrl_msg_1).is_ok());

        // Update memory
        let mem_1 = GuestMemoryAtomic::new(mem.clone());
        vu_console_backend.update_memory(mem_1.clone()).unwrap();

        assert!(vu_console_backend.handle_control_msg(ctrl_msg_2).is_ok());
    }

    #[test]
    fn test_virtio_console_tx_request() {
        let console_controller = Arc::new(RwLock::new(ConsoleController::new(BackendType::Nested)));
        let mut vu_console_backend = VhostUserConsoleBackend::new(console_controller)
            .expect("Failed create vhuconsole backend");

        // Artificial memory
        let mem = GuestMemoryMmap::<()>::from_ranges(&[(GuestAddress(0), 0x1000)]).unwrap();

        // Test 1: Empty queue
        let mem1 = GuestMemoryAtomic::new(mem.clone());
        let vring = VringRwLock::new(mem1, 0x1000).unwrap();
        assert!(vu_console_backend
            .process_tx_requests(vec![], &vring)
            .is_ok());

        // Test 2: Found more than 1 descriptor
        let desc_chain = build_desc_chain(&mem, 2, vec![VRING_DESC_F_WRITE as u16, 0], 0x0);
        let mem1 = GuestMemoryAtomic::new(mem.clone());
        let vring = VringRwLock::new(mem1.clone(), 0x1000).unwrap();
        vu_console_backend.update_memory(mem1).unwrap();
        assert_eq!(
            vu_console_backend
                .process_tx_requests(vec![desc_chain], &vring)
                .unwrap_err(),
            Error::UnexpectedDescriptorCount(2)
        );

        // Test 3: The descriptor should be read-only
        let desc_chain = build_desc_chain(&mem, 1, vec![VRING_DESC_F_WRITE as u16], 0x0);
        let mem1 = GuestMemoryAtomic::new(mem.clone());
        let vring = VringRwLock::new(mem1.clone(), 0x1000).unwrap();
        vu_console_backend.update_memory(mem1).unwrap();
        assert_eq!(
            vu_console_backend
                .process_tx_requests(vec![desc_chain], &vring)
                .unwrap_err(),
            Error::UnexpectedWriteOnlyDescriptor(0)
        );

        // Test 4: Empty buffer
        let desc_chain = build_desc_chain(&mem, 1, vec![0], 0x200);
        let mem1 = GuestMemoryAtomic::new(mem.clone());
        let vring = VringRwLock::new(mem1.clone(), 0x1000).unwrap();
        vu_console_backend.update_memory(mem1).unwrap();
        assert!(vu_console_backend
            .process_tx_requests(vec![desc_chain], &vring)
            .is_ok());

        // Test 5: Fill message to the buffer
        let desc_chain = build_desc_chain(&mem, 1, vec![0], 0x200);
        let desc_addr = desc_chain.clone().collect::<Vec<_>>()[0].addr();

        // Build the Vec with the desired string
        let mut buffer: Vec<u8> = Vec::new();
        let string_bytes = "Hello!".as_bytes();
        buffer.extend_from_slice(string_bytes);

        // Write a new buffer into the desc_chain
        desc_chain.memory().write_slice(&buffer, desc_addr).unwrap();

        // Verify that it is written
        let mut read_buffer: Vec<u8> = vec![0; 0x200];
        desc_chain
            .memory()
            .read_slice(&mut read_buffer, desc_addr)
            .expect("Failed to read");
        let read_buffer: Vec<u8> = read_buffer.iter().take(buffer.len()).copied().collect();

        assert_eq!(
            String::from_utf8(read_buffer).unwrap(),
            String::from_utf8(buffer).unwrap()
        );

        assert!(vu_console_backend
            .process_tx_requests(vec![desc_chain], &vring)
            .is_ok());
    }

    #[test]
    fn test_virtio_console_tx_request_network() {
        let console_controller =
            Arc::new(RwLock::new(ConsoleController::new(BackendType::Network)));
        let mut vu_console_backend = VhostUserConsoleBackend::new(console_controller)
            .expect("Failed create vhuconsole backend");

        // Artificial memory
        let mem = GuestMemoryMmap::<()>::from_ranges(&[(GuestAddress(0), 0x1000)]).unwrap();
        let desc_chain = build_desc_chain(&mem, 1, vec![0], 0x200);
        let mem1 = GuestMemoryAtomic::new(mem.clone());
        let vring = VringRwLock::new(mem1.clone(), 0x1000).unwrap();

        // Test 5: Fill message to the buffer
        vu_console_backend.update_memory(mem1).unwrap();
        let desc_addr = desc_chain.clone().collect::<Vec<_>>()[0].addr();

        // Build the Vec with the desired string
        let mut buffer: Vec<u8> = Vec::new();
        let string_bytes = "Hello!".as_bytes();
        buffer.extend_from_slice(string_bytes);

        // Write a new buffer into the desc_chain
        desc_chain.memory().write_slice(&buffer, desc_addr).unwrap();

        // Verify that it is written
        let mut read_buffer: Vec<u8> = vec![0; 0x200];
        desc_chain
            .memory()
            .read_slice(&mut read_buffer, desc_addr)
            .expect("Failed to read");
        let read_buffer: Vec<u8> = read_buffer.iter().take(buffer.len()).copied().collect();

        assert_eq!(
            String::from_utf8(read_buffer).unwrap(),
            String::from_utf8(buffer).unwrap()
        );

        assert!(vu_console_backend
            .process_tx_requests(vec![desc_chain], &vring)
            .is_ok());
    }

    #[test]
    fn test_virtio_console_rx_request() {
        let console_controller = Arc::new(RwLock::new(ConsoleController::new(BackendType::Nested)));
        let mut vu_console_backend = VhostUserConsoleBackend::new(console_controller)
            .expect("Failed create vhuconsole backend");

        // Artificial memory
        let mem = GuestMemoryMmap::<()>::from_ranges(&[(GuestAddress(0), 0x1000)]).unwrap();

        // Test 1: Empty queue
        let mem1 = GuestMemoryAtomic::new(mem.clone());
        let vring = VringRwLock::new(mem1, 0x1000).unwrap();
        assert!(vu_console_backend
            .process_rx_requests(vec![], &vring)
            .is_ok());

        // Test 2: Found more than 1 descriptor
        let desc_chain = build_desc_chain(&mem, 2, vec![0, 0], 0x0);
        let mem1 = GuestMemoryAtomic::new(mem.clone());
        let vring = VringRwLock::new(mem1.clone(), 0x1000).unwrap();
        vu_console_backend.update_memory(mem1).unwrap();
        assert_eq!(
            vu_console_backend
                .process_rx_requests(vec![desc_chain], &vring)
                .unwrap_err(),
            Error::UnexpectedDescriptorCount(2)
        );

        // Test 3: The descriptor should be read-only
        let desc_chain = build_desc_chain(&mem, 1, vec![0], 0x0);
        let mem1 = GuestMemoryAtomic::new(mem.clone());
        let vring = VringRwLock::new(mem1.clone(), 0x1000).unwrap();
        vu_console_backend.update_memory(mem1).unwrap();
        assert_eq!(
            vu_console_backend
                .process_rx_requests(vec![desc_chain], &vring)
                .unwrap_err(),
            Error::UnexpectedReadableDescriptor(0)
        );

        // Test 4: Empty buffer
        let desc_chain = build_desc_chain(&mem, 1, vec![VRING_DESC_F_WRITE as u16], 0x0);
        let mem1 = GuestMemoryAtomic::new(mem.clone());
        let vring = VringRwLock::new(mem1.clone(), 0x1000).unwrap();
        vu_console_backend.update_memory(mem1).unwrap();
        assert!(!vu_console_backend
            .process_rx_requests(vec![desc_chain], &vring)
            .unwrap());

        // Test 5: Fill message to the buffer
        let desc_chain = build_desc_chain(&mem, 1, vec![VRING_DESC_F_WRITE as u16], 0x0);
        let mem1 = GuestMemoryAtomic::new(mem.clone());
        let vring = VringRwLock::new(mem1.clone(), 0x1000).unwrap();

        vu_console_backend.update_memory(mem1).unwrap();
        let input_buffer = "Hello!".to_string();
        let _ = vu_console_backend.rx_data_fifo.add(input_buffer.clone());
        assert!(vu_console_backend
            .process_rx_requests(vec![desc_chain.clone()], &vring)
            .unwrap());

        // Test 6: Verify written data
        let desc_addr = GuestAddress(0x100);
        let mut read_buffer: Vec<u8> = vec![0; 0x100];
        desc_chain
            .memory()
            .read_slice(&mut read_buffer, desc_addr)
            .expect("Failed to read");

        let read_buffer: Vec<u8> = read_buffer
            .iter()
            .take(input_buffer.len())
            .copied()
            .collect();

        assert_eq!(String::from_utf8(read_buffer).unwrap(), input_buffer);
    }

    #[test]
    fn test_virtio_console_start_tcp_console_thread() {
        let console_controller = Arc::new(RwLock::new(ConsoleController::new(BackendType::Nested)));
        let vu_console_backend = Arc::new(RwLock::new(
            VhostUserConsoleBackend::new(console_controller)
                .expect("Failed create vhuconsole backend"),
        ));
        let tcp_addr = "127.0.0.1:12345".to_string();

        let read_handle = VhostUserConsoleBackend::start_tcp_console_thread(
            &vu_console_backend,
            tcp_addr.clone(),
        );
        vu_console_backend.read().unwrap().kill_console_thread();
        assert!(read_handle.join().is_ok());
    }

    #[test]
    fn test_virtio_console_start_nested_console_thread() {
        let console_controller = Arc::new(RwLock::new(ConsoleController::new(BackendType::Nested)));
        let vu_console_backend = Arc::new(RwLock::new(
            VhostUserConsoleBackend::new(console_controller)
                .expect("Failed create vhuconsole backend"),
        ));

        let read_handle = VhostUserConsoleBackend::start_console_thread(&vu_console_backend);

        vu_console_backend.read().unwrap().kill_console_thread();
        assert!(read_handle.join().is_ok());
    }
}
