// vhost device console
//
// Copyright 2023-2024 VIRTUAL OPEN SYSTEMS SAS. All Rights Reserved.
//          Timos Ampelikiotis <t.ampelikiotis@virtualopensystems.com>
//
// SPDX-License-Identifier: Apache-2.0 or BSD-3-Clause

use std::{
    io::{self, Read, Result as IoResult, Write},
    net::TcpListener,
    os::fd::{AsRawFd, RawFd},
    slice::from_raw_parts,
    sync::{Arc, RwLock},
};

use crossterm::terminal::{disable_raw_mode, enable_raw_mode};
use log::{error, trace, warn};
use queues::{IsQueue, Queue};
use thiserror::Error as ThisError;
use vhost::vhost_user::message::{VhostUserProtocolFeatures, VhostUserVirtioFeatures};
use vhost_user_backend::{VhostUserBackendMut, VringEpollHandler, VringRwLock, VringT};
use virtio_bindings::bindings::{
    virtio_config::{VIRTIO_F_NOTIFY_ON_EMPTY, VIRTIO_F_VERSION_1},
    virtio_ring::{VIRTIO_RING_F_EVENT_IDX, VIRTIO_RING_F_INDIRECT_DESC},
};
use virtio_queue::{DescriptorChain, QueueOwnedT};
use vm_memory::{
    ByteValued, GuestAddressSpace, GuestMemoryAtomic, GuestMemoryLoadGuard, GuestMemoryMmap,
};
use vmm_sys_util::{
    epoll::EventSet,
    eventfd::{EventFd, EFD_NONBLOCK},
};

use crate::{
    console::{BackendType, ConsoleController},
    virtio_console::{
        VirtioConsoleControl, VIRTIO_CONSOLE_CONSOLE_PORT, VIRTIO_CONSOLE_DEVICE_READY,
        VIRTIO_CONSOLE_F_MULTIPORT, VIRTIO_CONSOLE_PORT_ADD, VIRTIO_CONSOLE_PORT_NAME,
        VIRTIO_CONSOLE_PORT_OPEN, VIRTIO_CONSOLE_PORT_READY,
    },
};

type Result<T> = std::result::Result<T, Error>;

#[derive(Copy, Clone, Debug, PartialEq, Eq, ThisError)]
pub enum Error {
    #[error("Failed to handle unknown event: {0}")]
    HandleEventUnknown(u16),
    #[error("Descriptor not found")]
    DescriptorNotFound,
    #[error("Failed to send notification")]
    NotificationFailed,
    #[error("Descriptor read failed")]
    DescriptorReadFailed,
    #[error("Descriptor write failed")]
    DescriptorWriteFailed,
    #[error("Add used element in vring {0} failed")]
    AddUsedElemFailed(u16),
    #[error("Failed to create new EventFd")]
    EventFdFailed,
    #[error("Failed to add control message in the internal queue")]
    RxCtrlQueueAddFailed,
    #[error("Error adding epoll")]
    EpollAdd,
    #[error("Error removing epoll")]
    EpollRemove,
    #[error("Error creating epoll")]
    EpollFdCreate,
}

impl From<Error> for io::Error {
    fn from(err: Error) -> Self {
        Self::new(io::ErrorKind::Other, err)
    }
}

/// Queue events
#[repr(u16)]
#[derive(Copy, Clone, Debug)]
enum QueueEvents {
    RxQueue = 0,
    TxQueue = 1,
    CtrlRxQueue = 2,
    CtrlTxQueue = 3,
    /// `BACKEND_RX_EFD` is being triggered when the backend has new data to
    /// send to the RX queue.
    BackendRxEfd = (VhostUserConsoleBackend::NUM_QUEUES + 1),
    /// `BACKEND_CTRL_RX_EFD` event is used when the backend needs to write to
    /// the RX control queue.
    BackendCtrlRxEfd = (VhostUserConsoleBackend::NUM_QUEUES + 2),
    KeyEfd = (VhostUserConsoleBackend::NUM_QUEUES + 3),
    ListenerEfd = (VhostUserConsoleBackend::NUM_QUEUES + 4),
    ExitEfd = (VhostUserConsoleBackend::NUM_QUEUES + 5),
}

impl QueueEvents {
    const RX_QUEUE: u16 = Self::RxQueue as u16;
    const TX_QUEUE: u16 = Self::TxQueue as u16;
    const CTRL_RX_QUEUE: u16 = Self::CtrlRxQueue as u16;
    const CTRL_TX_QUEUE: u16 = Self::CtrlTxQueue as u16;
    // The two following events are used to help the vhu_console
    // backend trigger events to itself. For example:
    const BACKEND_RX_EFD: u16 = Self::BackendRxEfd as u16;
    const BACKEND_CTRL_RX_EFD: u16 = Self::BackendCtrlRxEfd as u16;
    const KEY_EFD: u16 = Self::KeyEfd as u16;
    const LISTENER_EFD: u16 = Self::ListenerEfd as u16;
    const EXIT_EFD: u16 = Self::ExitEfd as u16;
}

/// Port name
///
/// Need to be updated when `MULTIPORT` feature is supported for more than one
/// devices.
const PORT_NAME: &[u8] = b"org.test.foo!";

// Define a new trait that combines Read and Write
pub trait ReadWrite: Read + Write {}

impl<T: Read + Write> ReadWrite for T {}

// SAFETY: The layout of the structure is fixed and can be initialized by
// reading its content from byte array.
unsafe impl ByteValued for VirtioConsoleControl {}

pub struct VhostUserConsoleBackend {
    max_queue_size: usize,
    controller: Arc<RwLock<ConsoleController>>,
    acked_features: u64,
    event_idx: bool,
    rx_ctrl_fifo: Queue<VirtioConsoleControl>,
    rx_data_fifo: Queue<u8>,
    epoll_fd: i32,
    stream_fd: Option<i32>,
    pub ready: bool,
    pub ready_to_write: bool,
    pub output_queue: Queue<String>,
    pub stdin: Option<Box<dyn Read + Send + Sync>>,
    pub listener: Option<TcpListener>,
    pub stream: Option<Box<dyn ReadWrite + Send + Sync>>,
    pub rx_event: EventFd,
    pub rx_ctrl_event: EventFd,
    pub exit_event: EventFd,
    mem: Option<GuestMemoryAtomic<GuestMemoryMmap>>,
}

type ConsoleDescriptorChain = DescriptorChain<GuestMemoryLoadGuard<GuestMemoryMmap<()>>>;

impl VhostUserConsoleBackend {
    // Virtio configuration
    pub const NUM_QUEUES: u16 = 4;

    pub fn new(max_queue_size: usize, controller: Arc<RwLock<ConsoleController>>) -> Result<Self> {
        Ok(Self {
            max_queue_size,
            controller,
            event_idx: false,
            rx_ctrl_fifo: Queue::new(),
            rx_data_fifo: Queue::new(),
            epoll_fd: epoll::create(false).map_err(|_| Error::EpollFdCreate)?,
            stream_fd: None,
            acked_features: 0x0,
            ready: false,
            ready_to_write: false,
            output_queue: Queue::new(),
            stdin: None,
            stream: None,
            listener: None,
            rx_event: EventFd::new(EFD_NONBLOCK).map_err(|_| Error::EventFdFailed)?,
            rx_ctrl_event: EventFd::new(EFD_NONBLOCK).map_err(|_| Error::EventFdFailed)?,
            exit_event: EventFd::new(EFD_NONBLOCK).map_err(|_| Error::EventFdFailed)?,
            mem: None,
        })
    }

    pub fn assign_input_method(&mut self, tcpaddr_str: String) -> Result<()> {
        if self.controller.read().unwrap().backend == BackendType::Nested {
            // Enable raw mode for local terminal if backend is nested
            enable_raw_mode().expect("Raw mode error");

            let stdin_fd = io::stdin().as_raw_fd();
            let stdin: Box<dyn Read + Send + Sync> = Box::new(io::stdin());
            self.stdin = Some(stdin);

            Self::epoll_register(self.epoll_fd.as_raw_fd(), stdin_fd, epoll::Events::EPOLLIN)
                .map_err(|_| Error::EpollAdd)?;
        } else {
            let listener = TcpListener::bind(tcpaddr_str).expect("asdasd");
            self.listener = Some(listener);
        }
        Ok(())
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
        if requests.is_empty() {
            return Ok(true);
        }

        for desc_chain in requests {
            let atomic_mem = self.mem.as_ref().unwrap().memory();
            let mut writer = desc_chain
                .clone()
                .writer(&atomic_mem)
                .map_err(|_| Error::DescriptorWriteFailed)?;

            let avail_data_len = writer.available_bytes();
            let queue_len = self.rx_data_fifo.size();
            let min_limit = std::cmp::min(queue_len, avail_data_len);

            for _i in 0..min_limit {
                let response: u8 = match self.rx_data_fifo.remove() {
                    Ok(item) => item,
                    _ => {
                        return Ok(true);
                    }
                };

                writer
                    .write_obj::<u8>(response)
                    .map_err(|_| Error::DescriptorWriteFailed)?;

                vring
                    .add_used(desc_chain.head_index(), writer.bytes_written() as u32)
                    .map_err(|_| Error::AddUsedElemFailed(QueueEvents::RX_QUEUE))?;
            }
        }

        Ok(true)
    }

    fn process_tx_requests(
        &mut self,
        requests: Vec<ConsoleDescriptorChain>,
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

            let mut tx_data: Vec<u8> = Vec::new();
            let data_len = reader.available_bytes();
            for _i in 0..data_len {
                let data_byte = reader
                    .read_obj::<u8>()
                    .map_err(|_| Error::DescriptorReadFailed)?;
                tx_data.push(data_byte);
            }

            let my_string = String::from_utf8(tx_data).unwrap();
            if self.controller.read().unwrap().backend == BackendType::Nested {
                print!("{}", my_string);
                io::stdout().flush().unwrap();
            } else {
                self.output_queue
                    .add(my_string)
                    .map_err(|_| Error::RxCtrlQueueAddFailed)?;
                self.write_tcp_stream();
            }

            vring
                .add_used(desc_chain.head_index(), reader.bytes_read() as u32)
                .map_err(|_| Error::AddUsedElemFailed(QueueEvents::TX_QUEUE))?;
        }

        Ok(true)
    }

    fn process_ctrl_rx_requests(
        &mut self,
        requests: Vec<ConsoleDescriptorChain>,
        vring: &VringRwLock,
    ) -> Result<bool> {
        let mut used_flag = false;

        if requests.is_empty() {
            return Ok(true);
        }

        for desc_chain in requests {
            let atomic_mem = self.mem.as_ref().unwrap().memory();
            let mut writer = desc_chain
                .clone()
                .writer(&atomic_mem)
                .map_err(|_| Error::DescriptorWriteFailed)?;

            let ctrl_msg: VirtioConsoleControl = match self.rx_ctrl_fifo.remove() {
                Ok(item) => {
                    used_flag = true;
                    item
                }
                _ => {
                    return Ok(used_flag);
                }
            };

            self.print_console_frame(ctrl_msg);

            let mut buffer: Vec<u8> = Vec::new();
            buffer.extend_from_slice(&ctrl_msg.to_le_bytes());

            if ctrl_msg.event.to_native() == VIRTIO_CONSOLE_PORT_NAME {
                buffer.extend_from_slice(PORT_NAME);
            };

            writer
                .write(buffer.as_slice())
                .map_err(|_| Error::DescriptorWriteFailed)?;

            vring
                .add_used(desc_chain.head_index(), writer.bytes_written() as u32)
                .map_err(|_| Error::AddUsedElemFailed(QueueEvents::CTRL_RX_QUEUE))?;
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

                if ctrl_msg.value != 1 {
                    trace!("Guest failure in adding device");
                    return Ok(());
                }

                self.ready = true;
                ctrl_msg_reply.event = VIRTIO_CONSOLE_PORT_ADD.into();
                self.rx_ctrl_fifo
                    .add(ctrl_msg_reply)
                    .map_err(|_| Error::RxCtrlQueueAddFailed)?;
            }
            VIRTIO_CONSOLE_PORT_READY => {
                trace!("VIRTIO_CONSOLE_PORT_READY");

                if ctrl_msg.value != 1 {
                    trace!("Guest failure in adding port for device");
                    return Ok(());
                }

                ctrl_msg_reply.event = VIRTIO_CONSOLE_CONSOLE_PORT.into();
                self.rx_ctrl_fifo
                    .add(ctrl_msg_reply)
                    .map_err(|_| Error::RxCtrlQueueAddFailed)?;

                ctrl_msg_reply.event = VIRTIO_CONSOLE_PORT_NAME.into();
                self.rx_ctrl_fifo
                    .add(ctrl_msg_reply)
                    .map_err(|_| Error::RxCtrlQueueAddFailed)?;

                ctrl_msg_reply.event = VIRTIO_CONSOLE_PORT_OPEN.into();
                self.rx_ctrl_fifo
                    .add(ctrl_msg_reply)
                    .map_err(|_| Error::RxCtrlQueueAddFailed)?;
            }
            VIRTIO_CONSOLE_PORT_OPEN => {
                trace!("VIRTIO_CONSOLE_PORT_OPEN");
            }
            other => {
                trace!("Uknown control event: {}", other);
                return Err(Error::HandleEventUnknown(other));
            }
        };
        Ok(())
    }

    fn process_ctrl_tx_requests(
        &mut self,
        requests: Vec<ConsoleDescriptorChain>,
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

            let request = reader
                .read_obj::<VirtioConsoleControl>()
                .map_err(|_| Error::DescriptorReadFailed)?;

            // Print the receive console frame
            self.print_console_frame(request);

            // Process the received control frame
            self.handle_control_msg(request)?;

            // trigger a kick to the CTRL_RT_QUEUE
            self.rx_ctrl_event.write(1).unwrap();

            vring
                .add_used(desc_chain.head_index(), reader.bytes_read() as u32)
                .map_err(|_| Error::AddUsedElemFailed(QueueEvents::CTRL_TX_QUEUE))?;
        }

        Ok(true)
    }

    /// Process the messages in the vring and dispatch replies
    fn process_rx_queue(&mut self, vring: &VringRwLock) -> Result<()> {
        let requests: Vec<_> = vring
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

    /// Process the messages in the vring and dispatch replies
    fn process_tx_queue(&mut self, vring: &VringRwLock) -> Result<()> {
        let requests: Vec<_> = vring
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
    fn process_ctrl_rx_queue(&mut self, vring: &VringRwLock) -> Result<()> {
        let requests: Vec<_> = vring
            .get_mut()
            .get_queue_mut()
            .iter(self.mem.as_ref().unwrap().memory())
            .map_err(|_| Error::DescriptorNotFound)?
            .collect();

        if self.process_ctrl_rx_requests(requests, vring)? {
            // Send notification once all the requests are processed
            vring
                .signal_used_queue()
                .map_err(|_| Error::NotificationFailed)?;
        }
        Ok(())
    }

    /// Process the messages in the vring and dispatch replies
    fn process_ctrl_tx_queue(&mut self, vring: &VringRwLock) -> Result<()> {
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
    pub fn set_vring_worker(&self, vring_worker: Arc<VringEpollHandler<Arc<RwLock<Self>>>>) {
        let rx_event_fd = self.rx_event.as_raw_fd();
        vring_worker
            .register_listener(
                rx_event_fd,
                EventSet::IN,
                u64::from(QueueEvents::BACKEND_RX_EFD),
            )
            .unwrap();

        let rx_ctrl_event_fd = self.rx_ctrl_event.as_raw_fd();
        vring_worker
            .register_listener(
                rx_ctrl_event_fd,
                EventSet::IN,
                u64::from(QueueEvents::BACKEND_CTRL_RX_EFD),
            )
            .unwrap();

        let exit_event_fd = self.exit_event.as_raw_fd();
        vring_worker
            .register_listener(
                exit_event_fd,
                EventSet::IN,
                u64::from(QueueEvents::EXIT_EFD),
            )
            .unwrap();

        let epoll_fd = self.epoll_fd.as_raw_fd();
        vring_worker
            .register_listener(epoll_fd, EventSet::IN, u64::from(QueueEvents::KEY_EFD))
            .unwrap();

        if self.controller.read().unwrap().backend == BackendType::Network {
            let listener_fd = self.listener.as_ref().expect("asd").as_raw_fd();
            vring_worker
                .register_listener(
                    listener_fd,
                    EventSet::IN,
                    u64::from(QueueEvents::LISTENER_EFD),
                )
                .unwrap();
        }
    }

    /// Register a file with an epoll to listen for events in evset.
    pub fn epoll_register(epoll_fd: RawFd, fd: RawFd, evset: epoll::Events) -> Result<()> {
        epoll::ctl(
            epoll_fd,
            epoll::ControlOptions::EPOLL_CTL_ADD,
            fd,
            epoll::Event::new(evset, fd as u64),
        )
        .map_err(|_| Error::EpollAdd)?;
        Ok(())
    }

    /// Remove a file from the epoll.
    pub fn epoll_unregister(epoll_fd: RawFd, fd: RawFd) -> Result<()> {
        epoll::ctl(
            epoll_fd,
            epoll::ControlOptions::EPOLL_CTL_DEL,
            fd,
            epoll::Event::new(epoll::Events::empty(), 0),
        )
        .map_err(|_| Error::EpollRemove)?;

        Ok(())
    }

    fn create_new_stream_thread(&mut self) {
        // Accept only one incoming connection
        if let Some(stream) = self.listener.as_ref().expect("asd").incoming().next() {
            match stream {
                Ok(stream) => {
                    let local_addr = self
                        .listener
                        .as_ref()
                        .expect("No listener")
                        .local_addr()
                        .unwrap();
                    println!("New connection on: {}", local_addr);
                    let stream_raw_fd = stream.as_raw_fd();
                    self.stream_fd = Some(stream_raw_fd);
                    if let Err(err) = Self::epoll_register(
                        self.epoll_fd.as_raw_fd(),
                        stream_raw_fd,
                        epoll::Events::EPOLLIN,
                    ) {
                        warn!("Failed to register with epoll: {:?}", err);
                    }

                    let stream: Box<dyn ReadWrite + Send + Sync> = Box::new(stream);
                    self.stream = Some(stream);
                    self.write_tcp_stream();
                }
                Err(e) => {
                    eprintln!("Stream error: {}", e);
                }
            }
        }
    }

    fn write_tcp_stream(&mut self) {
        if self.stream.is_some() {
            while self.output_queue.size() > 0 {
                let byte_stream = self
                    .output_queue
                    .remove()
                    .expect("Error removing element from output queue")
                    .into_bytes();

                if let Err(e) = self
                    .stream
                    .as_mut()
                    .expect("Stream not found")
                    .write_all(&byte_stream)
                {
                    eprintln!("Error writing to stream: {}", e);
                }
            }
        }
    }

    fn read_tcp_stream(&mut self) {
        let mut buffer = [0; 1024];
        match self.stream.as_mut().expect("No stream").read(&mut buffer) {
            Ok(bytes_read) => {
                if bytes_read == 0 {
                    let local_addr = self
                        .listener
                        .as_ref()
                        .expect("No listener")
                        .local_addr()
                        .unwrap();
                    println!("Close connection on: {}", local_addr);
                    if let Err(err) = Self::epoll_unregister(
                        self.epoll_fd.as_raw_fd(),
                        self.stream_fd.expect("No stream fd"),
                    ) {
                        warn!("Failed to register with epoll: {:?}", err);
                    }
                    return;
                }
                if self.ready_to_write {
                    for byte in buffer.iter().take(bytes_read) {
                        self.rx_data_fifo.add(*byte).unwrap();
                    }
                    self.rx_event.write(1).unwrap();
                }
            }
            Err(e) => {
                eprintln!("Error reading from socket: {}", e);
            }
        }
    }

    fn read_char_thread(&mut self) -> IoResult<()> {
        let mut bytes = [0; 1];
        match self.stdin.as_mut().expect("No stdin").read(&mut bytes) {
            Ok(read_len) => {
                if read_len > 0 {
                    // If the user presses ^C then exit
                    if bytes[0] == 3 {
                        disable_raw_mode().expect("Raw mode error");
                        trace!("Termination!\n");
                        std::process::exit(0);
                    }

                    // If backend is ready pass the data to vhu_console
                    // and trigger an EventFd.
                    if self.ready_to_write {
                        self.rx_data_fifo.add(bytes[0]).unwrap();
                        self.rx_event.write(1).unwrap();
                    }
                }
                Ok(())
            }
            Err(e) => {
                eprintln!("Read stdin error: {}", e);
                Err(e)
            }
        }
    }

    pub fn prepare_exit(&self) {
        /* For the nested backend */
        if self.controller.read().unwrap().backend == BackendType::Nested {
            disable_raw_mode().expect("Raw mode error");
        }
    }
}

/// VhostUserBackendMut trait methods
impl VhostUserBackendMut for VhostUserConsoleBackend {
    type Vring = VringRwLock;
    type Bitmap = ();

    fn num_queues(&self) -> usize {
        usize::from(Self::NUM_QUEUES)
    }

    fn max_queue_size(&self) -> usize {
        self.max_queue_size
    }

    fn features(&self) -> u64 {
        (1 << VIRTIO_F_VERSION_1)
            | (1 << VIRTIO_F_NOTIFY_ON_EMPTY)
            | (1 << VIRTIO_RING_F_EVENT_IDX)
            | (1 << VIRTIO_RING_F_INDIRECT_DESC)
            | (1 << VIRTIO_CONSOLE_F_MULTIPORT)
            | VhostUserVirtioFeatures::PROTOCOL_FEATURES.bits()
    }

    fn acked_features(&mut self, features: u64) {
        self.acked_features = features;
    }

    fn protocol_features(&self) -> VhostUserProtocolFeatures {
        VhostUserProtocolFeatures::MQ
            | VhostUserProtocolFeatures::CONFIG
            | VhostUserProtocolFeatures::REPLY_ACK
    }

    fn get_config(&self, offset: u32, size: u32) -> Vec<u8> {
        debug_assert_eq!(
            std::mem::size_of::<*const u8>(),
            8,
            "If we start supporting non-64-bit pointers, remove the following clippy lint."
        );
        #[allow(clippy::cast_possible_wrap)]
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
                    .offset(offset as isize),
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
        if device_event == QueueEvents::EXIT_EFD {
            self.prepare_exit();
            return Ok(());
        }

        if device_event == QueueEvents::LISTENER_EFD {
            self.create_new_stream_thread();
            return Ok(());
        }

        if device_event == QueueEvents::KEY_EFD {
            if self.controller.read().unwrap().backend == BackendType::Nested {
                return self.read_char_thread();
            } else {
                self.read_tcp_stream();
                return Ok(());
            }
        }

        let vring = if device_event == QueueEvents::BACKEND_RX_EFD {
            &vrings[QueueEvents::RX_QUEUE as usize]
        } else if device_event == QueueEvents::BACKEND_CTRL_RX_EFD {
            &vrings[QueueEvents::CTRL_RX_QUEUE as usize]
        } else if device_event < Self::NUM_QUEUES {
            &vrings[device_event as usize]
        } else {
            return Err(Error::HandleEventUnknown(device_event).into());
        };

        if self.event_idx {
            loop {
                vring.disable_notification().unwrap();
                match device_event {
                    QueueEvents::RX_QUEUE => {
                        if self.rx_data_fifo.size() != 0 {
                            self.process_rx_queue(vring)
                        } else {
                            break;
                        }
                    }
                    QueueEvents::TX_QUEUE => {
                        self.ready_to_write = true;
                        self.process_tx_queue(vring)
                    }
                    QueueEvents::CTRL_RX_QUEUE => {
                        if self.ready && (self.rx_ctrl_fifo.size() != 0) {
                            self.process_ctrl_rx_queue(vring)
                        } else {
                            break;
                        }
                    }
                    QueueEvents::CTRL_TX_QUEUE => self.process_ctrl_tx_queue(vring),
                    QueueEvents::BACKEND_RX_EFD => {
                        let _ = self.rx_event.read();
                        self.process_rx_queue(vring)
                    }
                    QueueEvents::BACKEND_CTRL_RX_EFD => {
                        let _ = self.rx_ctrl_event.read();
                        self.process_ctrl_rx_queue(vring)
                    }
                    other => Err(Error::HandleEventUnknown(other)),
                }?;
                if !vring.enable_notification().unwrap() {
                    break;
                }
            }
        } else {
            match device_event {
                QueueEvents::RX_QUEUE => self.process_rx_queue(vring),
                QueueEvents::TX_QUEUE => {
                    self.ready_to_write = true;
                    self.process_tx_queue(vring)
                }
                QueueEvents::CTRL_RX_QUEUE => self.process_ctrl_rx_queue(vring),
                QueueEvents::CTRL_TX_QUEUE => self.process_ctrl_tx_queue(vring),
                QueueEvents::BACKEND_RX_EFD => {
                    let _ = self.rx_event.read();
                    self.process_rx_queue(vring)
                }
                QueueEvents::BACKEND_CTRL_RX_EFD => {
                    let _ = self.rx_ctrl_event.read();
                    self.process_ctrl_rx_queue(vring)
                }
                other => Err(Error::HandleEventUnknown(other)),
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
    use std::io::Cursor;

    use virtio_bindings::virtio_ring::{VRING_DESC_F_NEXT, VRING_DESC_F_WRITE};
    use virtio_queue::{
        desc::{split::Descriptor as SplitDescriptor, RawDescriptor},
        mock::MockSplitQueue,
        Queue,
    };
    use vm_memory::{Bytes, GuestAddress, GuestMemoryAtomic, GuestMemoryMmap};

    use super::*;
    use crate::DEFAULT_QUEUE_SIZE;

    #[test]
    fn test_vhost_user_console_backend_creation() {
        let console_controller = Arc::new(RwLock::new(ConsoleController::new(BackendType::Nested)));
        let vhost_user_console_backend =
            VhostUserConsoleBackend::new(DEFAULT_QUEUE_SIZE, console_controller)
                .expect("Failed create vhuconsole backend");

        assert_eq!(vhost_user_console_backend.acked_features, 0);
        assert!(!vhost_user_console_backend.event_idx);
        assert!(!vhost_user_console_backend.ready);
        assert!(!vhost_user_console_backend.ready_to_write);
    }

    #[test]
    fn test_virtio_console_empty_handle_request() {
        let console_controller = Arc::new(RwLock::new(ConsoleController::new(BackendType::Nested)));
        let mut vu_console_backend =
            VhostUserConsoleBackend::new(DEFAULT_QUEUE_SIZE, console_controller)
                .expect("Failed create vhuconsole backend");

        let mem = GuestMemoryAtomic::new(
            GuestMemoryMmap::<()>::from_ranges(&[(GuestAddress(0), 0x1000)]).unwrap(),
        );

        vu_console_backend.update_memory(mem.clone()).unwrap();

        let vring = VringRwLock::new(mem, 0x1000).unwrap();
        vring.set_queue_info(0x100, 0x200, 0x300).unwrap();
        vring.set_queue_ready(true);
        let list_vrings = [vring.clone(), vring.clone(), vring.clone(), vring];

        vu_console_backend
            .handle_event(QueueEvents::RX_QUEUE, EventSet::IN, &list_vrings, 0)
            .unwrap();

        vu_console_backend
            .handle_event(QueueEvents::TX_QUEUE, EventSet::IN, &list_vrings, 0)
            .unwrap();

        vu_console_backend
            .handle_event(QueueEvents::CTRL_RX_QUEUE, EventSet::IN, &list_vrings, 0)
            .unwrap();

        vu_console_backend
            .handle_event(QueueEvents::CTRL_TX_QUEUE, EventSet::IN, &list_vrings, 0)
            .unwrap();

        vu_console_backend
            .handle_event(QueueEvents::BACKEND_RX_EFD, EventSet::IN, &list_vrings, 0)
            .unwrap();

        vu_console_backend
            .handle_event(
                QueueEvents::BACKEND_CTRL_RX_EFD,
                EventSet::IN,
                &list_vrings,
                0,
            )
            .unwrap();
    }

    #[test]
    fn test_virtio_console_empty_requests() {
        let console_controller = Arc::new(RwLock::new(ConsoleController::new(BackendType::Nested)));
        let mut vu_console_backend =
            VhostUserConsoleBackend::new(DEFAULT_QUEUE_SIZE, console_controller)
                .expect("Failed create vhuconsole backend");

        let mem = GuestMemoryAtomic::new(
            GuestMemoryMmap::<()>::from_ranges(&[(GuestAddress(0), 0x1000)]).unwrap(),
        );

        let vring = VringRwLock::new(mem, 0x1000).unwrap();

        // Empty descriptor chain should be ignored
        vu_console_backend
            .process_rx_requests(Vec::<ConsoleDescriptorChain>::new(), &vring)
            .unwrap();
        vu_console_backend
            .process_tx_requests(Vec::<ConsoleDescriptorChain>::new(), &vring)
            .unwrap();
        vu_console_backend
            .process_ctrl_rx_requests(Vec::<ConsoleDescriptorChain>::new(), &vring)
            .unwrap();
        vu_console_backend
            .process_ctrl_tx_requests(Vec::<ConsoleDescriptorChain>::new(), &vring)
            .unwrap();
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

            let desc = RawDescriptor::from(SplitDescriptor::new(
                u64::from(0x100 * (i + 1)),
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
    fn test_virtio_console_ctrl_rx_request() {
        let console_controller = Arc::new(RwLock::new(ConsoleController::new(BackendType::Nested)));
        let mut vu_console_backend =
            VhostUserConsoleBackend::new(DEFAULT_QUEUE_SIZE, console_controller)
                .expect("Failed create vhuconsole backend");

        let mem = GuestMemoryMmap::<()>::from_ranges(&[(GuestAddress(0), 0x1000)]).unwrap();

        // Test 1: Empty queue
        let mem1 = GuestMemoryAtomic::new(mem.clone());
        let vring = VringRwLock::new(mem1, 0x1000).unwrap();
        assert!(vu_console_backend
            .process_ctrl_rx_requests(vec![], &vring)
            .unwrap());

        // Test 2: Found no rx elements
        let desc_chain = build_desc_chain(&mem, 1, vec![0], 0x200);
        let mem1 = GuestMemoryAtomic::new(mem.clone());
        let vring = VringRwLock::new(mem1.clone(), 0x1000).unwrap();
        vu_console_backend.update_memory(mem1).unwrap();

        assert!(!vu_console_backend
            .process_ctrl_rx_requests(vec![desc_chain], &vring)
            .unwrap());

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
        let mem1 = GuestMemoryAtomic::new(mem);
        let vring = VringRwLock::new(mem1.clone(), 0x1000).unwrap();
        vu_console_backend.update_memory(mem1).unwrap();

        let ctrl_msg = VirtioConsoleControl {
            id: 0.into(),
            event: VIRTIO_CONSOLE_PORT_NAME.into(),
            value: 1.into(),
        };
        let _ = vu_console_backend.rx_ctrl_fifo.add(ctrl_msg);

        assert!(vu_console_backend
            .process_ctrl_rx_requests(vec![desc_chain], &vring)
            .unwrap());
    }

    #[test]
    fn test_virtio_console_ctrl_tx_request() {
        let console_controller = Arc::new(RwLock::new(ConsoleController::new(BackendType::Nested)));
        let mut vu_console_backend =
            VhostUserConsoleBackend::new(DEFAULT_QUEUE_SIZE, console_controller)
                .expect("Failed create vhuconsole backend");

        let mem = GuestMemoryMmap::<()>::from_ranges(&[(GuestAddress(0), 0x1000)]).unwrap();

        // Test 1: Empty queue
        let mem1 = GuestMemoryAtomic::new(mem.clone());
        let vring = VringRwLock::new(mem1, 0x1000).unwrap();
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
            Error::DescriptorReadFailed
        );

        // Test 3: Smaller descriptor len than a console ctrl message
        let desc_chain = build_desc_chain(&mem, 1, vec![0], 0x2);
        let mem1 = GuestMemoryAtomic::new(mem.clone());
        let vring = VringRwLock::new(mem1.clone(), 0x1000).unwrap();
        vu_console_backend.update_memory(mem1).unwrap();
        assert_eq!(
            vu_console_backend
                .process_ctrl_tx_requests(vec![desc_chain], &vring)
                .unwrap_err(),
            Error::DescriptorReadFailed
        );

        // Test 4: Complete function successfully -- VIRTIO_CONSOLE_PORT_READY message
        let desc_chain = build_desc_chain(&mem, 1, vec![0], 0x8);
        let mem1 = GuestMemoryAtomic::new(mem);
        let vring = VringRwLock::new(mem1.clone(), 0x1000).unwrap();
        vu_console_backend.update_memory(mem1).unwrap();
        assert!(vu_console_backend
            .process_ctrl_tx_requests(vec![desc_chain], &vring)
            .unwrap());
    }

    #[test]
    fn test_virtio_console_handle_control_msg() {
        let console_controller = Arc::new(RwLock::new(ConsoleController::new(BackendType::Nested)));
        let mut vu_console_backend =
            VhostUserConsoleBackend::new(DEFAULT_QUEUE_SIZE, console_controller)
                .expect("Failed create vhuconsole backend");

        let mem = GuestMemoryMmap::<()>::from_ranges(&[(GuestAddress(0), 0x1000)]).unwrap();
        let mem_1 = GuestMemoryAtomic::new(mem.clone());
        vu_console_backend.update_memory(mem_1).unwrap();

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

        vu_console_backend.handle_control_msg(ctrl_msg_3).unwrap();

        assert_eq!(
            vu_console_backend
                .handle_control_msg(ctrl_msg_err)
                .unwrap_err(),
            Error::HandleEventUnknown(4)
        );

        vu_console_backend.handle_control_msg(ctrl_msg_1).unwrap();

        // Update memory
        let mem_1 = GuestMemoryAtomic::new(mem);
        vu_console_backend.update_memory(mem_1).unwrap();

        vu_console_backend.handle_control_msg(ctrl_msg_2).unwrap();
    }

    #[test]
    fn test_virtio_console_tx_request() {
        let console_controller = Arc::new(RwLock::new(ConsoleController::new(BackendType::Nested)));
        let mut vu_console_backend =
            VhostUserConsoleBackend::new(DEFAULT_QUEUE_SIZE, console_controller)
                .expect("Failed create vhuconsole backend");

        let mem = GuestMemoryMmap::<()>::from_ranges(&[(GuestAddress(0), 0x1000)]).unwrap();

        // Test 1: Empty queue
        let mem1 = GuestMemoryAtomic::new(mem.clone());
        let vring = VringRwLock::new(mem1, 0x1000).unwrap();
        vu_console_backend
            .process_tx_requests(vec![], &vring)
            .unwrap();

        // Test 2: Empty buffer
        let desc_chain = build_desc_chain(&mem, 1, vec![0], 0x200);
        let mem1 = GuestMemoryAtomic::new(mem.clone());
        let vring = VringRwLock::new(mem1.clone(), 0x1000).unwrap();
        vu_console_backend.update_memory(mem1).unwrap();
        vu_console_backend
            .process_tx_requests(vec![desc_chain], &vring)
            .unwrap();

        // Test 3: Fill message to the buffer
        let desc_chain = build_desc_chain(&mem, 1, vec![0], 0x200);
        let desc_addr = desc_chain.clone().collect::<Vec<_>>()[0].addr();

        // Build the Vec with the desired string
        let mut buffer: Vec<u8> = Vec::new();
        let string_bytes = b"Hello!";
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

        vu_console_backend
            .process_tx_requests(vec![desc_chain], &vring)
            .unwrap();
    }

    #[test]
    fn test_virtio_console_tx_request_network() {
        let console_controller =
            Arc::new(RwLock::new(ConsoleController::new(BackendType::Network)));
        let mut vu_console_backend =
            VhostUserConsoleBackend::new(DEFAULT_QUEUE_SIZE, console_controller)
                .expect("Failed create vhuconsole backend");

        let mem = GuestMemoryMmap::<()>::from_ranges(&[(GuestAddress(0), 0x1000)]).unwrap();
        let desc_chain = build_desc_chain(&mem, 1, vec![0], 0x200);
        let mem1 = GuestMemoryAtomic::new(mem);
        let vring = VringRwLock::new(mem1.clone(), 0x1000).unwrap();

        // Test: Fill message to the buffer
        vu_console_backend.update_memory(mem1).unwrap();
        let desc_addr = desc_chain.clone().collect::<Vec<_>>()[0].addr();

        // Build the Vec with the desired string
        let mut buffer: Vec<u8> = Vec::new();
        let string_bytes = b"Hello!";
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

        vu_console_backend
            .process_tx_requests(vec![desc_chain], &vring)
            .unwrap();
    }

    #[test]
    fn test_virtio_console_rx_request() {
        let console_controller = Arc::new(RwLock::new(ConsoleController::new(BackendType::Nested)));
        let mut vu_console_backend =
            VhostUserConsoleBackend::new(DEFAULT_QUEUE_SIZE, console_controller)
                .expect("Failed create vhuconsole backend");

        let mem = GuestMemoryMmap::<()>::from_ranges(&[(GuestAddress(0), 0x1000)]).unwrap();

        // Test 1: Empty queue
        let mem1 = GuestMemoryAtomic::new(mem.clone());
        let vring = VringRwLock::new(mem1, 0x1000).unwrap();
        vu_console_backend
            .process_rx_requests(vec![], &vring)
            .unwrap();

        // Test 2: Empty buffer
        let desc_chain = build_desc_chain(&mem, 1, vec![0], 0x200);
        let mem1 = GuestMemoryAtomic::new(mem.clone());
        let vring = VringRwLock::new(mem1.clone(), 0x1000).unwrap();
        vu_console_backend.update_memory(mem1).unwrap();

        assert!(vu_console_backend
            .process_rx_requests(vec![desc_chain], &vring)
            .unwrap());

        // Test 3: Fill message to the buffer. The descriptor should be write-only
        let desc_chain = build_desc_chain(&mem, 1, vec![0], 0x200);
        let mem1 = GuestMemoryAtomic::new(mem.clone());
        let vring = VringRwLock::new(mem1.clone(), 0x1000).unwrap();
        vu_console_backend.update_memory(mem1).unwrap();

        let input_buffer = b"Hello!";
        // Add each byte individually to the rx_data_fifo
        for &byte in input_buffer.clone().iter() {
            let _ = vu_console_backend.rx_data_fifo.add(byte);
        }

        // available_data are 0 so min_limit is 0 too
        assert!(vu_console_backend
            .process_rx_requests(vec![desc_chain], &vring)
            .unwrap());

        // Test 4: Fill message to the buffer. Everything should work!
        let desc_chain = build_desc_chain(&mem, 1, vec![VRING_DESC_F_WRITE as u16], 0x200);
        let mem1 = GuestMemoryAtomic::new(mem);
        let vring = VringRwLock::new(mem1.clone(), 0x1000).unwrap();
        vu_console_backend.update_memory(mem1).unwrap();

        let input_buffer = b"Hello!";
        for &byte in input_buffer.clone().iter() {
            let _ = vu_console_backend.rx_data_fifo.add(byte);
        }
        assert!(vu_console_backend
            .process_rx_requests(vec![desc_chain.clone()], &vring)
            .unwrap());

        // Test 5: Verify written data
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

        assert_eq!(read_buffer, input_buffer);
    }

    #[test]
    fn test_virtio_console_start_nested_console_thread() {
        let console_controller = Arc::new(RwLock::new(ConsoleController::new(BackendType::Nested)));
        let mut vu_console_backend =
            VhostUserConsoleBackend::new(DEFAULT_QUEUE_SIZE, console_controller)
                .expect("Failed create vhuconsole backend");

        let mem = GuestMemoryMmap::<()>::from_ranges(&[(GuestAddress(0), 0x1000)]).unwrap();
        let mem = GuestMemoryAtomic::new(mem);
        vu_console_backend.update_memory(mem.clone()).unwrap();
        let vring = VringRwLock::new(mem, 0x1000).unwrap();

        let input_data = b"H";
        let cursor = Cursor::new(input_data.clone().to_vec());

        // Replace stdin with a cursor for testing
        vu_console_backend.stdin = Some(Box::new(cursor));

        vu_console_backend.ready_to_write = true;
        vu_console_backend
            .handle_event(QueueEvents::KEY_EFD, EventSet::IN, &[vring], 0)
            .unwrap();

        let received_byte = vu_console_backend.rx_data_fifo.peek();

        // verify that the character has been received and is the one we sent
        assert_eq!(received_byte.unwrap(), input_data[0]);
    }

    #[test]
    fn test_virtio_console_tcp_console_read_func() {
        let console_controller =
            Arc::new(RwLock::new(ConsoleController::new(BackendType::Network)));
        let mut vu_console_backend =
            VhostUserConsoleBackend::new(DEFAULT_QUEUE_SIZE, console_controller)
                .expect("Failed create vhuconsole backend");

        let mem = GuestMemoryMmap::<()>::from_ranges(&[(GuestAddress(0), 0x1000)]).unwrap();
        let mem = GuestMemoryAtomic::new(mem);
        vu_console_backend.update_memory(mem.clone()).unwrap();
        let vring = VringRwLock::new(mem, 0x1000).unwrap();

        let input_data = b"H";
        let cursor = Cursor::new(input_data.clone().to_vec());

        // Replace stream with a cursor for testing
        vu_console_backend.stream = Some(Box::new(cursor));

        vu_console_backend.ready_to_write = true;
        vu_console_backend
            .handle_event(QueueEvents::KEY_EFD, EventSet::IN, &[vring], 0)
            .unwrap();

        let received_byte = vu_console_backend.rx_data_fifo.peek();

        // verify that the character has been received and is the one we sent
        assert_eq!(received_byte.unwrap(), input_data[0]);
    }

    #[test]
    fn test_virtio_console_tcp_console_write_func() {
        let console_controller =
            Arc::new(RwLock::new(ConsoleController::new(BackendType::Network)));
        let mut vu_console_backend =
            VhostUserConsoleBackend::new(DEFAULT_QUEUE_SIZE, console_controller)
                .expect("Failed create vhuconsole backend");

        let mem = GuestMemoryMmap::<()>::from_ranges(&[(GuestAddress(0), 0x1000)]).unwrap();
        let mem = GuestMemoryAtomic::new(mem);
        vu_console_backend.update_memory(mem).unwrap();

        // Test 1: Call the actual read function
        let cursor = Cursor::new(Vec::new());

        vu_console_backend.stream = Some(Box::new(cursor));
        vu_console_backend
            .output_queue
            .add("Test".to_string())
            .unwrap();
        vu_console_backend.write_tcp_stream();

        // All data has been consumed by the cursor
        assert_eq!(vu_console_backend.output_queue.size(), 0);
    }
}
