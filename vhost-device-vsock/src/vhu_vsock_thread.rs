// SPDX-License-Identifier: Apache-2.0 or BSD-3-Clause

use std::{
    collections::{HashMap, HashSet},
    io::{self, BufRead, BufReader},
    iter::FromIterator,
    num::Wrapping,
    ops::Deref,
    os::unix::{
        net::{UnixListener, UnixStream},
        prelude::{AsRawFd, RawFd},
    },
    sync::{
        mpsc::{self, Sender},
        Arc, Mutex, RwLock,
    },
    thread,
    time::Duration,
};

use log::{error, warn};
use mio::{unix::SourceFd, Events, Interest, Poll, Token};
use vhost_user_backend::{EventSet, VringEpollHandler, VringRwLock, VringT};
use virtio_queue::QueueOwnedT;
use virtio_vsock::packet::{VsockPacket, PKT_HEADER_SIZE};
use vm_memory::{GuestAddressSpace, GuestMemoryAtomic, GuestMemoryMmap};
use vmm_sys_util::event::{
    new_event_consumer_and_notifier, EventConsumer, EventFlag, EventNotifier,
};
#[cfg(feature = "backend_vsock")]
use vsock::{VsockListener, VMADDR_CID_ANY};

use crate::{
    rxops::*,
    thread_backend::*,
    vhu_vsock::{
        BackendType, CidMap, ConnMapKey, Error, Result, VhostUserVsockBackend, BACKEND_EVENT,
        SIBLING_VM_EVENT, VSOCK_HOST_CID,
    },
    vsock_conn::*,
};

type ArcVhostBknd = Arc<VhostUserVsockBackend>;

enum RxQueueType {
    Standard,
    RawPkts,
}

// Data which is required by a worker handling event idx.
struct EventData {
    vring: VringRwLock,
    event_idx: bool,
    head_idx: u16,
    used_len: usize,
}

enum ListenerType {
    Unix(UnixListener),
    #[cfg(feature = "backend_vsock")]
    Vsock(VsockListener),
}

pub(crate) struct VhostUserVsockThread {
    /// Guest memory map.
    pub mem: Option<GuestMemoryAtomic<GuestMemoryMmap>>,
    /// VIRTIO_RING_F_EVENT_IDX.
    pub event_idx: bool,
    backend_info: BackendType,
    /// Host socket raw file descriptor and listener.
    host_listeners_map: HashMap<i32, ListenerType>,
    /// poll fd to which new host connections are added.
    //poller which host connections are added
    poller: Arc<Mutex<Poll>>,
    /// VsockThreadBackend instance.
    pub thread_backend: VsockThreadBackend,
    /// CID of the guest.
    guest_cid: u64,
    /// Channel to a worker which handles event idx.
    sender: Sender<EventData>,
    /// host side port on which application listens.
    local_port: Wrapping<u32>,
    /// The tx buffer size
    tx_buffer_size: u32,
    /// EventConsumer to consume custom events. Currently used to
    /// notify this thread to process raw vsock packets sent from a sibling
    /// VM.
    pub sibling_event_consumer: EventConsumer,
    /// EventNotifier used by sibling devices to wake this thread.
    _sibling_event_notifier: EventNotifier,

    /// Keeps track of which RX queue was processed first in the last iteration.
    /// Used to alternate between the RX queues to prevent the starvation of one
    /// by the other.
    last_processed: RxQueueType,
}

impl VhostUserVsockThread {
    /// Create a new instance of VhostUserVsockThread.
    pub fn new(
        backend_info: BackendType,
        guest_cid: u64,
        tx_buffer_size: u32,
        groups: Vec<String>,
        cid_map: Arc<RwLock<CidMap>>,
    ) -> Result<Self> {
        let mut host_listeners_map = HashMap::new();
        match &backend_info {
            BackendType::UnixDomainSocket(uds_path) => {
                // TODO: better error handling, maybe add a param to force the unlink
                let _ = std::fs::remove_file(uds_path.clone());
                let host_listener = UnixListener::bind(uds_path)
                    .and_then(|sock| sock.set_nonblocking(true).map(|_| sock))
                    .map_err(Error::UnixBind)?;
                let host_sock = host_listener.as_raw_fd();
                host_listeners_map.insert(host_sock, ListenerType::Unix(host_listener));
            }
            #[cfg(feature = "backend_vsock")]
            BackendType::Vsock(vsock_info) => {
                for p in &vsock_info.listen_ports {
                    let host_listener = VsockListener::bind_with_cid_port(VMADDR_CID_ANY, *p)
                        .and_then(|sock| sock.set_nonblocking(true).map(|_| sock))
                        .map_err(Error::VsockBind)?;
                    let host_sock = host_listener.as_raw_fd();
                    host_listeners_map.insert(host_sock, ListenerType::Vsock(host_listener));
                }
            }
        }

        let poller = Arc::new(Mutex::new(Poll::new().map_err(Error::EpollFdCreate)?));

        let mut groups = groups;
        let groups_set: Arc<RwLock<HashSet<String>>> =
            Arc::new(RwLock::new(HashSet::from_iter(groups.drain(..))));

        let (sibling_event_consumer, sibling_event_notifier) =
            new_event_consumer_and_notifier(EventFlag::NONBLOCK).map_err(Error::EventFlagCreate)?;

        let thread_backend = VsockThreadBackend::new(
            backend_info.clone(),
            poller.clone(),
            guest_cid,
            tx_buffer_size,
            groups_set.clone(),
            cid_map.clone(),
        );

        {
            let mut cid_map = cid_map.write().unwrap();
            if cid_map.contains_key(&guest_cid) {
                return Err(Error::CidAlreadyInUse);
            }

            cid_map.insert(
                guest_cid,
                (
                    thread_backend.raw_pkts_queue.clone(),
                    groups_set,
                    sibling_event_notifier.try_clone().unwrap(),
                ),
            );
        }
        let (sender, receiver) = mpsc::channel::<EventData>();
        thread::spawn(move || loop {
            // TODO: Understand why doing the following in the background thread works.
            // maybe we'd better have thread pool for the entire application if necessary.
            let Ok(event_data) = receiver.recv() else {
                break;
            };
            Self::vring_handle_event(event_data);
        });

        let thread = VhostUserVsockThread {
            mem: None,
            event_idx: false,
            backend_info: backend_info.clone(),
            host_listeners_map,
            poller,
            thread_backend,
            guest_cid,
            sender,
            local_port: Wrapping(0),
            tx_buffer_size,
            sibling_event_consumer,
            _sibling_event_notifier: sibling_event_notifier,
            last_processed: RxQueueType::Standard,
        };

        for host_raw_fd in thread.host_listeners_map.keys() {
            VhostUserVsockThread::epoll_register(&thread.poller, *host_raw_fd, Interest::READABLE)?;
        }

        Ok(thread)
    }

    fn vring_handle_event(event_data: EventData) {
        if event_data.event_idx {
            if event_data
                .vring
                .add_used(event_data.head_idx, event_data.used_len as u32)
                .is_err()
            {
                warn!("Could not return used descriptors to ring");
            }
            match event_data.vring.needs_notification() {
                Err(_) => {
                    warn!("Could not check if queue needs to be notified");
                    event_data.vring.signal_used_queue().unwrap();
                }
                Ok(needs_notification) => {
                    if needs_notification {
                        event_data.vring.signal_used_queue().unwrap();
                    }
                }
            }
        } else {
            if event_data
                .vring
                .add_used(event_data.head_idx, event_data.used_len as u32)
                .is_err()
            {
                warn!("Could not return used descriptors to ring");
            }
            event_data.vring.signal_used_queue().unwrap();
        }
    }

    /// Register a file with an mio::poll to listen for events in interests.
    pub fn epoll_register(poller: &Arc<Mutex<Poll>>, fd: RawFd, interests: Interest) -> Result<()> {
        let mut source = SourceFd(&fd);

        poller
            .lock()
            .unwrap()
            .registry()
            .register(&mut source, Token(fd as usize), interests)
            .map_err(Error::EpollAdd)?;

        Ok(())
    }

    /// Remove a file from the mio::poller.
    pub fn epoll_unregister(poller: &Arc<Mutex<Poll>>, fd: RawFd) -> Result<()> {
        let mut source = SourceFd(&fd);

        poller
            .lock()
            .unwrap()
            .registry()
            .deregister(&mut source)
            .map_err(Error::EpollRemove)?;

        Ok(())
    }

    /// Modify the interests we listen to for the fd in the mio::poll.
    pub fn epoll_modify(poller: &Arc<Mutex<Poll>>, fd: RawFd, interests: Interest) -> Result<()> {
        let mut source = SourceFd(&fd);

        poller
            .lock()
            .unwrap()
            .registry()
            .reregister(&mut source, Token(fd as usize), interests)
            .map_err(Error::EpollModify)?;

        Ok(())
    }

    /// Return raw file descriptor of the epoll file.
    fn get_epoll_fd(&self) -> RawFd {
        self.poller.lock().unwrap().as_raw_fd()
    }

    /// Register our listeners in the VringEpollHandler
    pub fn register_listeners(&mut self, poll_handler: Arc<VringEpollHandler<ArcVhostBknd>>) {
        poll_handler
            .register_listener(
                self.get_epoll_fd(),
                EventSet::READABLE,
                u64::from(BACKEND_EVENT),
            )
            .unwrap();
        poll_handler
            .register_listener(
                self.sibling_event_consumer.as_raw_fd(),
                EventSet::READABLE,
                u64::from(SIBLING_VM_EVENT),
            )
            .unwrap();
    }

    /// Process a BACKEND_EVENT received by VhostUserVsockBackend.
    pub fn process_backend_evt(&mut self, _evset: EventSet) {
        let mut events = Events::with_capacity(32);
        loop {
            let polled = self
                .poller
                .lock()
                .unwrap()
                .poll(&mut events, Some(Duration::ZERO));
            match polled {
                Ok(()) => {
                    let ready: Vec<(RawFd, bool)> = events
                        .iter()
                        .map(|event| {
                            (
                                event.token().0.try_into().unwrap_or(-1) as RawFd,
                                event.is_writable(),
                            )
                        })
                        .collect();
                    for (fd, writable) in ready {
                        self.handle_event(fd, writable);
                    }
                    break;
                }
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(_) => {
                    warn!("failed to consume new poll event");
                    break;
                }
            }
        }
    }

    /// Handle a BACKEND_EVENT by either accepting a new connection or
    /// forwarding a request to the appropriate connection object.
    fn handle_event(&mut self, fd: RawFd, writable: bool) {
        if let Some(listener) = self.host_listeners_map.get(&fd) {
            // This is a new connection initiated by an application running on the host
            match listener {
                ListenerType::Unix(unix_listener) => {
                    let conn = unix_listener.accept().map_err(Error::UnixAccept);
                    if self.mem.is_some() {
                        conn.and_then(|(stream, _)| {
                            stream
                                .set_nonblocking(true)
                                .map(|_| stream)
                                .map_err(Error::UnixAccept)
                        })
                        .and_then(|stream| self.add_stream_listener(stream))
                        .unwrap_or_else(|err| {
                            warn!("Unable to accept new local connection: {err:?}");
                        });
                    } else {
                        // If we aren't ready to process requests, accept and immediately close
                        // the connection.
                        conn.map(drop).unwrap_or_else(|err| {
                            warn!("Error closing an incoming connection: {err:?}");
                        });
                    }
                }
                #[cfg(feature = "backend_vsock")]
                ListenerType::Vsock(vsock_listener) => {
                    let conn = vsock_listener.accept().map_err(Error::VsockAccept);
                    if self.mem.is_some() {
                        match conn {
                            Ok((stream, addr)) => {
                                if let Err(err) = stream.set_nonblocking(true) {
                                    warn!("Failed to set stream to non-blocking: {err:?}");
                                    return;
                                }

                                let peer_port = match vsock_listener.local_addr() {
                                    Ok(listener_addr) => listener_addr.port(),
                                    Err(err) => {
                                        warn!("Failed to get peer address: {err:?}");
                                        return;
                                    }
                                };

                                let local_port = addr.port();
                                let stream_raw_fd = stream.as_raw_fd();
                                self.add_new_connection_from_host(
                                    stream_raw_fd,
                                    StreamType::Vsock(stream),
                                    local_port,
                                    peer_port,
                                );
                                if let Err(err) = Self::epoll_register(
                                    &self.poller,
                                    stream_raw_fd,
                                    Interest::READABLE | Interest::WRITABLE,
                                ) {
                                    warn!("Failed to register with poller: {err:?}");
                                }
                            }
                            Err(err) => {
                                warn!("Unable to accept new local connection: {err:?}");
                            }
                        }
                    } else {
                        conn.map(drop).unwrap_or_else(|err| {
                            warn!("Error closing an incoming connection: {err:?}");
                        });
                    }
                }
            }
        } else {
            // Check if the stream represented by fd has already established a
            // connection with the application running in the guest
            if let std::collections::hash_map::Entry::Vacant(_) =
                self.thread_backend.listener_map.entry(fd)
            {
                // New connection from the host
                if writable {
                    // A brand-new host connection must first arrive as readable.
                    return;
                }
                let mut stream = match self.thread_backend.stream_map.remove(&fd) {
                    Some(s) => s,
                    None => {
                        warn!("Error while searching fd in the stream map");
                        return;
                    }
                };

                match stream {
                    #[cfg(feature = "backend_vsock")]
                    StreamType::Vsock(_) => {
                        error!("Stream type should not be of type vsock");
                    }
                    StreamType::Unix(ref mut unix_stream) => {
                        // Local peer is sending a "connect PORT\n" command
                        let peer_port = match Self::read_local_stream_port(unix_stream) {
                            Ok(port) => port,
                            Err(err) => {
                                warn!("Error while parsing \"connect PORT\n\" command: {err:?}");
                                return;
                            }
                        };

                        // Allocate a local port number
                        let local_port = match self.allocate_local_port() {
                            Ok(lp) => lp,
                            Err(err) => {
                                warn!("Error while allocating local port: {err:?}");
                                return;
                            }
                        };

                        self.add_new_connection_from_host(fd, stream, local_port, peer_port);

                        // Re-register the fd to listen for readable and writable events.
                        Self::epoll_modify(
                            &self.poller,
                            fd,
                            Interest::READABLE | Interest::WRITABLE,
                        )
                        .unwrap();
                    }
                }
            } else {
                // Previously connected connection

                let key = self.thread_backend.listener_map.get(&fd).unwrap();
                let conn = self.thread_backend.conn_map.get_mut(key).unwrap();

                if writable {
                    // Flush any remaining data from the tx buffer
                    match conn.tx_buf.flush_to(&mut conn.stream) {
                        Ok(cnt) => {
                            if cnt > 0 {
                                conn.fwd_cnt += Wrapping(cnt as u32);
                                conn.rx_queue.enqueue(RxOps::CreditUpdate);
                            } else {
                                // If no remaining data to flush, keep only readable interest.
                                if Self::epoll_modify(&self.poller, fd, Interest::READABLE).is_err()
                                {
                                    error!("Failed to disable writable interest");
                                }
                            }
                            self.thread_backend
                                .backend_rxq
                                .push_back(ConnMapKey::new(conn.local_port, conn.peer_port));
                        }
                        Err(e) => {
                            log::debug!("Error: {e:?}");
                        }
                    }
                    return;
                }

                // Unregister the stream from the poller and register it again when the
                // connection is established with the guest
                let _ = Self::epoll_unregister(&self.poller, fd);

                // Enqueue a read request
                conn.rx_queue.enqueue(RxOps::Rw);
                self.thread_backend
                    .backend_rxq
                    .push_back(ConnMapKey::new(conn.local_port, conn.peer_port));
            }
        }
    }

    fn add_new_connection_from_host(
        &mut self,
        fd: RawFd,
        stream: StreamType,
        local_port: u32,
        peer_port: u32,
    ) {
        // Insert the fd into the backend's maps
        self.thread_backend
            .listener_map
            .insert(fd, ConnMapKey::new(local_port, peer_port));

        // Create a new connection object an enqueue a connection request
        // packet to be sent to the guest
        let conn_map_key = ConnMapKey::new(local_port, peer_port);
        let mut new_conn = VsockConnection::new_local_init(
            stream,
            VSOCK_HOST_CID,
            local_port,
            self.guest_cid,
            peer_port,
            self.poller.clone(),
            self.tx_buffer_size,
        );
        new_conn.rx_queue.enqueue(RxOps::Request);
        new_conn.set_peer_port(peer_port);

        // Add connection object into the backend's maps
        self.thread_backend.conn_map.insert(conn_map_key, new_conn);

        self.thread_backend
            .backend_rxq
            .push_back(ConnMapKey::new(local_port, peer_port));
    }

    /// Allocate a new local port number.
    fn allocate_local_port(&mut self) -> Result<u32> {
        // TODO: Improve space efficiency of this operation
        // TODO: Reuse the conn_map HashMap
        // TODO: Test this.
        let mut alloc_local_port = self.local_port.0;
        loop {
            if !self
                .thread_backend
                .local_port_set
                .contains(&alloc_local_port)
            {
                // The port set doesn't contain the newly allocated port number.
                self.local_port = Wrapping(alloc_local_port + 1);
                self.thread_backend.local_port_set.insert(alloc_local_port);
                return Ok(alloc_local_port);
            } else {
                alloc_local_port = alloc_local_port.wrapping_add(1);
                if alloc_local_port == self.local_port.0 {
                    // We have exhausted our search and wrapped back to the starting port
                    return Err(Error::NoFreeLocalPort);
                }
            }
        }
    }

    /// Read `CONNECT PORT_NUM\n` from the connected stream.
    fn read_local_stream_port(stream: &mut UnixStream) -> Result<u32> {
        let mut buf = Vec::new();
        let mut reader = BufReader::new(stream);

        let n = reader
            .read_until(b'\n', &mut buf)
            .map_err(Error::UnixRead)?;

        let mut word_iter = std::str::from_utf8(&buf[..n])
            .map_err(Error::ConvertFromUtf8)?
            .split_whitespace();

        word_iter
            .next()
            .ok_or(Error::InvalidPortRequest)
            .and_then(|word| {
                if word.to_lowercase() == "connect" {
                    Ok(())
                } else {
                    Err(Error::InvalidPortRequest)
                }
            })
            .and_then(|_| word_iter.next().ok_or(Error::InvalidPortRequest))
            .and_then(|word| word.parse::<u32>().map_err(Error::ParseInteger))
            .map_err(|e| Error::ReadStreamPort(Box::new(e)))
    }

    /// Add a stream to the poller with readable interest.
    fn add_stream_listener(&mut self, stream: UnixStream) -> Result<()> {
        let stream_fd = stream.as_raw_fd();
        self.thread_backend
            .stream_map
            .insert(stream_fd, StreamType::Unix(stream));
        VhostUserVsockThread::epoll_register(&self.poller, stream_fd, Interest::READABLE)?;

        Ok(())
    }

    /// Iterate over the rx queue and process rx requests.
    fn process_rx_queue(&mut self, vring: &VringRwLock, rx_queue_type: RxQueueType) -> Result<()> {
        let atomic_mem = match &self.mem {
            Some(m) => m,
            None => return Err(Error::NoMemoryConfigured),
        };

        let mut vring_mut = vring.get_mut();

        let queue = vring_mut.get_queue_mut();

        while let Some(mut avail_desc) = queue
            .iter(atomic_mem.memory())
            .map_err(|_| Error::IterateQueue)?
            .next()
        {
            let mem = atomic_mem.clone().memory();

            let head_idx = avail_desc.head_index();
            let used_len = match VsockPacket::from_rx_virtq_chain(
                mem.deref(),
                &mut avail_desc,
                self.tx_buffer_size,
            ) {
                Ok(mut pkt) => {
                    let recv_result = match rx_queue_type {
                        RxQueueType::Standard => self.thread_backend.recv_pkt(&mut pkt),
                        RxQueueType::RawPkts => self.thread_backend.recv_raw_pkt(&mut pkt),
                    };

                    if recv_result.is_ok() {
                        PKT_HEADER_SIZE + pkt.len() as usize
                    } else {
                        queue.iter(mem).unwrap().go_to_previous_position();
                        break;
                    }
                }
                Err(e) => {
                    warn!("vsock: RX queue error: {e:?}");
                    0
                }
            };

            let vring = vring.clone();
            let event_idx = self.event_idx;
            self.sender
                .send(EventData {
                    vring,
                    event_idx,
                    head_idx,
                    used_len,
                })
                .unwrap();

            match rx_queue_type {
                RxQueueType::Standard => {
                    if !self.thread_backend.pending_rx() {
                        break;
                    }
                }
                RxQueueType::RawPkts => {
                    if !self.thread_backend.pending_raw_pkts() {
                        break;
                    }
                }
            }
        }
        Ok(())
    }

    /// Wrapper to process rx queue based on whether event idx is enabled or
    /// not.
    fn process_unix_sockets(&mut self, vring: &VringRwLock, event_idx: bool) -> Result<()> {
        if event_idx {
            // To properly handle EVENT_IDX we need to keep calling
            // process_rx_queue until it stops finding new requests
            // on the queue, as vm-virtio's Queue implementation
            // only checks avail_index once
            loop {
                if !self.thread_backend.pending_rx() {
                    break;
                }
                vring.disable_notification().unwrap();

                self.process_rx_queue(vring, RxQueueType::Standard)?;
                if !vring.enable_notification().unwrap() {
                    break;
                }
            }
        } else {
            self.process_rx_queue(vring, RxQueueType::Standard)?;
        }
        Ok(())
    }

    /// Wrapper to process raw vsock packets queue based on whether event idx is
    /// enabled or not.
    pub fn process_raw_pkts(&mut self, vring: &VringRwLock, event_idx: bool) -> Result<()> {
        if event_idx {
            loop {
                if !self.thread_backend.pending_raw_pkts() {
                    break;
                }
                vring.disable_notification().unwrap();

                self.process_rx_queue(vring, RxQueueType::RawPkts)?;
                if !vring.enable_notification().unwrap() {
                    break;
                }
            }
        } else {
            self.process_rx_queue(vring, RxQueueType::RawPkts)?;
        }
        Ok(())
    }

    pub fn process_rx(&mut self, vring: &VringRwLock, event_idx: bool) -> Result<()> {
        match self.last_processed {
            RxQueueType::Standard => {
                if self.thread_backend.pending_raw_pkts() {
                    self.process_raw_pkts(vring, event_idx)?;
                    self.last_processed = RxQueueType::RawPkts;
                }
                if self.thread_backend.pending_rx() {
                    self.process_unix_sockets(vring, event_idx)?;
                }
            }
            RxQueueType::RawPkts => {
                if self.thread_backend.pending_rx() {
                    self.process_unix_sockets(vring, event_idx)?;
                    self.last_processed = RxQueueType::Standard;
                }
                if self.thread_backend.pending_raw_pkts() {
                    self.process_raw_pkts(vring, event_idx)?;
                }
            }
        }
        Ok(())
    }

    /// Process tx queue and send requests to the backend for processing.
    fn process_tx_queue(&mut self, vring: &VringRwLock) -> Result<()> {
        let atomic_mem = match &self.mem {
            Some(m) => m,
            None => return Err(Error::NoMemoryConfigured),
        };

        while let Some(mut avail_desc) = vring
            .get_mut()
            .get_queue_mut()
            .iter(atomic_mem.memory())
            .map_err(|_| Error::IterateQueue)?
            .next()
        {
            let mem = atomic_mem.clone().memory();

            let head_idx = avail_desc.head_index();
            let pkt = match VsockPacket::from_tx_virtq_chain(
                mem.deref(),
                &mut avail_desc,
                self.tx_buffer_size,
            ) {
                Ok(pkt) => pkt,
                Err(e) => {
                    log::debug!("vsock: error reading TX packet: {e:?}");
                    continue;
                }
            };

            if self.thread_backend.send_pkt(&pkt).is_err() {
                vring
                    .get_mut()
                    .get_queue_mut()
                    .iter(mem)
                    .unwrap()
                    .go_to_previous_position();
                break;
            }

            // TODO: Check if the protocol requires read length to be correct
            let used_len = 0;

            let vring = vring.clone();
            let event_idx = self.event_idx;
            self.sender
                .send(EventData {
                    vring,
                    event_idx,
                    head_idx,
                    used_len,
                })
                .unwrap();
        }

        Ok(())
    }

    /// Wrapper to process tx queue based on whether event idx is enabled or
    /// not.
    pub fn process_tx(&mut self, vring_lock: &VringRwLock, event_idx: bool) -> Result<()> {
        if event_idx {
            // To properly handle EVENT_IDX we need to keep calling
            // process_rx_queue until it stops finding new requests
            // on the queue, as vm-virtio's Queue implementation
            // only checks avail_index once
            loop {
                vring_lock.disable_notification().unwrap();
                self.process_tx_queue(vring_lock)?;
                if !vring_lock.enable_notification().unwrap() {
                    break;
                }
            }
        } else {
            self.process_tx_queue(vring_lock)?;
        }
        Ok(())
    }
}

impl Drop for VhostUserVsockThread {
    fn drop(&mut self) {
        match &self.backend_info {
            BackendType::UnixDomainSocket(uds_path) => {
                let _ = std::fs::remove_file(uds_path);
            }
            #[cfg(feature = "backend_vsock")]
            BackendType::Vsock(_) => {
                // Nothing to do
            }
        }
        self.thread_backend
            .cid_map
            .write()
            .unwrap()
            .remove(&self.guest_cid);
    }
}
#[cfg(test)]
mod tests {
    use std::{
        collections::HashMap,
        io::{Read, Write},
        path::PathBuf,
    };

    use tempfile::tempdir;
    use vm_memory::GuestAddress;
    use vmm_sys_util::event::{new_event_consumer_and_notifier, EventFlag};
    #[cfg(feature = "backend_vsock")]
    use vsock::{VsockStream, VMADDR_CID_LOCAL};

    use super::*;
    #[cfg(feature = "backend_vsock")]
    use crate::vhu_vsock::VsockProxyInfo;

    const CONN_TX_BUF_SIZE: u32 = 64 * 1024;

    fn test_vsock_thread(backend_info: BackendType) {
        let groups: Vec<String> = vec![String::from("default")];

        let cid_map: Arc<RwLock<CidMap>> = Arc::new(RwLock::new(HashMap::new()));

        let t = VhostUserVsockThread::new(backend_info, 3, CONN_TX_BUF_SIZE, groups, cid_map);
        assert!(t.is_ok());

        let mut t = t.unwrap();
        let mem = GuestMemoryAtomic::new(
            GuestMemoryMmap::<()>::from_ranges(&[(GuestAddress(0), 0x10000)]).unwrap(),
        );

        t.mem = Some(mem.clone());

        let (dummy_fd, _dummy_notifier) =
            new_event_consumer_and_notifier(EventFlag::NONBLOCK).unwrap();

        VhostUserVsockThread::epoll_register(&t.poller, dummy_fd.as_raw_fd(), Interest::WRITABLE)
            .unwrap();
        VhostUserVsockThread::epoll_modify(&t.poller, dummy_fd.as_raw_fd(), Interest::READABLE)
            .unwrap();
        VhostUserVsockThread::epoll_unregister(&t.poller, dummy_fd.as_raw_fd()).unwrap();

        let vring = VringRwLock::new(mem, 0x1000).unwrap();
        vring.set_queue_info(0x100, 0x200, 0x300).unwrap();
        vring.set_queue_ready(true);

        t.process_tx(&vring, false).unwrap();
        t.process_tx(&vring, true).unwrap();
        // add backend_rxq to avoid that RX processing is skipped
        t.thread_backend
            .backend_rxq
            .push_back(ConnMapKey::new(0, 0));
        t.process_rx(&vring, false).unwrap();
        t.process_rx(&vring, true).unwrap();
        t.process_raw_pkts(&vring, false).unwrap();
        t.process_raw_pkts(&vring, true).unwrap();

        VhostUserVsockThread::vring_handle_event(EventData {
            vring: vring.clone(),
            event_idx: false,
            head_idx: 0,
            used_len: 0,
        });
        VhostUserVsockThread::vring_handle_event(EventData {
            vring,
            event_idx: true,
            head_idx: 0,
            used_len: 0,
        });

        _dummy_notifier.notify().unwrap();

        t.process_backend_evt(EventSet::empty());
    }

    #[test]
    fn test_vsock_thread_unix() {
        let test_dir = tempdir().expect("Could not create a temp test directory.");
        let backend_info =
            BackendType::UnixDomainSocket(test_dir.path().join("test_vsock_thread.vsock"));
        test_vsock_thread(backend_info);
        test_dir.close().unwrap();
    }

    #[cfg(feature = "backend_vsock")]
    #[test]
    fn test_vsock_thread_vsock() {
        let backend_info = BackendType::Vsock(VsockProxyInfo {
            forward_cid: 1,
            listen_ports: vec![],
        });
        test_vsock_thread(backend_info);
    }

    #[test]
    fn test_vsock_thread_failures() {
        let groups: Vec<String> = vec![String::from("default")];

        let cid_map: Arc<RwLock<CidMap>> = Arc::new(RwLock::new(HashMap::new()));

        let test_dir = tempdir().expect("Could not create a temp test directory.");

        let t = VhostUserVsockThread::new(
            BackendType::UnixDomainSocket(PathBuf::from("/sys/not_allowed.vsock")),
            3,
            CONN_TX_BUF_SIZE,
            groups.clone(),
            cid_map.clone(),
        );
        assert!(t.is_err());

        let vsock_socket_path = test_dir.path().join("test_vsock_thread_failures.vsock");
        let mut t = VhostUserVsockThread::new(
            BackendType::UnixDomainSocket(vsock_socket_path),
            3,
            CONN_TX_BUF_SIZE,
            groups.clone(),
            cid_map.clone(),
        )
        .unwrap();
        let invalid_poller = Arc::new(Mutex::new(Poll::new().unwrap()));
        assert!(
            VhostUserVsockThread::epoll_register(&invalid_poller, -1, Interest::READABLE).is_err()
        );
        assert!(
            VhostUserVsockThread::epoll_modify(&invalid_poller, -1, Interest::READABLE).is_err()
        );
        assert!(VhostUserVsockThread::epoll_unregister(&invalid_poller, -1).is_err());

        let mem = GuestMemoryAtomic::new(
            GuestMemoryMmap::<()>::from_ranges(&[(GuestAddress(0), 0x10000)]).unwrap(),
        );

        let vring = VringRwLock::new(mem, 0x1000).unwrap();

        // memory is not configured, so processing TX should fail
        assert!(t.process_tx(&vring, false).is_err());
        assert!(t.process_tx(&vring, true).is_err());

        // add backend_rxq to avoid that RX processing is skipped
        t.thread_backend
            .backend_rxq
            .push_back(ConnMapKey::new(0, 0));
        assert!(t.process_rx(&vring, false).is_err());
        assert!(t.process_rx(&vring, true).is_err());

        // trying to use a CID that is already in use should fail
        let vsock_socket_path2 = test_dir.path().join("test_vsock_thread_failures2.vsock");
        let t2 = VhostUserVsockThread::new(
            BackendType::UnixDomainSocket(vsock_socket_path2),
            3,
            CONN_TX_BUF_SIZE,
            groups,
            cid_map,
        );
        assert!(t2.is_err());

        test_dir.close().unwrap();
    }

    #[test]
    fn test_vsock_thread_unix_backend() {
        let groups: Vec<String> = vec![String::from("default")];
        let cid_map: Arc<RwLock<CidMap>> = Arc::new(RwLock::new(HashMap::new()));

        let test_dir = tempdir().expect("Could not create a temp test directory.");
        let vsock_path = test_dir.path().join("test_vsock_thread.vsock");

        let t = VhostUserVsockThread::new(
            BackendType::UnixDomainSocket(vsock_path.clone()),
            3,
            CONN_TX_BUF_SIZE,
            groups,
            cid_map,
        );

        let mut t = t.unwrap();

        let mem = GuestMemoryAtomic::new(
            GuestMemoryMmap::<()>::from_ranges(&[(GuestAddress(0), 0x10000)]).unwrap(),
        );

        t.mem = Some(mem.clone());

        let mut uds = UnixStream::connect(vsock_path).unwrap();
        t.process_backend_evt(EventSet::empty());

        uds.write_all(b"CONNECT 1234\n").unwrap();
        t.process_backend_evt(EventSet::empty());

        // Write and read something from the Unix socket
        uds.write_all(b"some data").unwrap();

        let mut buf = vec![0u8; 16];
        uds.set_nonblocking(true).unwrap();
        // There isn't any peer responding, so we don't expect data
        uds.read(&mut buf).unwrap_err();

        t.process_backend_evt(EventSet::empty());

        test_dir.close().unwrap();
    }

    #[cfg(feature = "backend_vsock")]
    #[test]
    fn test_vsock_thread_vsock_backend() {
        VsockListener::bind_with_cid_port(VMADDR_CID_LOCAL, libc::VMADDR_PORT_ANY).expect(
            "This test uses VMADDR_CID_LOCAL, so the vsock_loopback kernel module must be loaded",
        );

        let groups: Vec<String> = vec![String::from("default")];
        let cid_map: Arc<RwLock<CidMap>> = Arc::new(RwLock::new(HashMap::new()));

        let t = VhostUserVsockThread::new(
            BackendType::Vsock(VsockProxyInfo {
                forward_cid: VMADDR_CID_LOCAL,
                listen_ports: vec![9003, 9004],
            }),
            3,
            CONN_TX_BUF_SIZE,
            groups,
            cid_map,
        );

        let mut t = t.unwrap();

        let mem = GuestMemoryAtomic::new(
            GuestMemoryMmap::<()>::from_ranges(&[(GuestAddress(0), 0x10000)]).unwrap(),
        );

        t.mem = Some(mem.clone());

        let mut vs1 = VsockStream::connect_with_cid_port(VMADDR_CID_LOCAL, 9003).unwrap();
        let mut vs2 = VsockStream::connect_with_cid_port(VMADDR_CID_LOCAL, 9004).unwrap();
        t.process_backend_evt(EventSet::empty());

        vs1.write_all(b"some data").unwrap();
        vs2.write_all(b"some data").unwrap();
        t.process_backend_evt(EventSet::empty());

        let mut buf = vec![0u8; 16];
        vs1.set_nonblocking(true).unwrap();
        vs2.set_nonblocking(true).unwrap();
        // There isn't any peer responding, so we don't expect data
        vs1.read(&mut buf).unwrap_err();
        vs2.read(&mut buf).unwrap_err();

        t.process_backend_evt(EventSet::empty());
    }
}
