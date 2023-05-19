// SPDX-License-Identifier: Apache-2.0 or BSD-3-Clause

use std::{
    fs::File,
    io,
    io::Read,
    num::Wrapping,
    ops::Deref,
    os::unix::{
        net::{UnixListener, UnixStream},
        prelude::{AsRawFd, FromRawFd, RawFd},
    },
    sync::Arc,
};

use futures::executor::{ThreadPool, ThreadPoolBuilder};
use log::warn;
use vhost_user_backend::{VringEpollHandler, VringRwLock, VringT};
use virtio_queue::QueueOwnedT;
use virtio_vsock::packet::{VsockPacket, PKT_HEADER_SIZE};
use vm_memory::{GuestAddressSpace, GuestMemoryAtomic, GuestMemoryMmap};
use vmm_sys_util::epoll::EventSet;

use crate::{
    rxops::*,
    thread_backend::*,
    vhu_vsock::{ConnMapKey, Error, Result, VhostUserVsockBackend, BACKEND_EVENT, VSOCK_HOST_CID},
    vsock_conn::*,
};

type ArcVhostBknd = Arc<VhostUserVsockBackend>;

pub(crate) struct VhostUserVsockThread {
    /// Guest memory map.
    pub mem: Option<GuestMemoryAtomic<GuestMemoryMmap>>,
    /// VIRTIO_RING_F_EVENT_IDX.
    pub event_idx: bool,
    /// Host socket raw file descriptor.
    host_sock: RawFd,
    /// Host socket path
    host_sock_path: String,
    /// Listener listening for new connections on the host.
    host_listener: UnixListener,
    /// Instance of VringWorker.
    vring_worker: Option<Arc<VringEpollHandler<ArcVhostBknd, VringRwLock, ()>>>,
    /// epoll fd to which new host connections are added.
    epoll_file: File,
    /// VsockThreadBackend instance.
    pub thread_backend: VsockThreadBackend,
    /// CID of the guest.
    guest_cid: u64,
    /// Thread pool to handle event idx.
    pool: ThreadPool,
    /// host side port on which application listens.
    local_port: Wrapping<u32>,
    /// The tx buffer size
    tx_buffer_size: u32,
}

impl VhostUserVsockThread {
    /// Create a new instance of VhostUserVsockThread.
    pub fn new(uds_path: String, guest_cid: u64, tx_buffer_size: u32) -> Result<Self> {
        // TODO: better error handling, maybe add a param to force the unlink
        let _ = std::fs::remove_file(uds_path.clone());
        let host_sock = UnixListener::bind(&uds_path)
            .and_then(|sock| sock.set_nonblocking(true).map(|_| sock))
            .map_err(Error::UnixBind)?;

        let epoll_fd = epoll::create(true).map_err(Error::EpollFdCreate)?;
        // SAFETY: Safe as the fd is guaranteed to be valid here.
        let epoll_file = unsafe { File::from_raw_fd(epoll_fd) };

        let host_raw_fd = host_sock.as_raw_fd();

        let thread = VhostUserVsockThread {
            mem: None,
            event_idx: false,
            host_sock: host_sock.as_raw_fd(),
            host_sock_path: uds_path.clone(),
            host_listener: host_sock,
            vring_worker: None,
            epoll_file,
            thread_backend: VsockThreadBackend::new(uds_path, epoll_fd, tx_buffer_size),
            guest_cid,
            pool: ThreadPoolBuilder::new()
                .pool_size(1)
                .create()
                .map_err(Error::CreateThreadPool)?,
            local_port: Wrapping(0),
            tx_buffer_size,
        };

        VhostUserVsockThread::epoll_register(epoll_fd, host_raw_fd, epoll::Events::EPOLLIN)?;

        Ok(thread)
    }

    /// Register a file with an epoll to listen for events in evset.
    pub fn epoll_register(epoll_fd: RawFd, fd: RawFd, evset: epoll::Events) -> Result<()> {
        epoll::ctl(
            epoll_fd,
            epoll::ControlOptions::EPOLL_CTL_ADD,
            fd,
            epoll::Event::new(evset, fd as u64),
        )
        .map_err(Error::EpollAdd)?;

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
        .map_err(Error::EpollRemove)?;

        Ok(())
    }

    /// Modify the events we listen to for the fd in the epoll.
    pub fn epoll_modify(epoll_fd: RawFd, fd: RawFd, evset: epoll::Events) -> Result<()> {
        epoll::ctl(
            epoll_fd,
            epoll::ControlOptions::EPOLL_CTL_MOD,
            fd,
            epoll::Event::new(evset, fd as u64),
        )
        .map_err(Error::EpollModify)?;

        Ok(())
    }

    /// Return raw file descriptor of the epoll file.
    fn get_epoll_fd(&self) -> RawFd {
        self.epoll_file.as_raw_fd()
    }

    /// Set self's VringWorker.
    pub fn set_vring_worker(
        &mut self,
        vring_worker: Option<Arc<VringEpollHandler<ArcVhostBknd, VringRwLock, ()>>>,
    ) {
        self.vring_worker = vring_worker;
        self.vring_worker
            .as_ref()
            .unwrap()
            .register_listener(self.get_epoll_fd(), EventSet::IN, u64::from(BACKEND_EVENT))
            .unwrap();
    }

    /// Process a BACKEND_EVENT received by VhostUserVsockBackend.
    pub fn process_backend_evt(&mut self, _evset: EventSet) {
        let mut epoll_events = vec![epoll::Event::new(epoll::Events::empty(), 0); 32];
        'epoll: loop {
            match epoll::wait(self.epoll_file.as_raw_fd(), 0, epoll_events.as_mut_slice()) {
                Ok(ev_cnt) => {
                    for evt in epoll_events.iter().take(ev_cnt) {
                        self.handle_event(
                            evt.data as RawFd,
                            epoll::Events::from_bits(evt.events).unwrap(),
                        );
                    }
                }
                Err(e) => {
                    if e.kind() == io::ErrorKind::Interrupted {
                        continue;
                    }
                    warn!("failed to consume new epoll event");
                }
            }
            break 'epoll;
        }
    }

    /// Handle a BACKEND_EVENT by either accepting a new connection or
    /// forwarding a request to the appropriate connection object.
    fn handle_event(&mut self, fd: RawFd, evset: epoll::Events) {
        if fd == self.host_sock {
            // This is a new connection initiated by an application running on the host
            let conn = self.host_listener.accept().map_err(Error::UnixAccept);
            if self.mem.is_some() {
                conn.and_then(|(stream, _)| {
                    stream
                        .set_nonblocking(true)
                        .map(|_| stream)
                        .map_err(Error::UnixAccept)
                })
                .and_then(|stream| self.add_stream_listener(stream))
                .unwrap_or_else(|err| {
                    warn!("Unable to accept new local connection: {:?}", err);
                });
            } else {
                // If we aren't ready to process requests, accept and immediately close
                // the connection.
                conn.map(drop).unwrap_or_else(|err| {
                    warn!("Error closing an incoming connection: {:?}", err);
                });
            }
        } else {
            // Check if the stream represented by fd has already established a
            // connection with the application running in the guest
            if let std::collections::hash_map::Entry::Vacant(_) =
                self.thread_backend.listener_map.entry(fd)
            {
                // New connection from the host
                if evset != epoll::Events::EPOLLIN {
                    // Has to be EPOLLIN as it was not connected previously
                    return;
                }
                let mut unix_stream = match self.thread_backend.stream_map.remove(&fd) {
                    Some(uds) => uds,
                    None => {
                        warn!("Error while searching fd in the stream map");
                        return;
                    }
                };

                // Local peer is sending a "connect PORT\n" command
                let peer_port = match Self::read_local_stream_port(&mut unix_stream) {
                    Ok(port) => port,
                    Err(err) => {
                        warn!("Error while parsing \"connect PORT\n\" command: {:?}", err);
                        return;
                    }
                };

                // Allocate a local port number
                let local_port = match self.allocate_local_port() {
                    Ok(lp) => lp,
                    Err(err) => {
                        warn!("Error while allocating local port: {:?}", err);
                        return;
                    }
                };

                // Insert the fd into the backend's maps
                self.thread_backend
                    .listener_map
                    .insert(fd, ConnMapKey::new(local_port, peer_port));

                // Create a new connection object an enqueue a connection request
                // packet to be sent to the guest
                let conn_map_key = ConnMapKey::new(local_port, peer_port);
                let mut new_conn = VsockConnection::new_local_init(
                    unix_stream,
                    VSOCK_HOST_CID,
                    local_port,
                    self.guest_cid,
                    peer_port,
                    self.get_epoll_fd(),
                    self.tx_buffer_size,
                );
                new_conn.rx_queue.enqueue(RxOps::Request);
                new_conn.set_peer_port(peer_port);

                // Add connection object into the backend's maps
                self.thread_backend.conn_map.insert(conn_map_key, new_conn);

                self.thread_backend
                    .backend_rxq
                    .push_back(ConnMapKey::new(local_port, peer_port));

                // Re-register the fd to listen for EPOLLIN and EPOLLOUT events
                Self::epoll_modify(
                    self.get_epoll_fd(),
                    fd,
                    epoll::Events::EPOLLIN | epoll::Events::EPOLLOUT,
                )
                .unwrap();
            } else {
                // Previously connected connection
                let key = self.thread_backend.listener_map.get(&fd).unwrap();
                let conn = self.thread_backend.conn_map.get_mut(key).unwrap();

                if evset == epoll::Events::EPOLLOUT {
                    // Flush any remaining data from the tx buffer
                    match conn.tx_buf.flush_to(&mut conn.stream) {
                        Ok(cnt) => {
                            if cnt > 0 {
                                conn.fwd_cnt += Wrapping(cnt as u32);
                                conn.rx_queue.enqueue(RxOps::CreditUpdate);
                            }
                            self.thread_backend
                                .backend_rxq
                                .push_back(ConnMapKey::new(conn.local_port, conn.peer_port));
                        }
                        Err(e) => {
                            dbg!("Error: {:?}", e);
                        }
                    }
                    return;
                }

                // Unregister stream from the epoll, register when connection is
                // established with the guest
                Self::epoll_unregister(self.epoll_file.as_raw_fd(), fd).unwrap();

                // Enqueue a read request
                conn.rx_queue.enqueue(RxOps::Rw);
                self.thread_backend
                    .backend_rxq
                    .push_back(ConnMapKey::new(conn.local_port, conn.peer_port));
            }
        }
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
                if alloc_local_port == self.local_port.0 {
                    // We have exhausted our search and wrapped back to the current port number
                    return Err(Error::NoFreeLocalPort);
                }
                alloc_local_port += 1;
            }
        }
    }

    /// Read `CONNECT PORT_NUM\n` from the connected stream.
    fn read_local_stream_port(stream: &mut UnixStream) -> Result<u32> {
        let mut buf = [0u8; 32];

        // Minimum number of bytes we should be able to read
        // Corresponds to 'CONNECT 0\n'
        const MIN_READ_LEN: usize = 10;

        // Read in the minimum number of bytes we can read
        stream
            .read_exact(&mut buf[..MIN_READ_LEN])
            .map_err(Error::UnixRead)?;

        let mut read_len = MIN_READ_LEN;
        while buf[read_len - 1] != b'\n' && read_len < buf.len() {
            stream
                .read_exact(&mut buf[read_len..read_len + 1])
                .map_err(Error::UnixRead)?;
            read_len += 1;
        }

        let mut word_iter = std::str::from_utf8(&buf[..read_len])
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

    /// Add a stream to epoll to listen for EPOLLIN events.
    fn add_stream_listener(&mut self, stream: UnixStream) -> Result<()> {
        let stream_fd = stream.as_raw_fd();
        self.thread_backend.stream_map.insert(stream_fd, stream);
        VhostUserVsockThread::epoll_register(
            self.get_epoll_fd(),
            stream_fd,
            epoll::Events::EPOLLIN,
        )?;

        Ok(())
    }

    /// Iterate over the rx queue and process rx requests.
    fn process_rx_queue(&mut self, vring: &VringRwLock) -> Result<bool> {
        let mut used_any = false;
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
            used_any = true;
            let mem = atomic_mem.clone().memory();

            let head_idx = avail_desc.head_index();
            let used_len = match VsockPacket::from_rx_virtq_chain(
                mem.deref(),
                &mut avail_desc,
                self.tx_buffer_size,
            ) {
                Ok(mut pkt) => {
                    if self.thread_backend.recv_pkt(&mut pkt).is_ok() {
                        PKT_HEADER_SIZE + pkt.len() as usize
                    } else {
                        queue.iter(mem).unwrap().go_to_previous_position();
                        break;
                    }
                }
                Err(e) => {
                    warn!("vsock: RX queue error: {:?}", e);
                    0
                }
            };

            let vring = vring.clone();
            let event_idx = self.event_idx;

            self.pool.spawn_ok(async move {
                // TODO: Understand why doing the following in the pool works
                if event_idx {
                    if vring.add_used(head_idx, used_len as u32).is_err() {
                        warn!("Could not return used descriptors to ring");
                    }
                    match vring.needs_notification() {
                        Err(_) => {
                            warn!("Could not check if queue needs to be notified");
                            vring.signal_used_queue().unwrap();
                        }
                        Ok(needs_notification) => {
                            if needs_notification {
                                vring.signal_used_queue().unwrap();
                            }
                        }
                    }
                } else {
                    if vring.add_used(head_idx, used_len as u32).is_err() {
                        warn!("Could not return used descriptors to ring");
                    }
                    vring.signal_used_queue().unwrap();
                }
            });

            if !self.thread_backend.pending_rx() {
                break;
            }
        }
        Ok(used_any)
    }

    /// Wrapper to process rx queue based on whether event idx is enabled or not.
    pub fn process_rx(&mut self, vring: &VringRwLock, event_idx: bool) -> Result<bool> {
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

                self.process_rx_queue(vring)?;
                if !vring.enable_notification().unwrap() {
                    break;
                }
            }
        } else {
            self.process_rx_queue(vring)?;
        }
        Ok(false)
    }

    /// Process tx queue and send requests to the backend for processing.
    fn process_tx_queue(&mut self, vring: &VringRwLock) -> Result<bool> {
        let mut used_any = false;

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
            used_any = true;
            let mem = atomic_mem.clone().memory();

            let head_idx = avail_desc.head_index();
            let pkt = match VsockPacket::from_tx_virtq_chain(
                mem.deref(),
                &mut avail_desc,
                self.tx_buffer_size,
            ) {
                Ok(pkt) => pkt,
                Err(e) => {
                    dbg!("vsock: error reading TX packet: {:?}", e);
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

            self.pool.spawn_ok(async move {
                if event_idx {
                    if vring.add_used(head_idx, used_len as u32).is_err() {
                        warn!("Could not return used descriptors to ring");
                    }
                    match vring.needs_notification() {
                        Err(_) => {
                            warn!("Could not check if queue needs to be notified");
                            vring.signal_used_queue().unwrap();
                        }
                        Ok(needs_notification) => {
                            if needs_notification {
                                vring.signal_used_queue().unwrap();
                            }
                        }
                    }
                } else {
                    if vring.add_used(head_idx, used_len as u32).is_err() {
                        warn!("Could not return used descriptors to ring");
                    }
                    vring.signal_used_queue().unwrap();
                }
            });
        }

        Ok(used_any)
    }

    /// Wrapper to process tx queue based on whether event idx is enabled or not.
    pub fn process_tx(&mut self, vring_lock: &VringRwLock, event_idx: bool) -> Result<bool> {
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
        Ok(false)
    }
}

impl Drop for VhostUserVsockThread {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.host_sock_path);
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use serial_test::serial;
    use vm_memory::GuestAddress;
    use vmm_sys_util::eventfd::EventFd;

    const CONN_TX_BUF_SIZE: u32 = 64 * 1024;

    impl VhostUserVsockThread {
        fn get_epoll_file(&self) -> &File {
            &self.epoll_file
        }
    }

    #[test]
    #[serial]
    fn test_vsock_thread() {
        let t =
            VhostUserVsockThread::new("test_vsock_thread.vsock".to_string(), 3, CONN_TX_BUF_SIZE);
        assert!(t.is_ok());

        let mut t = t.unwrap();
        let epoll_fd = t.get_epoll_file().as_raw_fd();

        let mem = GuestMemoryAtomic::new(
            GuestMemoryMmap::<()>::from_ranges(&[(GuestAddress(0), 0x10000)]).unwrap(),
        );

        t.mem = Some(mem.clone());

        let dummy_fd = EventFd::new(0).unwrap();

        assert!(VhostUserVsockThread::epoll_register(
            epoll_fd,
            dummy_fd.as_raw_fd(),
            epoll::Events::EPOLLOUT
        )
        .is_ok());
        assert!(VhostUserVsockThread::epoll_modify(
            epoll_fd,
            dummy_fd.as_raw_fd(),
            epoll::Events::EPOLLIN
        )
        .is_ok());
        assert!(VhostUserVsockThread::epoll_unregister(epoll_fd, dummy_fd.as_raw_fd()).is_ok());
        assert!(VhostUserVsockThread::epoll_register(
            epoll_fd,
            dummy_fd.as_raw_fd(),
            epoll::Events::EPOLLIN
        )
        .is_ok());

        let vring = VringRwLock::new(mem, 0x1000).unwrap();
        vring.set_queue_info(0x100, 0x200, 0x300).unwrap();
        vring.set_queue_ready(true);

        assert!(t.process_tx(&vring, false).is_ok());
        assert!(t.process_tx(&vring, true).is_ok());
        // add backend_rxq to avoid that RX processing is skipped
        t.thread_backend
            .backend_rxq
            .push_back(ConnMapKey::new(0, 0));
        assert!(t.process_rx(&vring, false).is_ok());
        assert!(t.process_rx(&vring, true).is_ok());

        dummy_fd.write(1).unwrap();

        t.process_backend_evt(EventSet::empty());
    }

    #[test]
    #[serial]
    fn test_vsock_thread_failures() {
        let t =
            VhostUserVsockThread::new("/sys/not_allowed.vsock".to_string(), 3, CONN_TX_BUF_SIZE);
        assert!(t.is_err());

        let mut t = VhostUserVsockThread::new(
            "test_vsock_thread_failures.vsock".to_string(),
            3,
            CONN_TX_BUF_SIZE,
        )
        .unwrap();
        assert!(VhostUserVsockThread::epoll_register(-1, -1, epoll::Events::EPOLLIN).is_err());
        assert!(VhostUserVsockThread::epoll_modify(-1, -1, epoll::Events::EPOLLIN).is_err());
        assert!(VhostUserVsockThread::epoll_unregister(-1, -1).is_err());

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
    }
}
