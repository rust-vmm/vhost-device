// SPDX-License-Identifier: Apache-2.0 or BSD-3-Clause

use std::{
    collections::{HashMap, HashSet, VecDeque},
    os::unix::{
        net::UnixStream,
        prelude::{AsRawFd, FromRawFd, RawFd},
    },
    sync::{Arc, RwLock},
};

use log::{info, warn};
use virtio_vsock::packet::{VsockPacket, PKT_HEADER_SIZE};
use vm_memory::bitmap::BitmapSlice;

use crate::{
    rxops::*,
    vhu_vsock::{
        CidMap, ConnMapKey, Error, Result, VSOCK_HOST_CID, VSOCK_OP_REQUEST, VSOCK_OP_RST,
        VSOCK_TYPE_STREAM,
    },
    vhu_vsock_thread::VhostUserVsockThread,
    vsock_conn::*,
};

pub(crate) struct RawVsockPacket {
    pub header: [u8; PKT_HEADER_SIZE],
    pub data: Vec<u8>,
}

impl RawVsockPacket {
    fn from_vsock_packet<B: BitmapSlice>(pkt: &VsockPacket<B>) -> Result<Self> {
        let mut raw_pkt = Self {
            header: [0; PKT_HEADER_SIZE],
            data: vec![0; pkt.len() as usize],
        };

        pkt.header_slice().copy_to(&mut raw_pkt.header);
        if !pkt.is_empty() {
            pkt.data_slice()
                .ok_or(Error::PktBufMissing)?
                .copy_to(raw_pkt.data.as_mut());
        }

        Ok(raw_pkt)
    }
}

pub(crate) struct VsockThreadBackend {
    /// Map of ConnMapKey objects indexed by raw file descriptors.
    pub listener_map: HashMap<RawFd, ConnMapKey>,
    /// Map of vsock connection objects indexed by ConnMapKey objects.
    pub conn_map: HashMap<ConnMapKey, VsockConnection<UnixStream>>,
    /// Queue of ConnMapKey objects indicating pending rx operations.
    pub backend_rxq: VecDeque<ConnMapKey>,
    /// Map of host-side unix streams indexed by raw file descriptors.
    pub stream_map: HashMap<i32, UnixStream>,
    /// Host side socket for listening to new connections from the host.
    host_socket_path: String,
    /// epoll for registering new host-side connections.
    epoll_fd: i32,
    /// Set of allocated local ports.
    pub local_port_set: HashSet<u32>,
    tx_buffer_size: u32,
    /// Maps the guest CID to the corresponding backend. Used for sibling VM communication.
    cid_map: Arc<RwLock<CidMap>>,
    /// Queue of raw vsock packets recieved from sibling VMs to be sent to the guest.
    raw_pkts_queue: VecDeque<RawVsockPacket>,
}

impl VsockThreadBackend {
    /// New instance of VsockThreadBackend.
    pub fn new(
        host_socket_path: String,
        epoll_fd: i32,
        tx_buffer_size: u32,
        cid_map: Arc<RwLock<CidMap>>,
    ) -> Self {
        Self {
            listener_map: HashMap::new(),
            conn_map: HashMap::new(),
            backend_rxq: VecDeque::new(),
            // Need this map to prevent connected stream from closing
            // TODO: think of a better solution
            stream_map: HashMap::new(),
            host_socket_path,
            epoll_fd,
            local_port_set: HashSet::new(),
            tx_buffer_size,
            cid_map,
            raw_pkts_queue: VecDeque::new(),
        }
    }

    /// Checks if there are pending rx requests in the backend rxq.
    pub fn pending_rx(&self) -> bool {
        !self.backend_rxq.is_empty()
    }

    /// Checks if there are pending raw vsock packets to be sent to the guest.
    pub fn pending_raw_pkts(&self) -> bool {
        !self.raw_pkts_queue.is_empty()
    }

    /// Deliver a vsock packet to the guest vsock driver.
    ///
    /// Returns:
    /// - `Ok(())` if the packet was successfully filled in
    /// - `Err(Error::EmptyBackendRxQ) if there was no available data
    pub fn recv_pkt<B: BitmapSlice>(&mut self, pkt: &mut VsockPacket<B>) -> Result<()> {
        // Pop an event from the backend_rxq
        let key = self.backend_rxq.pop_front().ok_or(Error::EmptyBackendRxQ)?;
        let conn = match self.conn_map.get_mut(&key) {
            Some(conn) => conn,
            None => {
                // assume that the connection does not exist
                return Ok(());
            }
        };

        if conn.rx_queue.peek() == Some(RxOps::Reset) {
            // Handle RST events here
            let conn = self.conn_map.remove(&key).unwrap();
            self.listener_map.remove(&conn.stream.as_raw_fd());
            self.stream_map.remove(&conn.stream.as_raw_fd());
            self.local_port_set.remove(&conn.local_port);
            VhostUserVsockThread::epoll_unregister(conn.epoll_fd, conn.stream.as_raw_fd())
                .unwrap_or_else(|err| {
                    warn!(
                        "Could not remove epoll listener for fd {:?}: {:?}",
                        conn.stream.as_raw_fd(),
                        err
                    )
                });

            // Initialize the packet header to contain a VSOCK_OP_RST operation
            pkt.set_op(VSOCK_OP_RST)
                .set_src_cid(VSOCK_HOST_CID)
                .set_dst_cid(conn.guest_cid)
                .set_src_port(conn.local_port)
                .set_dst_port(conn.peer_port)
                .set_len(0)
                .set_type(VSOCK_TYPE_STREAM)
                .set_flags(0)
                .set_buf_alloc(0)
                .set_fwd_cnt(0);

            return Ok(());
        }

        // Handle other packet types per connection
        conn.recv_pkt(pkt)?;

        Ok(())
    }

    /// Deliver a guest generated packet to its destination in the backend.
    ///
    /// Absorbs unexpected packets, handles rest to respective connection
    /// object.
    ///
    /// Returns:
    /// - always `Ok(())` if packet has been consumed correctly
    pub fn send_pkt<B: BitmapSlice>(&mut self, pkt: &VsockPacket<B>) -> Result<()> {
        let dst_cid = pkt.dst_cid();
        if dst_cid != VSOCK_HOST_CID {
            let cid_map = self.cid_map.read().unwrap();
            if cid_map.contains_key(&dst_cid) {
                let sibling_backend = cid_map.get(&dst_cid).unwrap();
                let mut sibling_backend_thread = sibling_backend.threads[0].lock().unwrap();

                sibling_backend_thread
                    .thread_backend
                    .raw_pkts_queue
                    .push_back(RawVsockPacket::from_vsock_packet(pkt)?);
                let _ = sibling_backend_thread.sibling_event_fd.write(1);
            } else {
                warn!("vsock: dropping packet for unknown cid: {:?}", dst_cid);
            }

            return Ok(());
        }

        // TODO: Rst if packet has unsupported type
        if pkt.type_() != VSOCK_TYPE_STREAM {
            info!("vsock: dropping packet of unknown type");
            return Ok(());
        }

        let key = ConnMapKey::new(pkt.dst_port(), pkt.src_port());

        // TODO: Handle cases where connection does not exist and packet op
        // is not VSOCK_OP_REQUEST
        if !self.conn_map.contains_key(&key) {
            // The packet contains a new connection request
            if pkt.op() == VSOCK_OP_REQUEST {
                self.handle_new_guest_conn(pkt);
            } else {
                // TODO: send back RST
            }
            return Ok(());
        }

        if pkt.op() == VSOCK_OP_RST {
            // Handle an RST packet from the guest here
            let conn = self.conn_map.get(&key).unwrap();
            if conn.rx_queue.contains(RxOps::Reset.bitmask()) {
                return Ok(());
            }
            let conn = self.conn_map.remove(&key).unwrap();
            self.listener_map.remove(&conn.stream.as_raw_fd());
            self.stream_map.remove(&conn.stream.as_raw_fd());
            self.local_port_set.remove(&conn.local_port);
            VhostUserVsockThread::epoll_unregister(conn.epoll_fd, conn.stream.as_raw_fd())
                .unwrap_or_else(|err| {
                    warn!(
                        "Could not remove epoll listener for fd {:?}: {:?}",
                        conn.stream.as_raw_fd(),
                        err
                    )
                });
            return Ok(());
        }

        // Forward this packet to its listening connection
        let conn = self.conn_map.get_mut(&key).unwrap();
        conn.send_pkt(pkt)?;

        if conn.rx_queue.pending_rx() {
            // Required if the connection object adds new rx operations
            self.backend_rxq.push_back(key);
        }

        Ok(())
    }

    /// Deliver a raw vsock packet sent from a sibling VM to the guest vsock driver.
    ///
    /// Returns:
    /// - `Ok(())` if packet was successfully filled in
    /// - `Err(Error::EmptyRawPktsQueue)` if there was no available data
    pub fn recv_raw_pkt<B: BitmapSlice>(&mut self, pkt: &mut VsockPacket<B>) -> Result<()> {
        let raw_vsock_pkt = self
            .raw_pkts_queue
            .pop_front()
            .ok_or(Error::EmptyRawPktsQueue)?;

        pkt.set_header_from_raw(&raw_vsock_pkt.header).unwrap();
        if !raw_vsock_pkt.data.is_empty() {
            let buf = pkt.data_slice().ok_or(Error::PktBufMissing)?;
            buf.copy_from(&raw_vsock_pkt.data);
        }

        Ok(())
    }

    /// Handle a new guest initiated connection, i.e from the peer, the guest driver.
    ///
    /// Attempts to connect to a host side unix socket listening on a path
    /// corresponding to the destination port as follows:
    /// - "{self.host_sock_path}_{local_port}""
    fn handle_new_guest_conn<B: BitmapSlice>(&mut self, pkt: &VsockPacket<B>) {
        let port_path = format!("{}_{}", self.host_socket_path, pkt.dst_port());

        UnixStream::connect(port_path)
            .and_then(|stream| stream.set_nonblocking(true).map(|_| stream))
            .map_err(Error::UnixConnect)
            .and_then(|stream| self.add_new_guest_conn(stream, pkt))
            .unwrap_or_else(|_| self.enq_rst());
    }

    /// Wrapper to add new connection to relevant HashMaps.
    fn add_new_guest_conn<B: BitmapSlice>(
        &mut self,
        stream: UnixStream,
        pkt: &VsockPacket<B>,
    ) -> Result<()> {
        let stream_fd = stream.as_raw_fd();
        self.listener_map
            .insert(stream_fd, ConnMapKey::new(pkt.dst_port(), pkt.src_port()));

        let conn = VsockConnection::new_peer_init(
            stream,
            pkt.dst_cid(),
            pkt.dst_port(),
            pkt.src_cid(),
            pkt.src_port(),
            self.epoll_fd,
            pkt.buf_alloc(),
            self.tx_buffer_size,
        );

        self.conn_map
            .insert(ConnMapKey::new(pkt.dst_port(), pkt.src_port()), conn);
        self.backend_rxq
            .push_back(ConnMapKey::new(pkt.dst_port(), pkt.src_port()));

        self.stream_map.insert(
            stream_fd,
            // SAFETY: Safe as the file descriptor is guaranteed to be valid.
            unsafe { UnixStream::from_raw_fd(stream_fd) },
        );
        self.local_port_set.insert(pkt.dst_port());

        VhostUserVsockThread::epoll_register(
            self.epoll_fd,
            stream_fd,
            epoll::Events::EPOLLIN | epoll::Events::EPOLLOUT,
        )?;
        Ok(())
    }

    /// Enqueue RST packets to be sent to guest.
    fn enq_rst(&mut self) {
        // TODO
        dbg!("New guest conn error: Enqueue RST");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vhu_vsock::{VhostUserVsockBackend, VsockConfig, VSOCK_OP_RW};
    use serial_test::serial;
    use std::os::unix::net::UnixListener;
    use virtio_vsock::packet::{VsockPacket, PKT_HEADER_SIZE};

    const DATA_LEN: usize = 16;
    const CONN_TX_BUF_SIZE: u32 = 64 * 1024;

    #[test]
    #[serial]
    fn test_vsock_thread_backend() {
        const VSOCK_SOCKET_PATH: &str = "test_vsock_thread_backend.vsock";
        const VSOCK_PEER_PORT: u32 = 1234;
        const VSOCK_PEER_PATH: &str = "test_vsock_thread_backend.vsock_1234";

        let _ = std::fs::remove_file(VSOCK_PEER_PATH);
        let _listener = UnixListener::bind(VSOCK_PEER_PATH).unwrap();

        let epoll_fd = epoll::create(false).unwrap();

        let cid_map: Arc<RwLock<CidMap>> = Arc::new(RwLock::new(HashMap::new()));

        let mut vtp = VsockThreadBackend::new(
            VSOCK_SOCKET_PATH.to_string(),
            epoll_fd,
            CONN_TX_BUF_SIZE,
            cid_map,
        );

        assert!(!vtp.pending_rx());

        let mut pkt_raw = [0u8; PKT_HEADER_SIZE + DATA_LEN];
        let (hdr_raw, data_raw) = pkt_raw.split_at_mut(PKT_HEADER_SIZE);

        // SAFETY: Safe as hdr_raw and data_raw are guaranteed to be valid.
        let mut packet = unsafe { VsockPacket::new(hdr_raw, Some(data_raw)).unwrap() };

        assert_eq!(
            vtp.recv_pkt(&mut packet).unwrap_err().to_string(),
            Error::EmptyBackendRxQ.to_string()
        );

        assert!(vtp.send_pkt(&packet).is_ok());

        packet.set_type(VSOCK_TYPE_STREAM);
        assert!(vtp.send_pkt(&packet).is_ok());

        packet.set_dst_cid(VSOCK_HOST_CID);
        packet.set_dst_port(VSOCK_PEER_PORT);
        assert!(vtp.send_pkt(&packet).is_ok());

        packet.set_op(VSOCK_OP_REQUEST);
        assert!(vtp.send_pkt(&packet).is_ok());

        packet.set_op(VSOCK_OP_RW);
        assert!(vtp.send_pkt(&packet).is_ok());

        packet.set_op(VSOCK_OP_RST);
        assert!(vtp.send_pkt(&packet).is_ok());

        assert!(vtp.recv_pkt(&mut packet).is_ok());

        // cleanup
        let _ = std::fs::remove_file(VSOCK_PEER_PATH);
    }

    #[test]
    #[serial]
    fn test_vsock_thread_backend_sibling_vms() {
        const CID: u64 = 3;
        const VSOCK_SOCKET_PATH: &str = "test_vsock_thread_backend.vsock";

        const SIBLING_CID: u64 = 4;
        const SIBLING_VHOST_SOCKET_PATH: &str = "test_vsock_thread_backend_sibling.socket";
        const SIBLING_VSOCK_SOCKET_PATH: &str = "test_vsock_thread_backend_sibling.vsock";
        const SIBLING_LISTENING_PORT: u32 = 1234;

        let cid_map: Arc<RwLock<CidMap>> = Arc::new(RwLock::new(HashMap::new()));

        let sibling_config = VsockConfig::new(
            SIBLING_CID,
            SIBLING_VHOST_SOCKET_PATH.to_string(),
            SIBLING_VSOCK_SOCKET_PATH.to_string(),
            CONN_TX_BUF_SIZE,
        );

        let sibling_backend =
            Arc::new(VhostUserVsockBackend::new(sibling_config, cid_map.clone()).unwrap());
        cid_map
            .write()
            .unwrap()
            .insert(SIBLING_CID, sibling_backend.clone());

        let epoll_fd = epoll::create(false).unwrap();
        let mut vtp = VsockThreadBackend::new(
            VSOCK_SOCKET_PATH.to_string(),
            epoll_fd,
            CONN_TX_BUF_SIZE,
            cid_map,
        );

        assert!(!vtp.pending_raw_pkts());

        let mut pkt_raw = [0u8; PKT_HEADER_SIZE + DATA_LEN];
        let (hdr_raw, data_raw) = pkt_raw.split_at_mut(PKT_HEADER_SIZE);

        // SAFETY: Safe as hdr_raw and data_raw are guaranteed to be valid.
        let mut packet = unsafe { VsockPacket::new(hdr_raw, Some(data_raw)).unwrap() };

        assert_eq!(
            vtp.recv_raw_pkt(&mut packet).unwrap_err().to_string(),
            Error::EmptyRawPktsQueue.to_string()
        );

        packet.set_type(VSOCK_TYPE_STREAM);
        packet.set_src_cid(CID);
        packet.set_dst_cid(SIBLING_CID);
        packet.set_dst_port(SIBLING_LISTENING_PORT);
        packet.set_op(VSOCK_OP_RW);
        packet.set_len(DATA_LEN as u32);
        packet
            .data_slice()
            .unwrap()
            .copy_from(&[0xCAu8, 0xFEu8, 0xBAu8, 0xBEu8]);

        assert!(vtp.send_pkt(&packet).is_ok());
        assert!(sibling_backend.threads[0]
            .lock()
            .unwrap()
            .thread_backend
            .pending_raw_pkts());

        let mut recvd_pkt_raw = [0u8; PKT_HEADER_SIZE + DATA_LEN];
        let (recvd_hdr_raw, recvd_data_raw) = recvd_pkt_raw.split_at_mut(PKT_HEADER_SIZE);

        let mut recvd_packet =
            // SAFETY: Safe as recvd_hdr_raw and recvd_data_raw are guaranteed to be valid.
            unsafe { VsockPacket::new(recvd_hdr_raw, Some(recvd_data_raw)).unwrap() };

        assert!(sibling_backend.threads[0]
            .lock()
            .unwrap()
            .thread_backend
            .recv_raw_pkt(&mut recvd_packet)
            .is_ok());

        assert_eq!(recvd_packet.type_(), VSOCK_TYPE_STREAM);
        assert_eq!(recvd_packet.src_cid(), CID);
        assert_eq!(recvd_packet.dst_cid(), SIBLING_CID);
        assert_eq!(recvd_packet.dst_port(), SIBLING_LISTENING_PORT);
        assert_eq!(recvd_packet.op(), VSOCK_OP_RW);
        assert_eq!(recvd_packet.len(), DATA_LEN as u32);

        assert_eq!(recvd_data_raw[0], 0xCAu8);
        assert_eq!(recvd_data_raw[1], 0xFEu8);
        assert_eq!(recvd_data_raw[2], 0xBAu8);
        assert_eq!(recvd_data_raw[3], 0xBEu8);
    }
}
