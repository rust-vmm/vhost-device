// SPDX-License-Identifier: Apache-2.0 or BSD-3-Clause

use std::{
    collections::{HashMap, HashSet, VecDeque},
    io::{Read, Result as StdIOResult, Write},
    ops::Deref,
    os::unix::{
        net::UnixStream,
        prelude::{AsRawFd, RawFd},
    },
    result::Result as StdResult,
    sync::{Arc, RwLock},
};

use log::{info, warn};
use virtio_queue::Writer;
use virtio_vsock::packet::{PacketHeader, VsockPacketRx, VsockPacketTx, PKT_HEADER_SIZE};
use vm_memory::{bitmap::BitmapSlice, ByteValued};
#[cfg(feature = "backend_vsock")]
use vsock::VsockStream;

use crate::{
    rxops::*,
    vhu_vsock::{
        BackendType, CidMap, ConnMapKey, Error, Result, VSOCK_HOST_CID, VSOCK_OP_REQUEST,
        VSOCK_OP_RST, VSOCK_TYPE_STREAM,
    },
    vhu_vsock_thread::VhostUserVsockThread,
    vsock_conn::*,
};

pub(crate) type RawPktsQ = VecDeque<RawVsockPacket>;

pub(crate) struct RawVsockPacket {
    pub header: [u8; PKT_HEADER_SIZE],
    pub data: Vec<u8>,
}

impl RawVsockPacket {
    fn from_vsock_packet<B: BitmapSlice>(pkt: &VsockPacketTx<B>) -> Result<Self> {
        let mut raw_pkt = Self {
            header: [0; PKT_HEADER_SIZE],
            data: vec![0; pkt.header().len() as usize],
        };

        raw_pkt.header.copy_from_slice(pkt.header().as_slice());
        if !pkt.header().is_empty() {
            let mut pkt = pkt.clone();
            let reader = pkt.data_slice().ok_or(Error::PktBufMissing)?;
            reader
                .read_exact(&mut raw_pkt.data)
                .map_err(|_| Error::GuestMemoryRead)?;
        }

        Ok(raw_pkt)
    }
}

pub(crate) enum StreamType {
    Unix(UnixStream),
    #[cfg(feature = "backend_vsock")]
    Vsock(VsockStream),
}

impl StreamType {
    fn try_clone(&self) -> StdIOResult<StreamType> {
        match self {
            StreamType::Unix(stream) => {
                let cloned_stream = stream.try_clone()?;
                Ok(StreamType::Unix(cloned_stream))
            }
            #[cfg(feature = "backend_vsock")]
            StreamType::Vsock(stream) => {
                let cloned_stream = stream.try_clone()?;
                Ok(StreamType::Vsock(cloned_stream))
            }
        }
    }
}

impl Read for StreamType {
    fn read(&mut self, buf: &mut [u8]) -> StdIOResult<usize> {
        match self {
            StreamType::Unix(stream) => stream.read(buf),
            #[cfg(feature = "backend_vsock")]
            StreamType::Vsock(stream) => stream.read(buf),
        }
    }
}

impl Write for StreamType {
    fn write(&mut self, buf: &[u8]) -> StdIOResult<usize> {
        match self {
            StreamType::Unix(stream) => stream.write(buf),
            #[cfg(feature = "backend_vsock")]
            StreamType::Vsock(stream) => stream.write(buf),
        }
    }

    fn flush(&mut self) -> StdIOResult<()> {
        match self {
            StreamType::Unix(stream) => stream.flush(),
            #[cfg(feature = "backend_vsock")]
            StreamType::Vsock(stream) => stream.flush(),
        }
    }
}

impl AsRawFd for StreamType {
    fn as_raw_fd(&self) -> RawFd {
        match self {
            StreamType::Unix(stream) => stream.as_raw_fd(),
            #[cfg(feature = "backend_vsock")]
            StreamType::Vsock(stream) => stream.as_raw_fd(),
        }
    }
}

pub trait VsockStreamIo {
    fn stream_read<B: BitmapSlice>(&mut self, buf: &mut Writer<B>) -> Result<usize>;
    fn stream_write(&mut self, buf: &[u8]) -> StdResult<usize, std::io::Error>;
}

impl VsockStreamIo for StreamType {
    /// Read from the stream into the guest buffer (H -> G)
    fn stream_read<B: BitmapSlice>(&mut self, writer: &mut Writer<B>) -> Result<usize> {
        //TODO: no zeropy is possible.
        let mut tmp_data = vec![0u8; writer.available_bytes()];
        let bytes_read = self.read(&mut tmp_data).map_err(Error::StreamRead)?;
        writer
            .write(&tmp_data[..bytes_read])
            .map_err(|_| Error::GuestMemoryWrite)
    }

    /// Write from the guest buffer to the stream (G -> H)
    fn stream_write(&mut self, buf: &[u8]) -> StdResult<usize, std::io::Error> {
        let src = buf.as_ptr().cast::<libc::c_void>();
        let fd = self.as_raw_fd();

        // SAFETY: We got a valid file descriptor from `AsRawFd`. The memory pointed to
        // by `src` is valid for reads of length `buf.len()` as it comes from a
        // valid `&[u8]` slice.
        let bytes_written = unsafe { libc::write(fd, src, buf.len()) };

        if bytes_written < 0 {
            Err(std::io::Error::last_os_error())
        } else {
            Ok(bytes_written.try_into().unwrap())
        }
    }
}

pub(crate) trait IsHybridVsock {
    fn is_hybrid_vsock(&self) -> bool;
}

impl IsHybridVsock for StreamType {
    fn is_hybrid_vsock(&self) -> bool {
        matches!(self, StreamType::Unix(_))
    }
}

pub(crate) struct VsockThreadBackend {
    /// Map of ConnMapKey objects indexed by raw file descriptors.
    pub listener_map: HashMap<RawFd, ConnMapKey>,
    /// Map of vsock connection objects indexed by ConnMapKey objects.
    pub conn_map: HashMap<ConnMapKey, VsockConnection<StreamType>>,
    /// Queue of ConnMapKey objects indicating pending rx operations.
    pub backend_rxq: VecDeque<ConnMapKey>,
    /// Map of host-side unix or vsock streams indexed by raw file descriptors.
    pub stream_map: HashMap<i32, StreamType>,
    /// Host side socket info for listening to new connections from the host.
    backend_info: BackendType,
    /// epoll for registering new host-side connections.
    epoll_fd: i32,
    /// CID of the guest.
    guest_cid: u64,
    /// Set of allocated local ports.
    pub local_port_set: HashSet<u32>,
    tx_buffer_size: u32,
    /// Maps the guest CID to the corresponding backend. Used for sibling VM
    /// communication.
    pub cid_map: Arc<RwLock<CidMap>>,
    /// Queue of raw vsock packets received from sibling VMs to be sent to the
    /// guest.
    pub raw_pkts_queue: Arc<RwLock<RawPktsQ>>,
    /// Set of groups assigned to the device which it is allowed to communicate
    /// with.
    groups_set: Arc<RwLock<HashSet<String>>>,
}

impl VsockThreadBackend {
    /// New instance of VsockThreadBackend.
    pub fn new(
        backend_info: BackendType,
        epoll_fd: i32,
        guest_cid: u64,
        tx_buffer_size: u32,
        groups_set: Arc<RwLock<HashSet<String>>>,
        cid_map: Arc<RwLock<CidMap>>,
    ) -> Self {
        Self {
            listener_map: HashMap::new(),
            conn_map: HashMap::new(),
            backend_rxq: VecDeque::new(),
            // Need this map to prevent connected stream from closing
            // TODO: think of a better solution
            stream_map: HashMap::new(),
            backend_info,
            epoll_fd,
            guest_cid,
            local_port_set: HashSet::new(),
            tx_buffer_size,
            cid_map,
            raw_pkts_queue: Arc::new(RwLock::new(VecDeque::new())),
            groups_set,
        }
    }

    /// Checks if there are pending rx requests in the backend rxq.
    pub fn pending_rx(&self) -> bool {
        !self.backend_rxq.is_empty()
    }

    /// Checks if there are pending raw vsock packets to be sent to the guest.
    pub fn pending_raw_pkts(&self) -> bool {
        !self.raw_pkts_queue.read().unwrap().is_empty()
    }

    /// Deliver a vsock packet to the guest vsock driver.
    ///
    /// Returns:
    /// - `Ok(())` if the packet was successfully filled in
    /// - `Err(Error::EmptyBackendRxQ) if there was no available data
    pub fn recv_pkt<B: BitmapSlice>(&mut self, pkt: &mut VsockPacketRx<B>) -> Result<()> {
        // Pop an event from the backend_rxq
        let key = self.backend_rxq.pop_front().ok_or(Error::EmptyBackendRxQ)?;
        let conn = match self.conn_map.get_mut(&key) {
            Some(conn) => conn,
            None => {
                // assume that the connection does not exist
                return Ok(());
            }
        };

        let mut vsock_header = PacketHeader::default();

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
            vsock_header
                .set_op(VSOCK_OP_RST)
                .set_src_cid(VSOCK_HOST_CID)
                .set_dst_cid(conn.guest_cid)
                .set_src_port(conn.local_port)
                .set_dst_port(conn.peer_port)
                .set_len(0)
                .set_type(VSOCK_TYPE_STREAM)
                .set_flags(0)
                .set_buf_alloc(0)
                .set_fwd_cnt(0);

            pkt.header_slice()
                .write_obj(vsock_header)
                .map_err(|_| Error::GuestMemoryWrite)?;

            return Ok(());
        }

        // Handle other packet types per connection
        conn.recv_pkt(&mut vsock_header, pkt)?;

        pkt.header_slice()
            .write_obj(vsock_header)
            .map_err(|_| Error::GuestMemoryWrite)?;

        Ok(())
    }

    /// Deliver a guest generated packet to its destination in the backend.
    ///
    /// Absorbs unexpected packets, handles rest to respective connection
    /// object.
    ///
    /// Returns:
    /// - always `Ok(())` if packet has been consumed correctly
    pub fn send_pkt<B: BitmapSlice>(&mut self, pkt: &mut VsockPacketTx<B>) -> Result<()> {
        if pkt.header().src_cid() != self.guest_cid {
            warn!(
                "vsock: dropping packet with inconsistent src_cid: {:?} from guest configured with CID: {:?}",
                pkt.header().src_cid(), self.guest_cid
            );
            return Ok(());
        }

        #[allow(irrefutable_let_patterns)]
        if let BackendType::UnixDomainSocket(_) = &self.backend_info {
            let dst_cid = pkt.header().dst_cid();
            if dst_cid != VSOCK_HOST_CID {
                let cid_map = self.cid_map.read().unwrap();
                if cid_map.contains_key(&dst_cid) {
                    let (sibling_raw_pkts_queue, sibling_groups_set, sibling_event_fd) =
                        cid_map.get(&dst_cid).unwrap();

                    if self
                        .groups_set
                        .read()
                        .unwrap()
                        .is_disjoint(sibling_groups_set.read().unwrap().deref())
                    {
                        info!("vsock: dropping packet for cid: {dst_cid:?} due to group mismatch");
                        return Ok(());
                    }

                    sibling_raw_pkts_queue
                        .write()
                        .unwrap()
                        .push_back(RawVsockPacket::from_vsock_packet(pkt)?);
                    let _ = sibling_event_fd.write(1);
                } else {
                    warn!("vsock: dropping packet for unknown cid: {dst_cid:?}");
                }

                return Ok(());
            }
        }

        // TODO: Rst if packet has unsupported type
        if pkt.header().type_() != VSOCK_TYPE_STREAM {
            info!("vsock: dropping packet of unknown type");
            return Ok(());
        }

        let key = ConnMapKey::new(pkt.header().dst_port(), pkt.header().src_port());

        // TODO: Handle cases where connection does not exist and packet op
        // is not VSOCK_OP_REQUEST
        if !self.conn_map.contains_key(&key) {
            // The packet contains a new connection request
            if pkt.header().op() == VSOCK_OP_REQUEST {
                self.handle_new_guest_conn(pkt);
            } else {
                // TODO: send back RST
            }
            return Ok(());
        }

        if pkt.header().op() == VSOCK_OP_RST {
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

    /// Deliver a raw vsock packet sent from a sibling VM to the guest vsock
    /// driver.
    ///
    /// Returns:
    /// - `Ok(())` if packet was successfully filled in
    /// - `Err(Error::EmptyRawPktsQueue)` if there was no available data
    pub fn recv_raw_pkt<B: BitmapSlice>(&mut self, pkt: &mut VsockPacketRx<B>) -> Result<()> {
        let raw_vsock_pkt = self
            .raw_pkts_queue
            .write()
            .unwrap()
            .pop_front()
            .ok_or(Error::EmptyRawPktsQueue)?;

        pkt.header_slice()
            .write_all(&raw_vsock_pkt.header)
            .map_err(|_| Error::GuestMemoryWrite)?;

        if !raw_vsock_pkt.data.is_empty() {
            pkt.data_slice()
                .write_all(&raw_vsock_pkt.data)
                .map_err(|_| Error::GuestMemoryWrite)?;
        }

        Ok(())
    }

    /// Handle a new guest initiated connection, i.e from the peer, the guest
    /// driver.
    ///
    /// In case of proxying using unix domain socket, attempts to connect to a
    /// host side unix socket listening on a path corresponding to the
    /// destination port as follows:
    /// - "{self.host_sock_path}_{local_port}""
    ///
    /// In case of proxying using vosck, attempts to connect to the
    /// {forward_cid, local_port}
    fn handle_new_guest_conn<B: BitmapSlice>(&mut self, pkt: &VsockPacketTx<B>) {
        match &self.backend_info {
            BackendType::UnixDomainSocket(uds_path) => {
                let port_path = format!("{}_{}", uds_path.display(), pkt.header().dst_port());
                UnixStream::connect(port_path)
                    .and_then(|stream| stream.set_nonblocking(true).map(|_| stream))
                    .map_err(Error::UnixConnect)
                    .and_then(|stream| self.add_new_guest_conn(StreamType::Unix(stream), pkt))
                    .unwrap_or_else(|_| self.enq_rst());
            }
            #[cfg(feature = "backend_vsock")]
            BackendType::Vsock(vsock_info) => {
                VsockStream::connect_with_cid_port(vsock_info.forward_cid, pkt.header().dst_port())
                    .and_then(|stream| stream.set_nonblocking(true).map(|_| stream))
                    .map_err(Error::VsockConnect)
                    .and_then(|stream| self.add_new_guest_conn(StreamType::Vsock(stream), pkt))
                    .unwrap_or_else(|_| self.enq_rst());
            }
        }
    }

    /// Wrapper to add new connection to relevant HashMaps.
    fn add_new_guest_conn<B: BitmapSlice>(
        &mut self,
        stream: StreamType,
        pkt: &VsockPacketTx<B>,
    ) -> Result<()> {
        let conn = VsockConnection::new_peer_init(
            stream.try_clone().map_err(match stream {
                StreamType::Unix(_) => Error::UnixConnect,
                #[cfg(feature = "backend_vsock")]
                StreamType::Vsock(_) => Error::VsockConnect,
            })?,
            pkt.header().dst_cid(),
            pkt.header().dst_port(),
            pkt.header().src_cid(),
            pkt.header().src_port(),
            self.epoll_fd,
            pkt.header().buf_alloc(),
            self.tx_buffer_size,
        );
        let stream_fd = conn.stream.as_raw_fd();
        self.listener_map.insert(
            stream_fd,
            ConnMapKey::new(pkt.header().dst_port(), pkt.header().src_port()),
        );

        self.conn_map.insert(
            ConnMapKey::new(pkt.header().dst_port(), pkt.header().src_port()),
            conn,
        );
        self.backend_rxq.push_back(ConnMapKey::new(
            pkt.header().dst_port(),
            pkt.header().src_port(),
        ));

        self.stream_map.insert(stream_fd, stream);
        self.local_port_set.insert(pkt.header().dst_port());

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
        log::debug!("New guest conn error: Enqueue RST");
    }
}

#[cfg(test)]
mod tests {
    use std::os::unix::net::UnixListener;

    use tempfile::tempdir;
    use virtio_vsock::packet::{VsockPacketRx, VsockPacketTx, PKT_HEADER_SIZE};
    use vm_memory::GuestAddressSpace;
    #[cfg(feature = "backend_vsock")]
    use vsock::{VsockListener, VMADDR_CID_ANY, VMADDR_CID_LOCAL};

    use super::*;
    #[cfg(feature = "backend_vsock")]
    use crate::vhu_vsock::VsockProxyInfo;
    use crate::{
        test_utils::{prepare_desc_chain_vsock, HeadParams},
        vhu_vsock::{BackendType, VhostUserVsockBackend, VsockConfig, VSOCK_OP_RW},
    };

    //const DATA_LEN: usize = 16;
    const CONN_TX_BUF_SIZE: u32 = 64 * 1024;
    //const QUEUE_SIZE: usize = 1024;
    const GROUP_NAME: &str = "default";
    const VSOCK_PEER_PORT: u32 = 1234;

    fn test_vsock_thread_backend(backend_info: BackendType) {
        const CID: u64 = 3;

        let epoll_fd = epoll::create(false).unwrap();

        let groups_set: HashSet<String> = vec![GROUP_NAME.to_string()].into_iter().collect();

        let cid_map: Arc<RwLock<CidMap>> = Arc::new(RwLock::new(HashMap::new()));

        let mut vtp = VsockThreadBackend::new(
            backend_info,
            epoll_fd,
            CID,
            CONN_TX_BUF_SIZE,
            Arc::new(RwLock::new(groups_set)),
            cid_map,
        );

        assert!(!vtp.pending_rx());

        let head_params = HeadParams::new(PKT_HEADER_SIZE, 5);
        let (mem, descr_chain) = prepare_desc_chain_vsock(false, &head_params, 1, 5);
        let mem = mem.memory();
        let mut packet =
            VsockPacketTx::from_tx_virtq_chain(mem.deref(), descr_chain, CONN_TX_BUF_SIZE).unwrap();

        let (mem_rx, descr_chain_rx) = prepare_desc_chain_vsock(true, &head_params, 1, 5);
        let mem_rx = mem_rx.memory();

        let mut packet_rx =
            VsockPacketRx::from_rx_virtq_chain(mem_rx.deref(), descr_chain_rx, CONN_TX_BUF_SIZE)
                .unwrap();

        assert_eq!(
            vtp.recv_pkt(&mut packet_rx).unwrap_err().to_string(),
            Error::EmptyBackendRxQ.to_string()
        );

        vtp.send_pkt(&mut packet).unwrap();

        packet.header_mut().set_type(VSOCK_TYPE_STREAM);
        vtp.send_pkt(&mut packet).unwrap();

        packet.header_mut().set_src_cid(CID);
        packet.header_mut().set_dst_cid(VSOCK_HOST_CID);
        packet.header_mut().set_dst_port(VSOCK_PEER_PORT);
        vtp.send_pkt(&mut packet).unwrap();

        packet.header_mut().set_op(VSOCK_OP_REQUEST);
        vtp.send_pkt(&mut packet).unwrap();

        packet.header_mut().set_op(VSOCK_OP_RW);
        vtp.send_pkt(&mut packet).unwrap();

        packet.header_mut().set_op(VSOCK_OP_RST);
        vtp.send_pkt(&mut packet).unwrap();

        //vtp.recv_pkt(&mut packet_rx).unwrap();

        // TODO: it is a nop for now
        vtp.enq_rst();
    }

    #[test]
    fn test_vsock_thread_backend_unix() {
        let test_dir = tempdir().expect("Could not create a temp test directory.");

        let vsock_socket_path = test_dir.path().join("test_vsock_thread_backend.vsock");
        let vsock_peer_path = test_dir.path().join("test_vsock_thread_backend.vsock_1234");

        let _listener = UnixListener::bind(&vsock_peer_path).unwrap();
        let backend_info = BackendType::UnixDomainSocket(vsock_socket_path.clone());

        test_vsock_thread_backend(backend_info);

        // cleanup
        let _ = std::fs::remove_file(&vsock_peer_path);
        let _ = std::fs::remove_file(&vsock_socket_path);

        test_dir.close().unwrap();
    }

    #[cfg(feature = "backend_vsock")]
    #[test]
    fn test_vsock_thread_backend_vsock() {
        VsockListener::bind_with_cid_port(VMADDR_CID_LOCAL, libc::VMADDR_PORT_ANY).expect(
            "This test uses VMADDR_CID_LOCAL, so the vsock_loopback kernel module must be loaded",
        );

        let _listener = VsockListener::bind_with_cid_port(VMADDR_CID_ANY, VSOCK_PEER_PORT).unwrap();
        let backend_info = BackendType::Vsock(VsockProxyInfo {
            forward_cid: VMADDR_CID_LOCAL,
            listen_ports: vec![],
        });

        test_vsock_thread_backend(backend_info);
    }

    //TODO: fix tests
    /*
    #[test]
    fn test_vsock_thread_backend_sibling_vms() {
        const CID: u64 = 3;
        const SIBLING_CID: u64 = 4;
        const SIBLING2_CID: u64 = 5;
        const SIBLING_LISTENING_PORT: u32 = 1234;

        let test_dir = tempdir().expect("Could not create a temp test directory.");

        let vsock_socket_path = test_dir.path().join("test_vsock_thread_backend.vsock");
        let sibling_vhost_socket_path = test_dir
            .path()
            .join("test_vsock_thread_backend_sibling.socket");
        let sibling_vsock_socket_path = test_dir
            .path()
            .join("test_vsock_thread_backend_sibling.vsock");
        let sibling2_vhost_socket_path = test_dir
            .path()
            .join("test_vsock_thread_backend_sibling2.socket");
        let sibling2_vsock_socket_path = test_dir
            .path()
            .join("test_vsock_thread_backend_sibling2.vsock");

        let cid_map: Arc<RwLock<CidMap>> = Arc::new(RwLock::new(HashMap::new()));

        let sibling_config = VsockConfig::new(
            SIBLING_CID,
            sibling_vhost_socket_path,
            BackendType::UnixDomainSocket(sibling_vsock_socket_path),
            CONN_TX_BUF_SIZE,
            QUEUE_SIZE,
            vec!["group1", "group2", "group3"]
                .into_iter()
                .map(String::from)
                .collect(),
        );

        let sibling2_config = VsockConfig::new(
            SIBLING2_CID,
            sibling2_vhost_socket_path,
            BackendType::UnixDomainSocket(sibling2_vsock_socket_path),
            CONN_TX_BUF_SIZE,
            QUEUE_SIZE,
            vec!["group1"].into_iter().map(String::from).collect(),
        );

        let sibling_backend =
            Arc::new(VhostUserVsockBackend::new(sibling_config, cid_map.clone()).unwrap());
        let sibling2_backend =
            Arc::new(VhostUserVsockBackend::new(sibling2_config, cid_map.clone()).unwrap());

        let epoll_fd = epoll::create(false).unwrap();

        let groups_set: HashSet<String> = vec!["groupA", "groupB", "group3"]
            .into_iter()
            .map(String::from)
            .collect();

        let mut vtp = VsockThreadBackend::new(
            BackendType::UnixDomainSocket(vsock_socket_path),
            epoll_fd,
            CID,
            CONN_TX_BUF_SIZE,
            Arc::new(RwLock::new(groups_set)),
            cid_map,
        );

        assert!(!vtp.pending_raw_pkts());

        let mut pkt_raw = [0u8; PKT_HEADER_SIZE + DATA_LEN];
        let (hdr_raw, data_raw) = pkt_raw.split_at_mut(PKT_HEADER_SIZE);

        let head_params = HeadParams::new(PKT_HEADER_SIZE, 5);
        let (mem, descr_chain) = prepare_desc_chain_vsock(false, &head_params, 1, 5);
        let mem = mem.memory();

        // SAFETY: Safe as hdr_raw and data_raw are guaranteed to be valid.
        let mut packet =
            VsockPacketRx::from_rx_virtq_chain(mem.deref(), descr_chain, CONN_TX_BUF_SIZE)
                .unwrap();
        assert_eq!(
            vtp.recv_raw_pkt(&mut packet).unwrap_err().to_string(),
            Error::EmptyRawPktsQueue.to_string()
        );


        packet.header_mut().set_type(VSOCK_TYPE_STREAM);
        packet.header_mut().set_src_cid(CID);
        packet.header_mut().set_dst_cid(SIBLING_CID);
        packet.header_mut().set_dst_port(SIBLING_LISTENING_PORT);
        packet.header_mut().set_op(VSOCK_OP_RW);
        packet.header_mut().set_len(DATA_LEN as u32);

        //Payload is hello
        /*packet
            .data_slice()
            .unwrap()
            .copy_from(&[0xCAu8, 0xFEu8, 0xBAu8, 0xBEu8]);
        */

        vtp.send_pkt(&mut &packet).unwrap();
        assert!(sibling_backend.threads[0]
            .lock()
            .unwrap()
            .thread_backend
            .pending_raw_pkts());

        packet.header_mut().set_dst_cid(SIBLING2_CID);
        vtp.send_pkt(&mut &packet).unwrap();
        // packet should be discarded since sibling2 is not in the same group
        assert!(!sibling2_backend.threads[0]
            .lock()
            .unwrap()
            .thread_backend
            .pending_raw_pkts());

        let mut recvd_pkt_raw = [0u8; PKT_HEADER_SIZE + DATA_LEN];
        let (recvd_hdr_raw, recvd_data_raw) = recvd_pkt_raw.split_at_mut(PKT_HEADER_SIZE);

        let mut recvd_packet =
            // SAFETY: Safe as recvd_hdr_raw and recvd_data_raw are guaranteed to be valid.
            unsafe { VsockPacket::new(recvd_hdr_raw, Some(recvd_data_raw)).unwrap() };

        sibling_backend.threads[0]
            .lock()
            .unwrap()
            .thread_backend
            .recv_raw_pkt(&mut recvd_packet)
            .unwrap();

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

        test_dir.close().unwrap();
    }
 */
}
