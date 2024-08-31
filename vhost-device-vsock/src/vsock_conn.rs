// SPDX-License-Identifier: Apache-2.0 or BSD-3-Clause

use std::{
    io::{ErrorKind, Write},
    num::Wrapping,
    os::unix::prelude::{AsRawFd, RawFd},
};

use log::{error, info};
use virtio_vsock::packet::{VsockPacket, PKT_HEADER_SIZE};
use vm_memory::{bitmap::BitmapSlice, ReadVolatile, VolatileSlice, WriteVolatile};

use crate::{
    rxops::*,
    rxqueue::*,
    thread_backend::IsHybridVsock,
    txbuf::*,
    vhu_vsock::{
        Error, Result, VSOCK_FLAGS_SHUTDOWN_RCV, VSOCK_FLAGS_SHUTDOWN_SEND,
        VSOCK_OP_CREDIT_REQUEST, VSOCK_OP_CREDIT_UPDATE, VSOCK_OP_REQUEST, VSOCK_OP_RESPONSE,
        VSOCK_OP_RST, VSOCK_OP_RW, VSOCK_OP_SHUTDOWN, VSOCK_TYPE_STREAM,
    },
    vhu_vsock_thread::VhostUserVsockThread,
};

pub(crate) struct VsockConnection<S> {
    /// Host-side stream corresponding to this vsock connection.
    pub stream: S,
    /// Specifies if the stream is connected to a listener on the host.
    pub connect: bool,
    /// Port at which a guest application is listening to.
    pub peer_port: u32,
    /// Queue holding pending rx operations per connection.
    pub rx_queue: RxQueue,
    /// CID of the host.
    local_cid: u64,
    /// Port on the host at which a host-side application listens to.
    pub local_port: u32,
    /// CID of the guest.
    pub guest_cid: u64,
    /// Total number of bytes written to stream from tx buffer.
    pub fwd_cnt: Wrapping<u32>,
    /// Total number of bytes previously forwarded to stream.
    last_fwd_cnt: Wrapping<u32>,
    /// Size of buffer the guest has allocated for this connection.
    peer_buf_alloc: u32,
    /// Number of bytes the peer has forwarded to a connection.
    peer_fwd_cnt: Wrapping<u32>,
    /// The total number of bytes sent to the guest vsock driver.
    rx_cnt: Wrapping<u32>,
    /// epoll fd to which this connection's stream has to be added.
    pub epoll_fd: RawFd,
    /// Local tx buffer.
    pub tx_buf: LocalTxBuf,
    /// Local tx buffer size
    tx_buffer_size: u32,
}

impl<S: AsRawFd + ReadVolatile + Write + WriteVolatile + IsHybridVsock> VsockConnection<S> {
    /// Create a new vsock connection object for locally i.e host-side
    /// inititated connections.
    pub fn new_local_init(
        stream: S,
        local_cid: u64,
        local_port: u32,
        guest_cid: u64,
        guest_port: u32,
        epoll_fd: RawFd,
        tx_buffer_size: u32,
    ) -> Self {
        Self {
            stream,
            connect: false,
            peer_port: guest_port,
            rx_queue: RxQueue::new(),
            local_cid,
            local_port,
            guest_cid,
            fwd_cnt: Wrapping(0),
            last_fwd_cnt: Wrapping(0),
            peer_buf_alloc: 0,
            peer_fwd_cnt: Wrapping(0),
            rx_cnt: Wrapping(0),
            epoll_fd,
            tx_buf: LocalTxBuf::new(tx_buffer_size),
            tx_buffer_size,
        }
    }

    /// Create a new vsock connection object for connections initiated by
    /// an application running in the guest.
    #[allow(clippy::too_many_arguments)]
    pub fn new_peer_init(
        stream: S,
        local_cid: u64,
        local_port: u32,
        guest_cid: u64,
        guest_port: u32,
        epoll_fd: RawFd,
        peer_buf_alloc: u32,
        tx_buffer_size: u32,
    ) -> Self {
        let mut rx_queue = RxQueue::new();
        rx_queue.enqueue(RxOps::Response);
        Self {
            stream,
            connect: false,
            peer_port: guest_port,
            rx_queue,
            local_cid,
            local_port,
            guest_cid,
            fwd_cnt: Wrapping(0),
            last_fwd_cnt: Wrapping(0),
            peer_buf_alloc,
            peer_fwd_cnt: Wrapping(0),
            rx_cnt: Wrapping(0),
            epoll_fd,
            tx_buf: LocalTxBuf::new(tx_buffer_size),
            tx_buffer_size,
        }
    }

    /// Set the peer port to the guest side application's port.
    pub fn set_peer_port(&mut self, peer_port: u32) {
        self.peer_port = peer_port;
    }

    /// Process a vsock packet that is meant for this connection.
    /// Forward data to the host-side application if the vsock packet
    /// contains a RW operation.
    pub fn recv_pkt<B: BitmapSlice>(&mut self, pkt: &mut VsockPacket<B>) -> Result<()> {
        // Initialize all fields in the packet header
        self.init_pkt(pkt);

        match self.rx_queue.dequeue() {
            Some(RxOps::Request) => {
                // Send a connection request to the guest-side application
                pkt.set_op(VSOCK_OP_REQUEST);
                Ok(())
            }
            Some(RxOps::Rw) => {
                if !self.connect {
                    // There is no host-side application listening for this
                    // packet, hence send back an RST.
                    pkt.set_op(VSOCK_OP_RST);
                    return Ok(());
                }

                // Check if peer has space for receiving data
                if self.need_credit_update_from_peer() {
                    self.last_fwd_cnt = self.fwd_cnt;
                    pkt.set_op(VSOCK_OP_CREDIT_REQUEST);
                    return Ok(());
                }
                let buf = pkt.data_slice().ok_or(Error::PktBufMissing)?;

                // Perform a credit check to find the maximum read size. The read
                // data must fit inside a packet buffer and be within peer's
                // available buffer space
                let max_read_len = std::cmp::min(buf.len(), self.peer_avail_credit());
                let mut buf = buf
                    .subslice(0, max_read_len)
                    .expect("subslicing should work since length was checked");
                // Read data from the stream directly into the buffer
                if let Ok(read_cnt) = self.stream.read_volatile(&mut buf) {
                    if read_cnt == 0 {
                        // If no data was read then the stream was closed down unexpectedly.
                        // Send a shutdown packet to the guest-side application.
                        pkt.set_op(VSOCK_OP_SHUTDOWN)
                            .set_flag(VSOCK_FLAGS_SHUTDOWN_RCV)
                            .set_flag(VSOCK_FLAGS_SHUTDOWN_SEND);
                    } else {
                        // If data was read, then set the length field in the packet header
                        // to the amount of data that was read.
                        pkt.set_op(VSOCK_OP_RW).set_len(read_cnt as u32);

                        // Re-register the stream file descriptor for read and write events
                        if VhostUserVsockThread::epoll_modify(
                            self.epoll_fd,
                            self.stream.as_raw_fd(),
                            epoll::Events::EPOLLIN | epoll::Events::EPOLLOUT,
                        )
                        .is_err()
                        {
                            if let Err(e) = VhostUserVsockThread::epoll_register(
                                self.epoll_fd,
                                self.stream.as_raw_fd(),
                                epoll::Events::EPOLLIN | epoll::Events::EPOLLOUT,
                            ) {
                                // TODO: let's move this logic out of this func, and handle it properly
                                error!("epoll_register failed: {:?}, but proceed further.", e);
                            }
                        };
                    }

                    // Update the rx_cnt with the amount of data in the vsock packet.
                    self.rx_cnt += Wrapping(pkt.len());
                    self.last_fwd_cnt = self.fwd_cnt;
                }
                Ok(())
            }
            Some(RxOps::Response) => {
                // A response has been received to a newly initiated host-side connection
                self.connect = true;
                pkt.set_op(VSOCK_OP_RESPONSE);
                Ok(())
            }
            Some(RxOps::CreditUpdate) => {
                // Request credit update from the guest.
                if !self.rx_queue.pending_rx() {
                    // Waste an rx buffer if no rx is pending
                    pkt.set_op(VSOCK_OP_CREDIT_UPDATE);
                    self.last_fwd_cnt = self.fwd_cnt;
                }
                Ok(())
            }
            _ => Err(Error::NoRequestRx),
        }
    }

    /// Deliver a guest generated packet to this connection.
    ///
    /// Returns:
    /// - always `Ok(())` to indicate that the packet has been consumed
    pub fn send_pkt<B: BitmapSlice>(&mut self, pkt: &VsockPacket<B>) -> Result<()> {
        // Update peer credit information
        self.peer_buf_alloc = pkt.buf_alloc();
        self.peer_fwd_cnt = Wrapping(pkt.fwd_cnt());

        match pkt.op() {
            VSOCK_OP_RESPONSE => {
                if self.stream.is_hybrid_vsock() {
                    // Confirmation for a host initiated connection
                    // TODO: Handle stream write error in a better manner
                    let response = format!("OK {}\n", self.peer_port);
                    self.stream.write_all(response.as_bytes()).unwrap();
                }
                self.connect = true;
            }
            VSOCK_OP_RW => {
                // Data has to be written to the host-side stream
                match pkt.data_slice() {
                    None => {
                        info!(
                            "Dropping empty packet from guest (lp={}, pp={})",
                            self.local_port, self.peer_port
                        );
                        return Ok(());
                    }
                    Some(buf) => {
                        if let Err(err) = self.send_bytes(buf) {
                            // TODO: Terminate this connection
                            dbg!("err:{:?}", err);
                            return Ok(());
                        }
                    }
                }
            }
            VSOCK_OP_CREDIT_UPDATE => {
                // Already updated the credit

                // Re-register the stream file descriptor for read and write events
                if VhostUserVsockThread::epoll_modify(
                    self.epoll_fd,
                    self.stream.as_raw_fd(),
                    epoll::Events::EPOLLIN | epoll::Events::EPOLLOUT,
                )
                .is_err()
                {
                    if let Err(e) = VhostUserVsockThread::epoll_register(
                        self.epoll_fd,
                        self.stream.as_raw_fd(),
                        epoll::Events::EPOLLIN | epoll::Events::EPOLLOUT,
                    ) {
                        // TODO: let's move this logic out of this func, and handle it properly
                        error!("epoll_register failed: {:?}, but proceed further.", e);
                    }
                };
            }
            VSOCK_OP_CREDIT_REQUEST => {
                // Send back this connection's credit information
                self.rx_queue.enqueue(RxOps::CreditUpdate);
            }
            VSOCK_OP_SHUTDOWN => {
                // Shutdown this connection
                let recv_off = pkt.flags() & VSOCK_FLAGS_SHUTDOWN_RCV != 0;
                let send_off = pkt.flags() & VSOCK_FLAGS_SHUTDOWN_SEND != 0;

                if recv_off && send_off && self.tx_buf.is_empty() {
                    self.rx_queue.enqueue(RxOps::Reset);
                }
            }
            _ => {}
        }

        Ok(())
    }

    /// Write data to the host-side stream.
    ///
    /// Returns:
    /// - Ok(cnt) where cnt is the number of bytes written to the stream
    /// - Err(Error::StreamWrite) if there was an error writing to the stream
    fn send_bytes<B: BitmapSlice>(&mut self, buf: &VolatileSlice<B>) -> Result<()> {
        if !self.tx_buf.is_empty() {
            // Data is already present in the buffer and the backend
            // is waiting for a EPOLLOUT event to flush it
            return self.tx_buf.push(buf);
        }

        // Write data to the stream

        let written_count = match self.stream.write_volatile(buf) {
            Ok(cnt) => cnt,
            Err(vm_memory::VolatileMemoryError::IOError(e)) => {
                if e.kind() == ErrorKind::WouldBlock {
                    0
                } else {
                    dbg!("send_bytes error: {:?}", e);
                    return Err(Error::StreamWrite);
                }
            }
            Err(e) => {
                dbg!("send_bytes error: {:?}", e);
                return Err(Error::StreamWrite);
            }
        };

        if written_count > 0 {
            // Increment forwarded count by number of bytes written to the stream
            self.fwd_cnt += Wrapping(written_count as u32);

            // At what point in available credits should we send a credit update.
            // This is set to 1/4th of the tx buffer size. If we keep it too low,
            // we will end up sending too many credit updates. If we keep it too
            // high, we will end up sending too few credit updates and cause stalls.
            // Stalls are more bad than too many credit updates.
            let free_space = self
                .tx_buffer_size
                .wrapping_sub((self.fwd_cnt - self.last_fwd_cnt).0);
            if free_space < self.tx_buffer_size / 4 {
                self.rx_queue.enqueue(RxOps::CreditUpdate);
            }
        }

        if written_count != buf.len() {
            return self.tx_buf.push(&buf.offset(written_count).unwrap());
        }

        Ok(())
    }

    /// Initialize all header fields in the vsock packet.
    fn init_pkt<'a, 'b, B: BitmapSlice>(
        &self,
        pkt: &'a mut VsockPacket<'b, B>,
    ) -> &'a mut VsockPacket<'b, B> {
        // Zero out the packet header
        pkt.set_header_from_raw(&[0u8; PKT_HEADER_SIZE]).unwrap();

        pkt.set_src_cid(self.local_cid)
            .set_dst_cid(self.guest_cid)
            .set_src_port(self.local_port)
            .set_dst_port(self.peer_port)
            .set_type(VSOCK_TYPE_STREAM)
            .set_buf_alloc(self.tx_buffer_size)
            .set_fwd_cnt(self.fwd_cnt.0)
    }

    /// Get max number of bytes we can send to peer without overflowing
    /// the peer's buffer.
    fn peer_avail_credit(&self) -> usize {
        (Wrapping(self.peer_buf_alloc) - (self.rx_cnt - self.peer_fwd_cnt)).0 as usize
    }

    /// Check if we need a credit update from the peer before sending
    /// more data to it.
    fn need_credit_update_from_peer(&self) -> bool {
        self.peer_avail_credit() == 0
    }
}

#[cfg(test)]
mod tests {
    use byteorder::{ByteOrder, LittleEndian};

    use super::*;
    use crate::vhu_vsock::{VSOCK_HOST_CID, VSOCK_OP_RW, VSOCK_TYPE_STREAM};
    use std::collections::VecDeque;
    use std::io::{Read, Result as IoResult};
    use std::ops::Deref;
    use std::sync::{Arc, Mutex};
    use virtio_bindings::bindings::virtio_ring::{VRING_DESC_F_NEXT, VRING_DESC_F_WRITE};
    use virtio_queue::{mock::MockSplitQueue, Descriptor, DescriptorChain, Queue, QueueOwnedT};
    use vm_memory::{
        Address, Bytes, GuestAddress, GuestAddressSpace, GuestMemoryAtomic, GuestMemoryLoadGuard,
        GuestMemoryMmap,
    };

    const CONN_TX_BUF_SIZE: u32 = 64 * 1024;

    struct HeadParams {
        head_len: usize,
        data_len: u32,
    }

    impl HeadParams {
        fn new(head_len: usize, data_len: u32) -> Self {
            Self { head_len, data_len }
        }
        fn construct_head(&self) -> Vec<u8> {
            let mut header = vec![0_u8; self.head_len];
            if self.head_len == PKT_HEADER_SIZE {
                // Offset into the header for data length
                const HDROFF_LEN: usize = 24;
                LittleEndian::write_u32(&mut header[HDROFF_LEN..], self.data_len);
            }
            header
        }
    }

    fn prepare_desc_chain_vsock(
        write_only: bool,
        head_params: &HeadParams,
        data_chain_len: u16,
        head_data_len: u32,
    ) -> (
        GuestMemoryAtomic<GuestMemoryMmap>,
        DescriptorChain<GuestMemoryLoadGuard<GuestMemoryMmap>>,
    ) {
        let mem = GuestMemoryMmap::<()>::from_ranges(&[(GuestAddress(0), 0x1000)]).unwrap();
        let virt_queue = MockSplitQueue::new(&mem, 16);
        let mut next_addr = virt_queue.desc_table().total_size() + 0x100;
        let mut flags = 0;

        if write_only {
            flags |= VRING_DESC_F_WRITE;
        }

        let mut head_flags = if data_chain_len > 0 {
            flags | VRING_DESC_F_NEXT
        } else {
            flags
        };

        // vsock packet header
        // let header = vec![0 as u8; head_params.head_len];
        let header = head_params.construct_head();
        let head_desc =
            Descriptor::new(next_addr, head_params.head_len as u32, head_flags as u16, 1);
        mem.write(&header, head_desc.addr()).unwrap();
        assert!(virt_queue.desc_table().store(0, head_desc).is_ok());
        next_addr += head_params.head_len as u64;

        // Put the descriptor index 0 in the first available ring position.
        mem.write_obj(0u16, virt_queue.avail_addr().unchecked_add(4))
            .unwrap();

        // Set `avail_idx` to 1.
        mem.write_obj(1u16, virt_queue.avail_addr().unchecked_add(2))
            .unwrap();

        // chain len excludes the head
        for i in 0..(data_chain_len) {
            // last descr in chain
            if i == data_chain_len - 1 {
                head_flags &= !VRING_DESC_F_NEXT;
            }
            // vsock data
            let data = vec![0_u8; head_data_len as usize];
            let data_desc = Descriptor::new(next_addr, data.len() as u32, head_flags as u16, i + 2);
            mem.write(&data, data_desc.addr()).unwrap();
            assert!(virt_queue.desc_table().store(i + 1, data_desc).is_ok());
            next_addr += head_data_len as u64;
        }

        // Create descriptor chain from pre-filled memory
        (
            GuestMemoryAtomic::new(mem.clone()),
            virt_queue
                .create_queue::<Queue>()
                .unwrap()
                .iter(GuestMemoryAtomic::new(mem.clone()).memory())
                .unwrap()
                .next()
                .unwrap(),
        )
    }

    struct VsockDummySocket {
        read_buffer: Arc<Mutex<VecDeque<u8>>>,
        write_buffer: Arc<Mutex<VecDeque<u8>>>,
    }

    impl VsockDummySocket {
        // Creates an open-ended socket.
        //
        // While one can use it to test reading and writing from it, reads will
        // always be empty and writes will never be readable by anyone else.
        fn new() -> VsockDummySocket {
            let read_buffer = Arc::new(Mutex::new(VecDeque::new()));
            let write_buffer = Arc::new(Mutex::new(VecDeque::new()));

            VsockDummySocket {
                read_buffer,
                write_buffer,
            }
        }

        // Creates a socket pair
        //
        // The read buffer of one socket is the write socket of the other (and vice versa).
        // One socket can be passed to the backend while the other can be used to fake writes
        // or to verify data that the backend wrote.
        fn pair() -> (VsockDummySocket, VsockDummySocket) {
            let buf1 = Arc::new(Mutex::new(VecDeque::new()));
            let buf2 = Arc::new(Mutex::new(VecDeque::new()));
            (
                VsockDummySocket {
                    read_buffer: buf1.clone(),
                    write_buffer: buf2.clone(),
                },
                VsockDummySocket {
                    read_buffer: buf2.clone(),
                    write_buffer: buf1.clone(),
                },
            )
        }
    }

    impl Write for VsockDummySocket {
        fn write(&mut self, buf: &[u8]) -> std::result::Result<usize, std::io::Error> {
            self.write_buffer.lock().unwrap().write(buf)
        }

        fn flush(&mut self) -> IoResult<()> {
            Ok(())
        }
    }

    impl WriteVolatile for VsockDummySocket {
        fn write_volatile<B: BitmapSlice>(
            &mut self,
            buf: &VolatileSlice<B>,
        ) -> std::result::Result<usize, vm_memory::VolatileMemoryError> {
            // VecDequeue has no fancy unsafe tricks that vm-memory can abstract.
            // One could do fairly efficient stuff using the moving From<Vec> imp...
            // But this is just for tests, so lets clone, convert to Vec, append, convert back and replace.
            let mut write_buffer = self.write_buffer.lock().unwrap();
            let mut vec = Vec::from(write_buffer.clone());
            let n = vec.write_volatile(buf)?;
            *write_buffer = VecDeque::from(vec);

            Ok(n)
        }
    }

    impl Read for VsockDummySocket {
        fn read(&mut self, buf: &mut [u8]) -> IoResult<usize> {
            self.read_buffer.lock().unwrap().read(buf)
        }
    }

    impl ReadVolatile for VsockDummySocket {
        fn read_volatile<B: BitmapSlice>(
            &mut self,
            buf: &mut VolatileSlice<B>,
        ) -> std::result::Result<usize, vm_memory::VolatileMemoryError> {
            // Similar to the std's Read impl, we only read on the head. Since
            // we drain the head, successive reads will cover the rest of the
            // queue.
            let mut read_buffer = self.read_buffer.lock().unwrap();
            let (head, _) = read_buffer.as_slices();
            let n = ReadVolatile::read_volatile(&mut &head[..], buf)?;
            read_buffer.drain(..n);

            Ok(n)
        }
    }

    impl AsRawFd for VsockDummySocket {
        fn as_raw_fd(&self) -> RawFd {
            -1
        }
    }

    impl IsHybridVsock for VsockDummySocket {
        fn is_hybrid_vsock(&self) -> bool {
            true
        }
    }

    #[test]
    fn test_vsock_conn_init() {
        // new locally inititated connection
        let mut dummy_file = VsockDummySocket::new();
        assert!(dummy_file.flush().is_ok());
        let mut conn_local = VsockConnection::new_local_init(
            dummy_file,
            VSOCK_HOST_CID,
            5000,
            3,
            5001,
            -1,
            CONN_TX_BUF_SIZE,
        );

        assert!(!conn_local.connect);
        assert_eq!(conn_local.peer_port, 5001);
        assert_eq!(conn_local.rx_queue, RxQueue::new());
        assert_eq!(conn_local.local_cid, VSOCK_HOST_CID);
        assert_eq!(conn_local.local_port, 5000);
        assert_eq!(conn_local.guest_cid, 3);

        // set peer port
        conn_local.set_peer_port(5002);
        assert_eq!(conn_local.peer_port, 5002);

        // New connection initiated by the peer/guest
        let dummy_file = VsockDummySocket::new();
        let mut conn_peer = VsockConnection::new_peer_init(
            dummy_file,
            VSOCK_HOST_CID,
            5000,
            3,
            5001,
            -1,
            65536,
            CONN_TX_BUF_SIZE,
        );

        assert!(!conn_peer.connect);
        assert_eq!(conn_peer.peer_port, 5001);
        assert_eq!(conn_peer.rx_queue.dequeue().unwrap(), RxOps::Response);
        assert!(!conn_peer.rx_queue.pending_rx());
        assert_eq!(conn_peer.local_cid, VSOCK_HOST_CID);
        assert_eq!(conn_peer.local_port, 5000);
        assert_eq!(conn_peer.guest_cid, 3);
        assert_eq!(conn_peer.peer_buf_alloc, 65536);
    }

    #[test]
    fn test_vsock_conn_credit() {
        // new locally inititated connection
        let dummy_file = VsockDummySocket::new();
        let mut conn_local = VsockConnection::new_local_init(
            dummy_file,
            VSOCK_HOST_CID,
            5000,
            3,
            5001,
            -1,
            CONN_TX_BUF_SIZE,
        );

        assert_eq!(conn_local.peer_avail_credit(), 0);
        assert!(conn_local.need_credit_update_from_peer());

        conn_local.peer_buf_alloc = 65536;
        assert_eq!(conn_local.peer_avail_credit(), 65536);
        assert!(!conn_local.need_credit_update_from_peer());

        conn_local.rx_cnt = Wrapping(32768);
        assert_eq!(conn_local.peer_avail_credit(), 32768);
        assert!(!conn_local.need_credit_update_from_peer());

        conn_local.rx_cnt = Wrapping(65536);
        assert_eq!(conn_local.peer_avail_credit(), 0);
        assert!(conn_local.need_credit_update_from_peer());
    }

    #[test]
    fn test_vsock_conn_init_pkt() {
        // parameters for packet head construction
        let head_params = HeadParams::new(PKT_HEADER_SIZE, 10);

        let dummy_file = VsockDummySocket::new();
        let conn_local = VsockConnection::new_local_init(
            dummy_file,
            VSOCK_HOST_CID,
            5000,
            3,
            5001,
            -1,
            CONN_TX_BUF_SIZE,
        );

        // write only descriptor chain
        let (mem, mut descr_chain) = prepare_desc_chain_vsock(true, &head_params, 2, 10);
        let mem = mem.memory();
        let mut pkt =
            VsockPacket::from_rx_virtq_chain(mem.deref(), &mut descr_chain, CONN_TX_BUF_SIZE)
                .unwrap();

        // initialize a vsock packet for the guest
        conn_local.init_pkt(&mut pkt);

        assert_eq!(pkt.src_cid(), VSOCK_HOST_CID);
        assert_eq!(pkt.dst_cid(), 3);
        assert_eq!(pkt.src_port(), 5000);
        assert_eq!(pkt.dst_port(), 5001);
        assert_eq!(pkt.type_(), VSOCK_TYPE_STREAM);
        assert_eq!(pkt.buf_alloc(), CONN_TX_BUF_SIZE);
        assert_eq!(pkt.fwd_cnt(), 0);
    }

    #[test]
    fn test_vsock_conn_recv_pkt() {
        // parameters for packet head construction
        let head_params = HeadParams::new(PKT_HEADER_SIZE, 5);

        let (mut host_socket, backend_socket) = VsockDummySocket::pair();
        let mut conn_local = VsockConnection::new_local_init(
            backend_socket,
            VSOCK_HOST_CID,
            5000,
            3,
            5001,
            -1,
            CONN_TX_BUF_SIZE,
        );

        // write only descriptor chain
        let (mem, mut descr_chain) = prepare_desc_chain_vsock(true, &head_params, 1, 5);
        let mem = mem.memory();
        let mut pkt =
            VsockPacket::from_rx_virtq_chain(mem.deref(), &mut descr_chain, CONN_TX_BUF_SIZE)
                .unwrap();

        // VSOCK_OP_REQUEST: new local conn request
        conn_local.rx_queue.enqueue(RxOps::Request);
        let op_req = conn_local.recv_pkt(&mut pkt);
        assert!(op_req.is_ok());
        assert!(!conn_local.rx_queue.pending_rx());
        assert_eq!(pkt.op(), VSOCK_OP_REQUEST);

        // VSOCK_OP_RST: reset if connection not established
        conn_local.rx_queue.enqueue(RxOps::Rw);
        let op_rst = conn_local.recv_pkt(&mut pkt);
        assert!(op_rst.is_ok());
        assert!(!conn_local.rx_queue.pending_rx());
        assert_eq!(pkt.op(), VSOCK_OP_RST);

        // VSOCK_OP_CREDIT_UPDATE: need credit update from peer/guest
        conn_local.connect = true;
        conn_local.rx_queue.enqueue(RxOps::Rw);
        conn_local.fwd_cnt = Wrapping(1024);
        let op_credit_update = conn_local.recv_pkt(&mut pkt);
        assert!(op_credit_update.is_ok());
        assert!(!conn_local.rx_queue.pending_rx());
        assert_eq!(pkt.op(), VSOCK_OP_CREDIT_REQUEST);
        assert_eq!(conn_local.last_fwd_cnt, Wrapping(1024));

        // VSOCK_OP_SHUTDOWN: zero data read from stream/file
        conn_local.peer_buf_alloc = 65536;
        conn_local.rx_queue.enqueue(RxOps::Rw);
        let op_zero_read_shutdown = conn_local.recv_pkt(&mut pkt);
        assert!(op_zero_read_shutdown.is_ok());
        assert!(!conn_local.rx_queue.pending_rx());
        assert_eq!(conn_local.rx_cnt, Wrapping(0));
        assert_eq!(conn_local.last_fwd_cnt, Wrapping(1024));
        assert_eq!(pkt.op(), VSOCK_OP_SHUTDOWN);
        assert_eq!(
            pkt.flags(),
            VSOCK_FLAGS_SHUTDOWN_RCV | VSOCK_FLAGS_SHUTDOWN_SEND
        );

        // VSOCK_OP_RW: finite data read from stream/file
        let payload = b"hello";
        host_socket.write_all(payload).unwrap();
        conn_local.rx_queue.enqueue(RxOps::Rw);
        let op_zero_read = conn_local.recv_pkt(&mut pkt);
        assert!(op_zero_read.is_ok());
        assert_eq!(pkt.op(), VSOCK_OP_RW);
        assert!(!conn_local.rx_queue.pending_rx());
        assert_eq!(conn_local.rx_cnt, Wrapping(payload.len() as u32));
        assert_eq!(conn_local.last_fwd_cnt, Wrapping(1024));
        assert_eq!(pkt.len(), 5);
        let buf = &mut [0u8; 5];
        assert!(pkt.data_slice().unwrap().read_slice(buf, 0).is_ok());
        assert_eq!(buf, b"hello");

        // VSOCK_OP_RESPONSE: response from a locally initiated connection
        conn_local.rx_queue.enqueue(RxOps::Response);
        let op_response = conn_local.recv_pkt(&mut pkt);
        assert!(op_response.is_ok());
        assert!(!conn_local.rx_queue.pending_rx());
        assert_eq!(pkt.op(), VSOCK_OP_RESPONSE);
        assert!(conn_local.connect);

        // VSOCK_OP_CREDIT_UPDATE: guest needs credit update
        conn_local.rx_queue.enqueue(RxOps::CreditUpdate);
        let op_credit_update = conn_local.recv_pkt(&mut pkt);
        assert!(!conn_local.rx_queue.pending_rx());
        assert!(op_credit_update.is_ok());
        assert_eq!(pkt.op(), VSOCK_OP_CREDIT_UPDATE);
        assert_eq!(conn_local.last_fwd_cnt, Wrapping(1024));

        // non-existent request
        let op_error = conn_local.recv_pkt(&mut pkt);
        assert!(op_error.is_err());
    }

    #[test]
    fn test_vsock_conn_send_pkt() {
        // parameters for packet head construction
        let head_params = HeadParams::new(PKT_HEADER_SIZE, 5);

        // new locally inititated connection
        let (mut host_socket, backend_socket) = VsockDummySocket::pair();
        let mut conn_local = VsockConnection::new_local_init(
            backend_socket,
            VSOCK_HOST_CID,
            5000,
            3,
            5001,
            -1,
            CONN_TX_BUF_SIZE,
        );

        // write only descriptor chain
        let (mem, mut descr_chain) = prepare_desc_chain_vsock(false, &head_params, 1, 5);
        let mem = mem.memory();
        let mut pkt =
            VsockPacket::from_tx_virtq_chain(mem.deref(), &mut descr_chain, CONN_TX_BUF_SIZE)
                .unwrap();

        // peer credit information
        pkt.set_buf_alloc(65536).set_fwd_cnt(1024);

        // check if peer credit information is updated currently
        let credit_check = conn_local.send_pkt(&pkt);
        assert!(credit_check.is_ok());
        assert_eq!(conn_local.peer_buf_alloc, 65536);
        assert_eq!(conn_local.peer_fwd_cnt, Wrapping(1024));

        // VSOCK_OP_RESPONSE
        pkt.set_op(VSOCK_OP_RESPONSE);
        assert_eq!(conn_local.peer_port, 5001);
        let peer_response = conn_local.send_pkt(&pkt);
        assert!(peer_response.is_ok());
        assert!(conn_local.connect);
        let mut resp_buf = vec![0; 8];
        host_socket.read_exact(&mut resp_buf).unwrap();
        assert_eq!(&resp_buf, b"OK 5001\n");

        // VSOCK_OP_RW
        pkt.set_op(VSOCK_OP_RW);
        let buf = b"hello";
        assert!(pkt.data_slice().unwrap().write_slice(buf, 0).is_ok());
        let rw_response = conn_local.send_pkt(&pkt);
        assert!(rw_response.is_ok());
        let mut resp_buf = vec![0; 5];
        host_socket.read_exact(&mut resp_buf).unwrap();
        assert_eq!(resp_buf, b"hello");

        // VSOCK_OP_CREDIT_REQUEST
        pkt.set_op(VSOCK_OP_CREDIT_REQUEST);
        let credit_response = conn_local.send_pkt(&pkt);
        assert!(credit_response.is_ok());
        assert_eq!(conn_local.rx_queue.peek().unwrap(), RxOps::CreditUpdate);

        // VSOCK_OP_SHUTDOWN
        pkt.set_op(VSOCK_OP_SHUTDOWN);
        pkt.set_flags(VSOCK_FLAGS_SHUTDOWN_RCV | VSOCK_FLAGS_SHUTDOWN_SEND);
        let shutdown_response = conn_local.send_pkt(&pkt);
        assert!(shutdown_response.is_ok());
        assert!(conn_local.rx_queue.contains(RxOps::Reset.bitmask()));
    }
}
