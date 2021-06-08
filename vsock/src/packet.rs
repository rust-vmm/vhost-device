#![deny(missing_docs)]
use byteorder::{ByteOrder, LittleEndian};
use thiserror::Error as ThisError;
use virtio_queue::DescriptorChain;
use vm_memory::{
    GuestAddress, GuestAddressSpace, GuestMemory, GuestMemoryAtomic, GuestMemoryLoadGuard,
    GuestMemoryMmap,
};

pub(crate) type Result<T> = std::result::Result<T, Error>;

/// Below enum defines custom error types for vsock packet operations.
#[derive(Debug, PartialEq, ThisError)]
pub(crate) enum Error {
    #[error("Descriptor not writable")]
    UnwritableDescriptor,
    #[error("Missing descriptor in queue")]
    QueueMissingDescriptor,
    #[error("Small header descriptor: {0}")]
    HdrDescTooSmall(u32),
    #[error("Chained guest memory error")]
    GuestMemory,
    #[error("Descriptor not readable")]
    UnreadableDescriptor,
    #[error("Extra descriptors in the descriptor chain")]
    ExtraDescrInChain,
    #[error("Data buffer size less than size in packet header")]
    DataDescTooSmall,
}

// TODO: Replace below with bindgen generated struct
// vsock packet header size when packed
pub const VSOCK_PKT_HDR_SIZE: usize = 44;

// Offset into header for source cid
const HDROFF_SRC_CID: usize = 0;

// Offset into header for destination cid
const HDROFF_DST_CID: usize = 8;

// Offset into header for source port
const HDROFF_SRC_PORT: usize = 16;

// Offset into header for destination port
const HDROFF_DST_PORT: usize = 20;

// Offset into the header for data length
const HDROFF_LEN: usize = 24;

// Offset into header for packet type
const HDROFF_TYPE: usize = 28;

// Offset into header for operation kind
const HDROFF_OP: usize = 30;

// Offset into header for additional flags
// only for VSOCK_OP_SHUTDOWN
const HDROFF_FLAGS: usize = 32;

// Offset into header for tx buf alloc
const HDROFF_BUF_ALLOC: usize = 36;

// Offset into header for forward count
const HDROFF_FWD_CNT: usize = 40;

/// Vsock packet structure implemented as a wrapper around a virtq descriptor chain:
/// - chain head holds the packet header
/// - optional data descriptor, only present for data packets (VSOCK_OP_RW)
#[derive(Debug)]
pub struct VsockPacket {
    hdr: *mut u8,
    buf: Option<*mut u8>,
    buf_size: usize,
}

impl VsockPacket {
    /// Create a vsock packet wrapper around a chain in the rx virtqueue.
    /// Perform bounds checking before creating the wrapper.
    pub(crate) fn from_rx_virtq_head(
        chain: &mut DescriptorChain<GuestMemoryLoadGuard<GuestMemoryMmap<()>>>,
        mem: GuestMemoryAtomic<GuestMemoryMmap>,
    ) -> Result<Self> {
        // head is at 0, next is at 1, max of two descriptors
        // head contains the packet header
        // next contains the optional packet data
        let mut descr_vec = Vec::with_capacity(2);

        for descr in chain {
            if !descr.is_write_only() {
                return Err(Error::UnwritableDescriptor);
            }

            descr_vec.push(descr);
        }

        if descr_vec.len() < 2 {
            // We expect a head and a data descriptor
            return Err(Error::QueueMissingDescriptor);
        }

        let head_descr = descr_vec[0];
        let data_descr = descr_vec[1];

        if head_descr.len() < VSOCK_PKT_HDR_SIZE as u32 {
            return Err(Error::HdrDescTooSmall(head_descr.len()));
        }

        Ok(Self {
            hdr: VsockPacket::guest_to_host_address(
                &mem.memory(),
                head_descr.addr(),
                VSOCK_PKT_HDR_SIZE,
            )
            .ok_or(Error::GuestMemory)? as *mut u8,
            buf: Some(
                VsockPacket::guest_to_host_address(
                    &mem.memory(),
                    data_descr.addr(),
                    data_descr.len() as usize,
                )
                .ok_or(Error::GuestMemory)? as *mut u8,
            ),
            buf_size: data_descr.len() as usize,
        })
    }

    /// Create a vsock packet wrapper around a chain in the tx virtqueue
    /// Bounds checking before creating the wrapper.
    pub(crate) fn from_tx_virtq_head(
        chain: &mut DescriptorChain<GuestMemoryLoadGuard<GuestMemoryMmap<()>>>,
        mem: GuestMemoryAtomic<GuestMemoryMmap>,
    ) -> Result<Self> {
        // head is at 0, next is at 1, max of two descriptors
        // head contains the packet header
        // next contains the optional packet data
        let mut descr_vec = Vec::with_capacity(2);
        // let mut num_descr = 0;

        for descr in chain {
            if descr.is_write_only() {
                return Err(Error::UnreadableDescriptor);
            }

            descr_vec.push(descr);
        }

        if descr_vec.len() > 2 {
            return Err(Error::ExtraDescrInChain);
        }

        let head_descr = descr_vec[0];

        if head_descr.len() < VSOCK_PKT_HDR_SIZE as u32 {
            return Err(Error::HdrDescTooSmall(head_descr.len()));
        }

        let mut pkt = Self {
            hdr: VsockPacket::guest_to_host_address(
                &mem.memory(),
                head_descr.addr(),
                VSOCK_PKT_HDR_SIZE,
            )
            .ok_or(Error::GuestMemory)? as *mut u8,
            buf: None,
            buf_size: 0,
        };

        // Zero length packet
        if pkt.is_empty() {
            return Ok(pkt);
        }

        // There exists packet data as well
        let data_descr = descr_vec[1];

        // Data buffer should be as large as described in the header
        if data_descr.len() < pkt.len() {
            return Err(Error::DataDescTooSmall);
        }

        pkt.buf_size = data_descr.len() as usize;
        pkt.buf = Some(
            VsockPacket::guest_to_host_address(
                &mem.memory(),
                data_descr.addr(),
                data_descr.len() as usize,
            )
            .ok_or(Error::GuestMemory)? as *mut u8,
        );

        Ok(pkt)
    }

    /// Convert an absolute address in guest address space to a host
    /// pointer and verify that the provided size defines a valid
    /// range within a single memory region.
    fn guest_to_host_address(
        mem: &GuestMemoryLoadGuard<GuestMemoryMmap>,
        addr: GuestAddress,
        size: usize,
    ) -> Option<*mut u8> {
        if mem.check_range(addr, size) {
            Some(mem.get_host_address(addr).unwrap())
        } else {
            None
        }
    }

    /// In place byte slice access to vsock packet header.
    pub fn hdr(&self) -> &[u8] {
        // Safe as bound checks performed in from_*_virtq_head
        unsafe { std::slice::from_raw_parts(self.hdr as *const u8, VSOCK_PKT_HDR_SIZE) }
    }

    /// In place mutable slice access to vsock packet header.
    pub fn hdr_mut(&mut self) -> &mut [u8] {
        // Safe as bound checks performed in from_*_virtq_head
        unsafe { std::slice::from_raw_parts_mut(self.hdr, VSOCK_PKT_HDR_SIZE) }
    }

    /// Size of vsock packet data, found by accessing len field
    /// of virtio_vsock_hdr struct.
    pub fn len(&self) -> u32 {
        LittleEndian::read_u32(&self.hdr()[HDROFF_LEN..])
    }

    /// Set the source cid.
    pub fn set_src_cid(&mut self, cid: u64) -> &mut Self {
        LittleEndian::write_u64(&mut self.hdr_mut()[HDROFF_SRC_CID..], cid);
        self
    }

    /// Set the destination cid.
    pub fn set_dst_cid(&mut self, cid: u64) -> &mut Self {
        LittleEndian::write_u64(&mut self.hdr_mut()[HDROFF_DST_CID..], cid);
        self
    }

    /// Set source port.
    pub fn set_src_port(&mut self, port: u32) -> &mut Self {
        LittleEndian::write_u32(&mut self.hdr_mut()[HDROFF_SRC_PORT..], port);
        self
    }

    /// Set destination port.
    pub fn set_dst_port(&mut self, port: u32) -> &mut Self {
        LittleEndian::write_u32(&mut self.hdr_mut()[HDROFF_DST_PORT..], port);
        self
    }

    /// Set type of connection.
    pub fn set_type(&mut self, type_: u16) -> &mut Self {
        LittleEndian::write_u16(&mut self.hdr_mut()[HDROFF_TYPE..], type_);
        self
    }

    /// Set size of tx buf.
    pub fn set_buf_alloc(&mut self, buf_alloc: u32) -> &mut Self {
        LittleEndian::write_u32(&mut self.hdr_mut()[HDROFF_BUF_ALLOC..], buf_alloc);
        self
    }

    /// Set amount of tx buf data written to stream.
    pub fn set_fwd_cnt(&mut self, fwd_cnt: u32) -> &mut Self {
        LittleEndian::write_u32(&mut self.hdr_mut()[HDROFF_FWD_CNT..], fwd_cnt);
        self
    }

    /// Set packet operation ID.
    pub fn set_op(&mut self, op: u16) -> &mut Self {
        LittleEndian::write_u16(&mut self.hdr_mut()[HDROFF_OP..], op);
        self
    }

    /// Check if the packet has no data.
    fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Get destination port from packet.
    pub fn dst_port(&self) -> u32 {
        LittleEndian::read_u32(&self.hdr()[HDROFF_DST_PORT..])
    }

    /// Get source port from packet.
    pub fn src_port(&self) -> u32 {
        LittleEndian::read_u32(&self.hdr()[HDROFF_SRC_PORT..])
    }

    /// Get source cid from packet.
    pub fn src_cid(&self) -> u64 {
        LittleEndian::read_u64(&self.hdr()[HDROFF_SRC_CID..])
    }

    /// Get destination cid from packet.
    pub fn dst_cid(&self) -> u64 {
        LittleEndian::read_u64(&self.hdr()[HDROFF_DST_CID..])
    }

    /// Get packet type.
    pub fn pkt_type(&self) -> u16 {
        LittleEndian::read_u16(&self.hdr()[HDROFF_TYPE..])
    }

    /// Get operation requested in the packet.
    pub fn op(&self) -> u16 {
        LittleEndian::read_u16(&self.hdr()[HDROFF_OP..])
    }

    /// Byte slice mutable access to vsock packet data buffer.
    pub fn buf_mut(&mut self) -> Option<&mut [u8]> {
        // Safe as bound checks performed while creating packet
        self.buf
            .map(|ptr| unsafe { std::slice::from_raw_parts_mut(ptr, self.buf_size) })
    }

    /// Byte slice access to vsock packet data buffer.
    pub fn buf(&self) -> Option<&[u8]> {
        // Safe as bound checks performed while creating packet
        self.buf
            .map(|ptr| unsafe { std::slice::from_raw_parts(ptr as *const u8, self.buf_size) })
    }

    /// Set data buffer length.
    pub fn set_len(&mut self, len: u32) -> &mut Self {
        LittleEndian::write_u32(&mut self.hdr_mut()[HDROFF_LEN..], len);
        self
    }

    /// Read buf alloc.
    pub fn buf_alloc(&self) -> u32 {
        LittleEndian::read_u32(&self.hdr()[HDROFF_BUF_ALLOC..])
    }

    /// Get fwd cnt from packet header.
    pub fn fwd_cnt(&self) -> u32 {
        LittleEndian::read_u32(&self.hdr()[HDROFF_FWD_CNT..])
    }

    /// Read flags from the packet header.
    pub fn flags(&self) -> u32 {
        LittleEndian::read_u32(&self.hdr()[HDROFF_FLAGS..])
    }

    /// Set packet header flag to flags.
    pub fn set_flags(&mut self, flags: u32) -> &mut Self {
        LittleEndian::write_u32(&mut self.hdr_mut()[HDROFF_FLAGS..], flags);
        self
    }

    /// Set OP specific flags.
    pub fn set_flag(&mut self, flag: u32) -> &mut Self {
        self.set_flags(self.flags() | flag);
        self
    }
}

#[cfg(test)]
pub mod tests {
    use crate::vhu_vsock::{VSOCK_OP_RW, VSOCK_TYPE_STREAM};

    use super::*;
    use virtio_queue::{
        defs::{VIRTQ_DESC_F_NEXT, VIRTQ_DESC_F_WRITE},
        mock::MockSplitQueue,
        Descriptor,
    };
    use vm_memory::{Address, Bytes, GuestAddress, GuestMemoryAtomic, GuestMemoryMmap};

    pub struct HeadParams {
        head_len: usize,
        data_len: u32,
    }

    impl HeadParams {
        pub fn new(head_len: usize, data_len: u32) -> Self {
            Self { head_len, data_len }
        }
        fn construct_head(&self) -> Vec<u8> {
            let mut header = vec![0_u8; self.head_len];
            if self.head_len == VSOCK_PKT_HDR_SIZE {
                LittleEndian::write_u32(&mut header[HDROFF_LEN..], self.data_len);
            }
            header
        }
    }

    pub fn prepare_desc_chain_vsock(
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
        let mut head_flags;

        if write_only {
            flags |= VIRTQ_DESC_F_WRITE;
        }

        if data_chain_len > 0 {
            head_flags = flags | VIRTQ_DESC_F_NEXT
        } else {
            head_flags = flags;
        }

        // vsock packet header
        // let header = vec![0 as u8; head_params.head_len];
        let header = head_params.construct_head();
        let head_desc = Descriptor::new(next_addr, head_params.head_len as u32, head_flags, 1);
        mem.write(&header, head_desc.addr()).unwrap();
        virt_queue.desc_table().store(0, head_desc);
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
                head_flags &= !VIRTQ_DESC_F_NEXT;
            }
            // vsock data
            let data = vec![0_u8; head_data_len as usize];
            let data_desc = Descriptor::new(next_addr, data.len() as u32, head_flags, i + 2);
            mem.write(&data, data_desc.addr()).unwrap();
            virt_queue.desc_table().store(i + 1, data_desc);
            next_addr += head_data_len as u64;
        }

        // Create descriptor chain from pre-filled memory
        (
            GuestMemoryAtomic::new(mem.clone()),
            virt_queue
                .create_queue(GuestMemoryAtomic::<GuestMemoryMmap>::new(mem.clone()))
                .iter()
                .unwrap()
                .next()
                .unwrap(),
        )
    }

    #[test]
    fn test_guest_to_host_address() {
        let mem = GuestMemoryAtomic::new(
            GuestMemoryMmap::<()>::from_ranges(&[(GuestAddress(0), 1000)]).unwrap(),
        );
        assert!(VsockPacket::guest_to_host_address(&mem.memory(), GuestAddress(0), 1000).is_some());
        assert!(VsockPacket::guest_to_host_address(&mem.memory(), GuestAddress(0), 500).is_some());
        assert!(
            VsockPacket::guest_to_host_address(&mem.memory(), GuestAddress(500), 500).is_some()
        );
        assert!(
            VsockPacket::guest_to_host_address(&mem.memory(), GuestAddress(501), 500).is_none()
        );
    }

    #[test]
    fn test_from_rx_virtq_head() {
        // parameters for packet head construction
        let head_params = HeadParams::new(VSOCK_PKT_HDR_SIZE, 10);

        // write only descriptor chain
        let (mem, mut descr_chain) = prepare_desc_chain_vsock(true, &head_params, 2, 10);
        assert!(VsockPacket::from_rx_virtq_head(&mut descr_chain, mem).is_ok());

        // read only descriptor chain
        let (mem, mut descr_chain) = prepare_desc_chain_vsock(false, &head_params, 1, 10);
        assert_eq!(
            VsockPacket::from_rx_virtq_head(&mut descr_chain, mem).unwrap_err(),
            Error::UnwritableDescriptor
        );

        // less than two descriptors
        let (mem, mut descr_chain) = prepare_desc_chain_vsock(true, &head_params, 0, 10);
        assert_eq!(
            VsockPacket::from_rx_virtq_head(&mut descr_chain, mem).unwrap_err(),
            Error::QueueMissingDescriptor
        );

        // incorrect header length
        let head_params = HeadParams::new(22, 10);
        let (mem, mut descr_chain) = prepare_desc_chain_vsock(true, &head_params, 1, 10);
        assert_eq!(
            VsockPacket::from_rx_virtq_head(&mut descr_chain, mem).unwrap_err(),
            Error::HdrDescTooSmall(22)
        );
    }

    #[test]
    fn test_vsock_packet_header_ops() {
        // parameters for head construction
        let head_params = HeadParams::new(VSOCK_PKT_HDR_SIZE, 10);

        let (mem, mut descr_chain) = prepare_desc_chain_vsock(true, &head_params, 2, 10);
        let mut vsock_packet = VsockPacket::from_rx_virtq_head(&mut descr_chain, mem).unwrap();

        // Check packet data's length
        assert!(!vsock_packet.is_empty());
        assert_eq!(vsock_packet.len(), 10);

        // Set and get the source CID in the packet header
        vsock_packet.set_src_cid(1);
        assert_eq!(vsock_packet.src_cid(), 1);

        // Set and get the destination CID in the packet header
        vsock_packet.set_dst_cid(1);
        assert_eq!(vsock_packet.dst_cid(), 1);

        // Set and get the source port in the packet header
        vsock_packet.set_src_port(5000);
        assert_eq!(vsock_packet.src_port(), 5000);

        // Set and get the destination port in the packet header
        vsock_packet.set_dst_port(5000);
        assert_eq!(vsock_packet.dst_port(), 5000);

        // Set and get packet type
        vsock_packet.set_type(VSOCK_TYPE_STREAM);
        assert_eq!(vsock_packet.pkt_type(), VSOCK_TYPE_STREAM);

        // Set and get tx buffer size
        vsock_packet.set_buf_alloc(10);
        assert_eq!(vsock_packet.buf_alloc(), 10);

        // Set and get fwd_cnt of packet's data
        vsock_packet.set_fwd_cnt(100);
        assert_eq!(vsock_packet.fwd_cnt(), 100);

        // Set and get packet operation type
        vsock_packet.set_op(VSOCK_OP_RW);
        assert_eq!(vsock_packet.op(), VSOCK_OP_RW);

        // Set and get length of packet's data buffer
        // this is a dummy test
        vsock_packet.set_len(20);
        assert_eq!(vsock_packet.len(), 20);
        assert!(!vsock_packet.is_empty());

        // Set and get packet's flags
        vsock_packet.set_flags(1);
        assert_eq!(vsock_packet.flags(), 1);
    }

    #[test]
    fn test_from_tx_virtq_head() {
        // parameters for head construction
        let head_params = HeadParams::new(VSOCK_PKT_HDR_SIZE, 0);

        // read only descriptor chain no data
        let (mem, mut descr_chain) = prepare_desc_chain_vsock(false, &head_params, 0, 0);
        assert!(VsockPacket::from_tx_virtq_head(&mut descr_chain, mem).is_ok());

        // parameters for head construction
        let head_params = HeadParams::new(VSOCK_PKT_HDR_SIZE, 10);

        // read only descriptor chain
        let (mem, mut descr_chain) = prepare_desc_chain_vsock(false, &head_params, 1, 10);
        assert!(VsockPacket::from_tx_virtq_head(&mut descr_chain, mem).is_ok());

        // write only descriptor chain
        let (mem, mut descr_chain) = prepare_desc_chain_vsock(true, &head_params, 1, 10);
        assert_eq!(
            VsockPacket::from_tx_virtq_head(&mut descr_chain, mem).unwrap_err(),
            Error::UnreadableDescriptor
        );

        // more than 2 descriptors in chain
        let (mem, mut descr_chain) = prepare_desc_chain_vsock(false, &head_params, 2, 10);
        assert_eq!(
            VsockPacket::from_tx_virtq_head(&mut descr_chain, mem).unwrap_err(),
            Error::ExtraDescrInChain
        );

        // length of data descriptor does not match the value in head
        let (mem, mut descr_chain) = prepare_desc_chain_vsock(false, &head_params, 1, 5);
        assert_eq!(
            VsockPacket::from_tx_virtq_head(&mut descr_chain, mem).unwrap_err(),
            Error::DataDescTooSmall
        );
    }
}
