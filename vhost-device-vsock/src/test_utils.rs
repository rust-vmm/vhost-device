// SPDX-License-Identifier: Apache-2.0 or BSD-3-Clause

use byteorder::{ByteOrder, LittleEndian};
use virtio_bindings::bindings::virtio_ring::{VRING_DESC_F_NEXT, VRING_DESC_F_WRITE};
use virtio_queue::{
    desc::{split::Descriptor as SplitDescriptor, RawDescriptor},
    mock::MockSplitQueue,
    DescriptorChain, Queue, QueueOwnedT,
};
use virtio_vsock::packet::PKT_HEADER_SIZE;
use vm_memory::{
    Address, Bytes, GuestAddress, GuestAddressSpace, GuestMemoryAtomic, GuestMemoryLoadGuard,
    GuestMemoryMmap,
};

pub(crate) fn prepare_desc_chain_vsock(
    write_only: bool,
    head_len: usize,
    data_chain_len: u16,
    data: &[u8],
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
    let mut header = vec![0_u8; head_len];
    if head_len == PKT_HEADER_SIZE {
        // Offset into the header for data length
        const HDROFF_LEN: usize = 24;
        LittleEndian::write_u32(&mut header[HDROFF_LEN..], data.len() as u32);
    }

    let head_desc = RawDescriptor::from(SplitDescriptor::new(
        next_addr,
        head_len as u32,
        head_flags as u16,
        1,
    ));
    mem.write(&header, SplitDescriptor::from(head_desc).addr())
        .unwrap();
    virt_queue.desc_table().store(0, head_desc).unwrap();
    next_addr += head_len as u64;

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
        let data_desc = RawDescriptor::from(SplitDescriptor::new(
            next_addr,
            data.len() as u32,
            head_flags as u16,
            i + 2,
        ));
        mem.write(data, SplitDescriptor::from(data_desc).addr())
            .unwrap();
        virt_queue.desc_table().store(i + 1, data_desc).unwrap();
        next_addr += data.len() as u64;
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
