// Copyright 2025 Red Hat Inc
//
// SPDX-License-Identifier: Apache-2.0 or BSD-3-Clause

use std::{
    fs::File,
    iter::zip,
    mem,
    os::fd::{AsRawFd, FromRawFd},
};

use assert_matches::assert_matches;
use libc::EFD_NONBLOCK;
use rutabaga_gfx::RutabagaFence;
use vhost::vhost_user::gpu_message::VhostUserGpuCursorPos;
use vhost_user_backend::{VringRwLock, VringT};
use virtio_bindings::virtio_ring::{VRING_DESC_F_NEXT, VRING_DESC_F_WRITE};
use virtio_queue::{
    desc::{split::Descriptor as SplitDescriptor, RawDescriptor},
    mock::MockSplitQueue,
    Queue, QueueT,
};
use vm_memory::{
    Bytes, GuestAddress, GuestAddressSpace, GuestMemory, GuestMemoryAtomic, GuestMemoryMmap,
};
use vmm_sys_util::eventfd::EventFd;

use crate::{
    gpu_types::VirtioGpuRing,
    protocol::GpuResponse::{ErrUnspec, OkCapset, OkCapsetInfo, OkNoData},
    renderer::Renderer,
};

pub struct TestingDescChainArgs<'a> {
    /// Each readable buffer becomes a descriptor (no WRITE flag)
    pub readable_desc_bufs: &'a [&'a [u8]],
    /// Each length becomes a writable descriptor (WRITE flag set)
    pub writable_desc_lengths: &'a [u32],
}

// Common function to test fence creation and processing logic.
// It takes a mutable reference to backend Gpu component and the fence object.
pub fn test_fence_operations<T: Renderer>(gpu_device: &mut T) {
    let fence = RutabagaFence {
        flags: 0,
        fence_id: 0,
        ctx_id: 1,
        ring_idx: 0,
    };
    // Test creating a fence with the `RutabagaFence`
    // This assumes create_fence returns Result<Result<NoData>> or similar nested
    // result
    let result = gpu_device.create_fence(fence);
    assert_matches!(result, Ok(OkNoData)); // Assuming OkNoData is defined

    // Test processing gpu fence: If the fence has already been signaled return true
    // This test logic implies that 'create_fence' automatically signals the first
    // fence (fence ID 0) or that the GfxstreamGpu is initialized with fence 0
    // already completed.
    let ring = VirtioGpuRing::Global;
    let result = gpu_device.process_fence(ring.clone(), 0, 0, 0); // Assuming ring, seq, flags, type
    assert_matches!(result, true, "Fence ID 0 should be signaled");

    // Test processing gpu fence: If the fence has not yet been signaled return
    // false
    let result = gpu_device.process_fence(ring, 1, 0, 0);
    assert_matches!(result, false, "Fence ID 1 should not be signaled");
}

/// Common function to validate capset discovery & fetch on any Renderer.
/// - Queries capset info at `index` (default 0 via the wrapper below)
/// - Uses the returned (`capset_id`, version) to fetch the actual capset blob.
pub fn test_capset_operations<T: Renderer>(gpu: &T, index: u32) {
    let info = gpu.get_capset_info(index);
    // Expect Ok(OkCapsetInfo { .. })
    assert_matches!(info, Ok(OkCapsetInfo { .. }));

    // Pull out id/version and fetch the capset
    let Ok(OkCapsetInfo {
        capset_id, version, ..
    }) = info
    else {
        unreachable!("assert_matches above guarantees this arm");
    };

    let caps = gpu.get_capset(capset_id, version);
    // Expect Ok(OkCapset(_))
    assert_matches!(caps, Ok(OkCapset(_)));
}

/// Test the cursor movement logic of any `GpuDevice` implementation.
/// - Resource ID 0 should hide the cursor (or fail if no resource is bound)
/// - Any other Resource ID should attempt to move the cursor (or fail if no
///   resource)
pub fn test_move_cursor<T: Renderer>(gpu_device: &mut T) {
    let cursor_pos = VhostUserGpuCursorPos {
        scanout_id: 1,
        x: 123,
        y: 123,
    };

    // Test case 1: Resource ID 0 (invalid/no resource)
    let result = gpu_device.move_cursor(0, cursor_pos);
    assert_matches!(result, Err(ErrUnspec));

    // Test case 2: Resource ID 1 (resource might exist)
    let result = gpu_device.move_cursor(1, cursor_pos);
    assert_matches!(result, Err(ErrUnspec));
}

/// Create a vring with the specified descriptor chains, queue size, and memory
/// regions. Returns the created `VringRwLock`, a vector of output buffer
/// address vectors, and the `EventFd` used for call notifications.
pub fn create_vring(
    mem: &GuestMemoryAtomic<GuestMemoryMmap>,
    chains: &[TestingDescChainArgs],
    queue_addr_start: GuestAddress,
    data_addr_start: GuestAddress,
    queue_size: u16,
) -> (VringRwLock, Vec<Vec<GuestAddress>>, EventFd) {
    let mem_handle = mem.memory();
    mem_handle
        .check_address(queue_addr_start)
        .expect("Invalid start address");

    let mut output_bufs = Vec::new();
    let vq = MockSplitQueue::create(&*mem_handle, queue_addr_start, queue_size);

    // Address of the buffer associated with the next descriptor we place
    let mut next_addr = data_addr_start.0;
    let mut chain_index_start = 0usize;
    let mut descriptors: Vec<SplitDescriptor> = Vec::new();

    for chain in chains {
        // Readable descriptors (no WRITE flag)
        for buf in chain.readable_desc_bufs.iter().copied() {
            mem_handle
                .check_address(GuestAddress(next_addr))
                .expect("Readable descriptor's buffer address is not valid!");
            let desc = SplitDescriptor::new(
                next_addr,
                u32::try_from(buf.len()).expect("Buffer too large to fit into descriptor"),
                0,
                0,
            );
            mem_handle.write(buf, desc.addr()).unwrap();
            descriptors.push(desc);
            next_addr += buf.len() as u64;
        }

        // Writable descriptors (WRITE flag)
        let mut writable_descriptor_addresses = Vec::new();
        for &desc_len in chain.writable_desc_lengths {
            mem_handle
                .check_address(GuestAddress(next_addr))
                .expect("Writable descriptor's buffer address is not valid!");
            let desc = SplitDescriptor::new(
                next_addr,
                desc_len,
                u16::try_from(VRING_DESC_F_WRITE).unwrap(),
                0,
            );
            writable_descriptor_addresses.push(desc.addr());
            descriptors.push(desc);
            next_addr += u64::from(desc_len);
        }
        output_bufs.push(writable_descriptor_addresses);

        // Link the descriptors we just appended into a single chain
        make_descriptors_into_a_chain(
            u16::try_from(chain_index_start).unwrap(),
            &mut descriptors[chain_index_start..],
        );
        chain_index_start = descriptors.len();
    }

    assert!(descriptors.len() < queue_size as usize);

    if !descriptors.is_empty() {
        let descs_raw: Vec<RawDescriptor> =
            descriptors.into_iter().map(RawDescriptor::from).collect();
        vq.build_multiple_desc_chains(&descs_raw)
            .expect("Failed to build descriptor chain");
    }

    // Create the vring and point it at the queue tables
    let queue: Queue = vq.create_queue().unwrap();
    let vring = VringRwLock::new(mem.clone(), queue_size).unwrap();

    // Install call eventfd
    let call_evt = EventFd::new(EFD_NONBLOCK).unwrap();
    let call_evt_clone = call_evt.try_clone().unwrap();
    vring
        .set_queue_info(queue.desc_table(), queue.avail_ring(), queue.used_ring())
        .unwrap();
    vring.set_call(Some(event_fd_into_file(call_evt_clone)));

    vring.set_enabled(true);
    vring.set_queue_ready(true);

    (vring, output_bufs, call_evt)
}

/// Link a slice of descriptors into a single chain starting at `start_idx`.
/// The last descriptor in the slice will have its NEXT flag cleared.
fn make_descriptors_into_a_chain(start_idx: u16, descriptors: &mut [SplitDescriptor]) {
    let last_idx = start_idx + u16::try_from(descriptors.len()).unwrap() - 1;
    for (idx, desc) in zip(start_idx.., descriptors.iter_mut()) {
        if idx == last_idx {
            desc.set_flags(desc.flags() & !VRING_DESC_F_NEXT as u16);
        } else {
            desc.set_flags(desc.flags() | VRING_DESC_F_NEXT as u16);
            desc.set_next(idx + 1);
        }
    }
}

/// Convert an `EventFd` into a File, transferring ownership of the underlying
/// FD.
fn event_fd_into_file(event_fd: EventFd) -> File {
    // SAFETY: transfer FD ownership into File; prevent Drop on EventFd.
    unsafe {
        let raw = event_fd.as_raw_fd();
        mem::forget(event_fd);
        File::from_raw_fd(raw)
    }
}
