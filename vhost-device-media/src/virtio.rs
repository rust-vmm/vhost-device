// Copyright 2026 Red Hat Inc
//
// SPDX-License-Identifier: Apache-2.0 or BSD-3-Clause

use std::{
    cell::Cell,
    cmp::{max, min},
    io,
    io::{ErrorKind, Read, Write},
    ops::Deref,
    rc::Rc,
};

use virtio_queue::{desc::split::Descriptor, DescriptorChain, DescriptorChainRwIter};
use vm_memory::{Bytes, GuestAddress, GuestMemory};

#[derive(Clone)]
pub struct DescriptorChainWriter<M: Deref>
where
    M::Target: GuestMemory,
{
    chain: DescriptorChain<M>,
    iter: DescriptorChainRwIter<M>,
    current: Option<Descriptor>,
    offset: u32,
    written: u32,
    max_written: Rc<Cell<u32>>,
}

impl<M: Deref + Clone> DescriptorChainWriter<M>
where
    M::Target: GuestMemory,
{
    pub fn new(chain: DescriptorChain<M>) -> Self {
        let mut iter = chain.clone().writable();
        let current = iter.next();
        Self {
            chain,
            iter,
            current,
            offset: 0,
            written: 0,
            max_written: Rc::new(Cell::new(0)),
        }
    }

    fn add_written(&mut self, written: u32) {
        self.written += written;
        self.max_written
            .set(max(self.max_written.get(), self.written));
    }

    pub fn max_written(&self) -> u32 {
        self.max_written.get()
    }
}

impl<M: Deref + Clone> Write for DescriptorChainWriter<M>
where
    M::Target: GuestMemory,
{
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        if let Some(current) = self.current {
            let left_in_descriptor: u32 = current.len() - self.offset;
            let to_write: u32 = min(left_in_descriptor as usize, buf.len()) as u32;

            let written = self
                .chain
                .memory()
                .write(
                    &buf[..(to_write as usize)],
                    GuestAddress(
                        current
                            .addr()
                            .0
                            .checked_add(u64::from(self.offset))
                            .ok_or(io::Error::other("Guest address overflow"))?,
                    ),
                )
                .map_err(|e| io::Error::new(ErrorKind::Other, e))?;

            self.offset += written as u32;

            if self.offset == current.len() {
                self.current = self.iter.next();
                self.offset = 0;
            }

            self.add_written(written as u32);

            Ok(written)
        } else {
            Ok(0)
        }
    }

    fn flush(&mut self) -> std::io::Result<()> {
        // no-op: we're writing directly to guest memory
        Ok(())
    }
}

/// A `Read` implementation that reads from the memory indicated by a virtio
/// descriptor chain.
pub struct DescriptorChainReader<M: Deref>
where
    M::Target: GuestMemory,
{
    chain: DescriptorChain<M>,
    iter: DescriptorChainRwIter<M>,
    current: Option<Descriptor>,
    offset: u32,
}

impl<M: Deref + Clone> DescriptorChainReader<M>
where
    M::Target: GuestMemory,
{
    pub fn new(chain: DescriptorChain<M>) -> Self {
        let mut iter = chain.clone().readable();
        let current = iter.next();

        Self {
            chain,
            iter,
            current,
            offset: 0,
        }
    }
}

impl<M: Deref> Read for DescriptorChainReader<M>
where
    M::Target: GuestMemory,
{
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if let Some(current) = self.current {
            let left_in_descriptor = current.len() - self.offset;
            let to_read: u32 = min(left_in_descriptor, buf.len() as u32);

            let read = self
                .chain
                .memory()
                .read(
                    &mut buf[..(to_read as usize)],
                    GuestAddress(current.addr().0 + u64::from(self.offset)),
                )
                .map_err(|e| io::Error::new(ErrorKind::Other, e))?;

            self.offset += read as u32;

            if self.offset == current.len() {
                self.current = self.iter.next();
                self.offset = 0;
            }

            Ok(read)
        } else {
            Ok(0)
        }
    }
}

#[cfg(test)]
mod tests {
    use rstest::*;
    use virtio_bindings::bindings::virtio_ring::VRING_DESC_F_WRITE;
    use virtio_queue::{desc::RawDescriptor, mock::MockSplitQueue};
    use vm_memory::{Bytes, GuestAddress, GuestMemoryMmap};

    use super::*;

    #[rstest]
    #[case::small_payload(&[0xAAu8, 0xBB], 0x1000)]
    #[case::medium_payload(&[0xAAu8, 0xBB, 0xCC, 0xDD], 0x1000)]
    #[case::large_payload(&[0x11u8, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88], 0x1000)]
    #[case::single_byte(&[0xFFu8], 0x2000)]
    #[case::all_zeros(&[0u8; 16], 0x3000)]
    fn test_descriptor_chain_reader_reads_payload(#[case] payload: &[u8], #[case] addr: u64) {
        let mem: GuestMemoryMmap =
            GuestMemoryMmap::from_ranges(&[(GuestAddress(0), 0x10000)]).unwrap();
        mem.write(payload, GuestAddress(addr)).unwrap();

        // Readable descriptor.
        let v = vec![RawDescriptor::from(Descriptor::new(
            addr,
            payload.len() as u32,
            0,
            0,
        ))];
        let queue = MockSplitQueue::new(&mem, 16);
        let chain = queue.build_desc_chain(&v).unwrap();

        let mut reader = DescriptorChainReader::new(chain);
        let mut out = vec![0u8; payload.len()];
        let n = reader.read(&mut out).unwrap();
        assert_eq!(n, payload.len());
        assert_eq!(out, payload);
    }

    #[rstest]
    #[case(&[1, 2, 3, 4], 4, 0x2000)]
    #[case(&[0xFF, 0xFE, 0xFD], 3, 0x2100)]
    #[case(&[0u8; 8], 8, 0x2200)]
    #[case(&[1], 1, 0x2300)]
    fn test_descriptor_chain_writer_writes_payload_and_tracks_max_written(
        #[case] data: &[u8],
        #[case] expected_written: usize,
        #[case] addr: u64,
    ) {
        let mem: GuestMemoryMmap =
            GuestMemoryMmap::from_ranges(&[(GuestAddress(0), 0x10000)]).unwrap();

        // Writable descriptor with enough space.
        let v = vec![RawDescriptor::from(Descriptor::new(
            addr,
            (data.len() + 4) as u32, // Extra space to ensure we don't hit the limit
            VRING_DESC_F_WRITE as u16,
            0,
        ))];
        let queue = MockSplitQueue::new(&mem, 16);
        let chain = queue.build_desc_chain(&v).unwrap();

        let mut writer = DescriptorChainWriter::new(chain);
        let n = writer.write(data).unwrap();
        assert_eq!(n, expected_written);
        assert_eq!(writer.max_written(), expected_written as u32);

        let mut out = vec![0u8; data.len()];
        mem.read(&mut out, GuestAddress(addr)).unwrap();
        assert_eq!(out, data);
    }

    #[rstest]
    #[case(&[9, 9, 9], 0x3000)]
    #[case(&[1, 2, 3, 4, 5], 0x4000)]
    #[case(&[0xFF], 0x5000)]
    fn test_writer_returns_zero_without_writable_descriptor(
        #[case] data: &[u8],
        #[case] addr: u64,
    ) {
        let mem: GuestMemoryMmap =
            GuestMemoryMmap::from_ranges(&[(GuestAddress(0), 0x10000)]).unwrap();

        // Readable only descriptor; writable iterator should be empty.
        let v = vec![RawDescriptor::from(Descriptor::new(addr, 8, 0, 0))];
        let queue = MockSplitQueue::new(&mem, 16);
        let chain = queue.build_desc_chain(&v).unwrap();

        let mut writer = DescriptorChainWriter::new(chain);
        let n = writer.write(data).unwrap();
        assert_eq!(n, 0);
        assert_eq!(writer.max_written(), 0);
    }

    #[test]
    fn test_writer_flush_is_noop() {
        let mem: GuestMemoryMmap =
            GuestMemoryMmap::from_ranges(&[(GuestAddress(0), 0x10000)]).unwrap();

        let v = vec![RawDescriptor::from(Descriptor::new(
            0x1000,
            64,
            VRING_DESC_F_WRITE as u16,
            0,
        ))];
        let queue = MockSplitQueue::new(&mem, 16);
        let chain = queue.build_desc_chain(&v).unwrap();

        let mut writer = DescriptorChainWriter::new(chain);
        assert!(writer.flush().is_ok());
    }

    #[test]
    fn test_reader_exhausted_returns_zero() {
        let mem: GuestMemoryMmap =
            GuestMemoryMmap::from_ranges(&[(GuestAddress(0), 0x10000)]).unwrap();
        mem.write(&[1, 2, 3, 4], GuestAddress(0x1000)).unwrap();

        let v = vec![RawDescriptor::from(Descriptor::new(0x1000, 4, 0, 0))];
        let queue = MockSplitQueue::new(&mem, 16);
        let chain = queue.build_desc_chain(&v).unwrap();

        let mut reader = DescriptorChainReader::new(chain);
        let mut buf = [0u8; 4];
        assert_eq!(reader.read(&mut buf).unwrap(), 4);
        assert_eq!(reader.read(&mut buf).unwrap(), 0);
    }

    #[rstest]
    #[case(1, 1)]
    #[case(4, 4)]
    #[case(8, 8)]
    #[case(16, 16)]
    #[case(32, 32)]
    fn test_writer_partial_writes(#[case] descriptor_size: u32, #[case] write_size: usize) {
        let mem: GuestMemoryMmap =
            GuestMemoryMmap::from_ranges(&[(GuestAddress(0), 0x10000)]).unwrap();

        // Writable descriptor with specific size.
        let v = vec![RawDescriptor::from(Descriptor::new(
            0x6000,
            descriptor_size,
            VRING_DESC_F_WRITE as u16,
            0,
        ))];
        let queue = MockSplitQueue::new(&mem, 16);
        let chain = queue.build_desc_chain(&v).unwrap();

        let mut writer = DescriptorChainWriter::new(chain);
        let data = vec![0xAAu8; write_size];
        let expected_written = std::cmp::min(write_size, descriptor_size as usize);
        let n = writer.write(&data).unwrap();
        assert_eq!(n, expected_written);
        assert_eq!(writer.max_written(), expected_written as u32);
    }
}
