// Copyright 2026 Red Hat Inc
//
// SPDX-License-Identifier: Apache-2.0 or BSD-3-Clause

//! Owned descriptor chain reader and writer.
//!
//! Although `virtio-queue` already provides [`virtio_queue::Reader`] and
//! [`virtio_queue::Writer`], those borrow guest memory with a lifetime
//! parameter (`Reader<'a, B>`, `Writer<'a, B>`). That lifetime prevents them
//! from being used as concrete type parameters in structs that must be stored
//! without a lifetime, such as `VirtioMediaDeviceRunner<Reader, Writer, ...>`
//! from the `virtio-media` crate.
//!
//! [`DescriptorChainReader`] and [`DescriptorChainWriter`] solve this by
//! holding the memory accessor by value (via a [`GuestMemoryLoadGuard`] clone)
//! rather than by borrow, making the resulting types lifetime-free.

use std::{
    cell::Cell,
    cmp::{max, min},
    io,
    io::{Read, Write},
    ops::Deref,
    rc::Rc,
};

use virtio_queue::{desc::split::Descriptor, DescriptorChain, DescriptorChainRwIter};
use vm_memory::{Address, Bytes, GuestAddress, GuestMemory};

/// An owned [`std::io::Write`] implementation over the writable region of a
/// virtio descriptor chain.
///
/// Writes are scattered across the chain's writable descriptors in order. The
/// total number of bytes written since construction is tracked via
/// [`max_written`](Self::max_written).
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
    /// Create a new writer positioned at the start of the writable descriptors
    /// in `chain`.
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

    /// Returns the total bytes written since construction. Pass this value to
    /// `add_used` to report the used length to the guest.
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
                .map_err(io::Error::other)?;

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

/// An owned [`std::io::Read`] implementation over the readable region of a
/// virtio descriptor chain.
///
/// Reads are gathered from the chain's readable descriptors in order.
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

            let addr = current
                .addr()
                .checked_add(u64::from(self.offset))
                .ok_or_else(|| io::Error::other("guest address overflow"))?;
            let read = self
                .chain
                .memory()
                .read(&mut buf[..(to_read as usize)], addr)
                .map_err(io::Error::other)?;

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
