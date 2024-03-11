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
