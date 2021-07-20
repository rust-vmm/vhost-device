//! Helpers for virtio and virtio-scsi.

use std::{
    cell::Cell,
    cmp::{max, min},
    io,
    io::{ErrorKind, Read, Write},
    rc::Rc,
};

use log::error;
use virtio_queue::{Descriptor, DescriptorChain, DescriptorChainRwIter};
use vm_memory::{Bytes, GuestAddress, GuestAddressSpace};

/// virtio-scsi has its own format for LUNs, documented in 5.6.6.1 of virtio
/// v1.1. This represents a LUN parsed from that format.
#[derive(PartialEq, Eq, Clone, Copy, Debug)]
pub enum VirtioScsiLun {
    ReportLuns,
    TargetLun(u8, u16),
}

impl VirtioScsiLun {
    pub fn parse(bytes: [u8; 8]) -> Option<Self> {
        if bytes == [0xc1, 0x01, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0] {
            Some(Self::ReportLuns)
        } else if bytes[0] == 0x1 {
            let target = bytes[1];
            // bytes[2..3] is a normal SCSI single-level lun
            if (bytes[2] & 0b0100_0000) == 0 {
                error!(
                    "Got LUN in unsupported format: {:#2x} {:#2x}",
                    bytes[2], bytes[3]
                );
                return None;
            }
            let lun = u16::from_be_bytes([bytes[2] & 0b0011_1111, bytes[3]]);
            Some(Self::TargetLun(target, lun))
        } else {
            None
        }
    }
}

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(dead_code)]
pub enum ResponseCode {
    Ok = 0,
    Overrun = 1,
    Aborted = 2,
    BadTarget = 3,
    Reset = 4,
    TransportFailure = 5,
    TargetFailure = 6,
    NexusFailure = 7,
    Busy = 8,
    Failure = 9,
}

#[derive(Debug, PartialEq, Eq)]
pub struct Response {
    pub response: ResponseCode,
    pub status: u8,
    pub status_qualifier: u16,
    pub sense: Vec<u8>,
    pub residual: u32,
}

impl Response {
    pub fn write(&self, writer: &mut impl Write) -> Result<(), io::Error> {
        writer.write_all(&(self.sense.len() as u32).to_le_bytes())?; // sense_len
        writer.write_all(&self.residual.to_le_bytes())?; // residual
        writer.write_all(&self.status_qualifier.to_le_bytes())?; // status qual
        writer.write_all(&[self.status])?; // status
        writer.write_all(&[self.response as u8])?; // response

        writer.write_all(&self.sense[..])?;

        Ok(())
    }

    /// Shortcut to create a response for an error condition, where most fields
    /// don't matter.
    pub fn error(code: ResponseCode, residual: u32) -> Self {
        assert!(code != ResponseCode::Ok);
        Self {
            response: code,
            status: 0,
            status_qualifier: 0,
            sense: Vec::new(),
            residual,
        }
    }
}

#[derive(Debug)]
pub enum VirtioScsiError {
    // VirtioError(VirtioError),
// ScsiError(ScsiError)
}

/// A `Write` implementation that writes to the memory indicated by a virtio
/// descriptor chain.
#[derive(Clone)]
pub struct DescriptorChainWriter<M: GuestAddressSpace + Clone> {
    chain: DescriptorChain<M>,
    iter: DescriptorChainRwIter<M>,
    current: Option<Descriptor>,
    offset: u32,
    written: u32,
    max_written: Rc<Cell<u32>>,
}

impl<M: GuestAddressSpace + Clone> DescriptorChainWriter<M> {
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

    pub fn skip(&mut self, bytes: u32) {
        self.offset += bytes;
        self.add_written(bytes);
        while self
            .current
            .map_or(false, |current| self.offset >= current.len())
        {
            let current = self.current.unwrap(); // safe: loop condition
            self.offset -= current.len();
            self.current = self.iter.next();
        }
    }

    pub fn residual(&mut self) -> u32 {
        let mut ret = 0;
        while let Some(current) = self.current {
            ret += current.len() - self.offset;
            self.offset = 0;
            self.current = self.iter.next();
        }
        ret
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

impl<M: GuestAddressSpace + Clone> Write for DescriptorChainWriter<M> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        if let Some(current) = self.current {
            let left_in_descriptor = current.len() - self.offset;
            let to_write: u32 = min(left_in_descriptor as usize, buf.len()) as u32;

            let written = self
                .chain
                .memory()
                .write(
                    &buf[..(to_write as usize)],
                    GuestAddress(current.addr().0 + u64::from(self.offset)),
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
pub struct DescriptorChainReader<M: GuestAddressSpace + Clone> {
    chain: DescriptorChain<M>,
    iter: DescriptorChainRwIter<M>,
    current: Option<Descriptor>,
    offset: u32,
}

impl<M: GuestAddressSpace + Clone> DescriptorChainReader<M> {
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

impl<M: GuestAddressSpace + Clone> Read for DescriptorChainReader<M> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if let Some(current) = self.current {
            let left_in_descriptor = current.len() - self.offset;
            let to_read = min(left_in_descriptor, buf.len() as u32);

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
