// SPDX-License-Identifier: Apache-2.0 or BSD-3-Clause

//! Helpers for virtio and virtio-scsi.
use std::{
    cell::Cell,
    cmp::{max, min},
    convert::TryInto,
    io,
    io::{ErrorKind, Read, Write},
    mem,
    ops::Deref,
    rc::Rc,
};

use log::error;
use virtio_bindings::virtio_scsi::virtio_scsi_cmd_req;
use virtio_queue::{Descriptor, DescriptorChain, DescriptorChainRwIter};
use vm_memory::{Bytes, GuestAddress, GuestMemory};

/// virtio-scsi has its own format for LUNs, documented in 5.6.6.1 of virtio
/// v1.1. This represents a LUN parsed from that format.
#[derive(PartialEq, Eq, Clone, Copy, Debug)]
pub enum VirtioScsiLun {
    ReportLuns,
    TargetLun(u8, u16),
}

pub const REPORT_LUNS: [u8; 8] = [0xc1, 0x01, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0];

impl VirtioScsiLun {
    pub(crate) const FLAT_SPACE_ADDRESSING_METHOD: u8 = 0b0100_0000;
    pub(crate) const ADDRESS_METHOD_PATTERN: u8 = 0b1100_0000;

    pub(crate) fn parse(bytes: [u8; 8]) -> Option<Self> {
        if bytes == REPORT_LUNS {
            Some(Self::ReportLuns)
        } else if bytes[0] == 0x1 {
            let target = bytes[1];
            // bytes[2..3] is a normal SCSI single-level lun
            if (bytes[2] & Self::ADDRESS_METHOD_PATTERN) != Self::FLAT_SPACE_ADDRESSING_METHOD {
                error!(
                    "Got LUN in unsupported format: {:#2x} {:#2x}. \
                     Only flat space addressing is supported!",
                    bytes[2], bytes[3]
                );
                return None;
            }

            let lun = u16::from_be_bytes([bytes[2] & !Self::ADDRESS_METHOD_PATTERN, bytes[3]]);
            Some(Self::TargetLun(target, lun))
        } else {
            None
        }
    }
}

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResponseCode {
    Ok = 0,
    Overrun = 1,
    BadTarget = 3,
    Failure = 9,
}

// These are the defaults given in the virtio spec; QEMU doesn't let the driver
// write to config space, so these will always be the correct values.
pub const SENSE_SIZE: usize = 96;
pub const CDB_SIZE: usize = 32;

pub struct Request {
    pub id: u64,
    pub lun: VirtioScsiLun,
    pub prio: u8,
    pub crn: u8,
    pub cdb: [u8; CDB_SIZE],
    pub task_attr: u8,
}

#[derive(Debug)]
pub enum RequestParseError {
    CouldNotReadGuestMemory(io::Error),
    FailedParsingLun([u8; 8]),
}

impl Request {
    pub fn parse(reader: &mut impl Read) -> Result<Self, RequestParseError> {
        let mut request = [0; mem::size_of::<virtio_scsi_cmd_req>()];

        reader
            .read_exact(&mut request)
            .map_err(RequestParseError::CouldNotReadGuestMemory)?;

        let lun = VirtioScsiLun::parse(request[0..8].try_into().expect("slice is of length 8"))
            .ok_or(RequestParseError::FailedParsingLun(
                request[0..8].try_into().expect("slice to be of length 8"),
            ))?;

        Ok(Self {
            id: u64::from_le_bytes(request[8..16].try_into().expect("slice is of length 8")),
            lun,
            task_attr: request[16],
            prio: request[17],
            crn: request[18],
            cdb: request[19..].try_into().expect("should fit into cdb"),
        })
    }
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

// TODO: Drop this if https://github.com/rust-vmm/vm-virtio/pull/33 found an agreement
/// A `Write` implementation that writes to the memory indicated by a virtio
/// descriptor chain.
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

    pub fn skip(&mut self, bytes: u32) {
        self.offset += bytes;
        self.add_written(bytes);
        while self
            .current
            .map_or(false, |current| self.offset >= current.len())
        {
            let current = self.current.expect("loop condition ensures existance");
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

impl<M: Deref + Clone> Write for DescriptorChainWriter<M>
where
    M::Target: GuestMemory,
{
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        if let Some(current) = self.current {
            let left_in_descriptor = current.len() - self.offset;
            let to_write: u32 = min(left_in_descriptor as usize, buf.len()) as u32;

            let written = self
                .chain
                .memory()
                .write(
                    &buf[..(to_write as usize)],
                    GuestAddress(current.addr().0.checked_add(u64::from(self.offset)).ok_or(
                        io::Error::new(ErrorKind::Other, vm_memory::Error::InvalidGuestRegion),
                    )?),
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

#[cfg(test)]
pub(crate) mod tests {
    use virtio_bindings::virtio_scsi::{virtio_scsi_cmd_req, virtio_scsi_cmd_resp};
    use virtio_queue::{mock::MockSplitQueue, Descriptor};
    use vm_memory::{ByteValued, GuestAddress, GuestMemoryMmap};

    use super::*;

    #[derive(Debug, Default, Clone, Copy)]
    #[repr(transparent)]
    pub(crate) struct VirtioScsiCmdReq(pub virtio_scsi_cmd_req);
    /// SAFETY: struct is a transparent wrapper around the request
    /// which can be read from a byte array
    unsafe impl ByteValued for VirtioScsiCmdReq {}

    #[derive(Debug, Default, Clone, Copy)]
    #[repr(transparent)]
    pub(crate) struct VirtioScsiCmdResp(pub virtio_scsi_cmd_resp);
    /// SAFETY: struct is a transparent wrapper around the response
    /// which can be read from a byte array
    unsafe impl ByteValued for VirtioScsiCmdResp {}

    pub(crate) fn report_luns_command() -> VirtioScsiCmdReq {
        VirtioScsiCmdReq(virtio_scsi_cmd_req {
            lun: REPORT_LUNS,
            tag: 0,
            task_attr: 0,
            prio: 0,
            crn: 0,
            cdb: [0; CDB_SIZE],
        })
    }

    #[test]
    fn test_parse_request() {
        let mem: GuestMemoryMmap =
            GuestMemoryMmap::from_ranges(&[(GuestAddress(0), 0x1000_0000)]).unwrap();

        // The `build_desc_chain` function will populate the `NEXT` related flags and field.
        let v = vec![
            // A device-writable request header descriptor.
            Descriptor::new(0x10_0000, 0x100, 0, 0),
        ];

        let req = report_luns_command();
        mem.write_obj(req, GuestAddress(0x10_0000))
            .expect("writing to succeed");

        let queue = MockSplitQueue::new(&mem, 16);
        let chain = queue.build_desc_chain(&v).unwrap();

        let mut chain = DescriptorChainReader::new(chain.clone());
        let req = Request::parse(&mut chain).expect("request failed to parse");
        assert_eq!(req.lun, VirtioScsiLun::ReportLuns);
    }
}
