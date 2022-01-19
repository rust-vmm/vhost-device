use std::{
    convert::TryFrom,
    io::{Read, Write},
};

use self::missing_lun::MissingLun;
use super::{CmdError, CmdOutput, Request, Target};

pub mod block_device;
pub mod command;
mod missing_lun;
pub mod mode_page;
mod response_data;

/// A single logical unit of an emulated SCSI device.
pub trait LogicalUnit<W: Write, R: Read>: Send + Sync {
    /// Process a SCSI command sent to this logical unit.
    ///
    /// # Return value
    /// This function returns a Result, but it should return Err only in limited
    /// circumstances: when something goes wrong at the transport level, such
    /// as writes to `req.data_in` failing or `req.cdb` being too short.
    /// Any other errors, such as invalid SCSI commands or I/O errors
    /// accessing an underlying file, should result in an Ok return value
    /// with a `CmdOutput` representing a SCSI-level error (i.e. CHECK
    /// CONDITION status, and appropriate sense data).
    fn execute_command(
        &self,
        req: Request<'_, W, R>,
        target: &EmulatedTarget<W, R>,
    ) -> Result<CmdOutput, CmdError>;
}

/// A SCSI target implemented by emulating a device within vhost-user-scsi.
pub struct EmulatedTarget<W: Write, R: Read> {
    luns: Vec<Box<dyn LogicalUnit<W, R>>>,
}

impl<W: Write, R: Read> EmulatedTarget<W, R> {
    pub fn new() -> Self {
        Self { luns: Vec::new() }
    }

    pub fn add_lun(&mut self, logical_unit: Box<dyn LogicalUnit<W, R>>) {
        self.luns.push(logical_unit);
    }

    pub fn luns(&self) -> impl Iterator<Item = u16> + ExactSizeIterator + '_ {
        // unwrap is safe: we limit LUNs at 256
        self.luns
            .iter()
            .enumerate()
            .map(|(idx, _logical_unit)| u16::try_from(idx).unwrap())
    }
}

impl<W: Write, R: Read> Target<W, R> for EmulatedTarget<W, R> {
    fn execute_command(&self, lun: u16, req: Request<'_, W, R>) -> Result<CmdOutput, CmdError> {
        let lun: &dyn LogicalUnit<W, R> = self
            .luns
            .get(lun as usize)
            .map_or(&MissingLun, |x| x.as_ref());

        lun.execute_command(req, self)
    }
}
