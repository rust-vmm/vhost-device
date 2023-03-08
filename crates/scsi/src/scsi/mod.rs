// SPDX-License-Identifier: Apache-2.0 or BSD-3-Clause

pub mod emulation;
pub mod sense;

use std::io::{self, Read, Write};

use self::sense::SenseTriple;

#[derive(PartialEq, Eq, Debug, Clone, Copy)]
pub enum TaskAttr {
    Simple,
    Ordered,
    HeadOfQueue,
    Aca,
}

#[derive(Debug, PartialEq, Eq)]
pub struct CmdOutput {
    pub status: u8,
    pub status_qualifier: u16,
    pub sense: Vec<u8>,
}

impl CmdOutput {
    pub const fn ok() -> Self {
        Self {
            status: 0,
            status_qualifier: 0,
            sense: Vec::new(),
        }
    }

    pub fn check_condition(sense: SenseTriple) -> Self {
        Self {
            status: 2,
            status_qualifier: 0,
            sense: sense.to_fixed_sense(),
        }
    }
}

pub struct Request<'a> {
    pub id: u64,
    pub cdb: &'a [u8],
    pub task_attr: TaskAttr,
    pub crn: u8,
    pub prio: u8,
}

/// An transport-level error encountered while processing a SCSI command.
///
/// This is only for transport-level errors; anything else should be handled by
/// returning a CHECK CONDITION status at the SCSI level.
#[derive(Debug)]
pub enum CmdError {
    /// The provided CDB is too short for its operation code.
    CdbTooShort,
    /// An error occurred while writing to the provided data in writer.
    DataIn(io::Error),
}

/// A transport-independent implementation of a SCSI target.
///
/// Currently, we only support emulated targets (see the `emulation` module),
/// but other implementations of this trait could implement pass-through to
/// iSCSI targets or SCSI devices on the host.
pub trait Target: Send + Sync {
    fn execute_command(
        &mut self,
        lun: u16,
        data_out: &mut dyn Read,
        data_in: &mut dyn Write,
        req: Request,
    ) -> Result<CmdOutput, CmdError>;
}
