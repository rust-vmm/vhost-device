pub mod emulation;
mod sense;

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
    const fn ok() -> Self {
        Self {
            status: 0,
            status_qualifier: 0,
            sense: Vec::new(),
        }
    }
    fn check_condition(sense: SenseTriple) -> Self {
        Self {
            status: 2,
            status_qualifier: 0,
            sense: sense.to_fixed_sense(),
        }
    }
}

pub struct Request<'a, W: Write, R: Read> {
    pub id: u64,
    pub cdb: &'a [u8],
    pub task_attr: TaskAttr,
    pub data_in: &'a mut W,
    pub data_out: &'a mut R,
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

#[allow(clippy::doc_markdown)]
/// A transport-independent implementation of a SCSI target.
///
/// Currently, we only support emulated targets (see the `emulation` module),
/// but other implementations of this trait could implement pass-through to
/// iSCSI targets or SCSI devices on the host.
pub trait Target<W: Write, R: Read>: Send + Sync {
    fn execute_command(&self, lun: u16, req: Request<'_, W, R>) -> Result<CmdOutput, CmdError>;
}
