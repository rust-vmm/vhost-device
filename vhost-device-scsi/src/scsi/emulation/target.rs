// SPDX-License-Identifier: Apache-2.0 or BSD-3-Clause

use std::convert::TryFrom;
use std::io::{Read, Write};

use log::error;

use super::{
    command::{
        Cdb, Command, LunIndependentCommand, LunSpecificCommand, ParseError, ReportLunsSelectReport,
    },
    missing_lun::MissingLun,
    response_data::{respond_report_luns, SilentlyTruncate},
};
use crate::scsi::{sense, CmdError, CmdOutput, Request, Target, TaskAttr};

pub struct LunRequest {
    pub _id: u64,
    pub task_attr: TaskAttr,
    pub crn: u8,
    pub prio: u8,
    pub _allocation_length: Option<u32>,
    pub naca: bool,
}

/// A single logical unit of an emulated SCSI device.
pub trait LogicalUnit: Send + Sync {
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
        &mut self,
        data_in: &mut SilentlyTruncate<&mut dyn Write>,
        data_out: &mut dyn Read,
        parameters: LunRequest,
        command: LunSpecificCommand,
    ) -> Result<CmdOutput, CmdError>;
}

/// A SCSI target implemented by emulating a device within vhost-device-scsi.
pub struct EmulatedTarget {
    luns: Vec<Box<dyn LogicalUnit>>,
}

impl EmulatedTarget {
    pub(crate) fn new() -> Self {
        Self { luns: Vec::new() }
    }

    pub(crate) fn add_lun(&mut self, logical_unit: Box<dyn LogicalUnit>) {
        self.luns.push(logical_unit);
    }

    pub(crate) fn luns(&self) -> impl ExactSizeIterator<Item = u16> + '_ {
        // unwrap is safe: we limit LUNs at 256
        self.luns
            .iter()
            .enumerate()
            .map(|(idx, _logical_unit)| u16::try_from(idx).unwrap())
    }
}

impl Default for EmulatedTarget {
    fn default() -> Self {
        Self::new()
    }
}

impl Target for EmulatedTarget {
    fn execute_command(
        &mut self,
        lun: u16,
        data_out: &mut dyn Read,
        data_in: &mut dyn Write,
        req: Request,
    ) -> Result<CmdOutput, CmdError> {
        match Cdb::parse(req.cdb) {
            Ok(cdb) => {
                let mut data_in = SilentlyTruncate::new(
                    data_in,
                    cdb.allocation_length.map_or(usize::MAX, |x| x as usize),
                );

                match cdb.command {
                    Command::LunIndependentCommand(cmd) => match cmd {
                        LunIndependentCommand::ReportLuns(select_report) => {
                            match select_report {
                                ReportLunsSelectReport::NoWellKnown
                                | ReportLunsSelectReport::All => {
                                    respond_report_luns(&mut data_in, self.luns())
                                        .map_err(CmdError::DataIn)?;
                                }
                                ReportLunsSelectReport::WellKnownOnly
                                | ReportLunsSelectReport::Administrative
                                | ReportLunsSelectReport::TopLevel
                                | ReportLunsSelectReport::SameConglomerate => {
                                    respond_report_luns(&mut data_in, vec![].into_iter())
                                        .map_err(CmdError::DataIn)?;
                                }
                            }
                            Ok(CmdOutput::ok())
                        }
                    },
                    Command::LunSpecificCommand(cmd) => {
                        let req = LunRequest {
                            _id: req.id,
                            task_attr: req.task_attr,
                            crn: req.crn,
                            prio: req.prio,
                            _allocation_length: cdb.allocation_length,
                            naca: cdb.naca,
                        };
                        match self.luns.get_mut(lun as usize) {
                            Some(lun) => lun.execute_command(&mut data_in, data_out, req, cmd),
                            None => MissingLun.execute_command(&mut data_in, data_out, req, cmd),
                        }
                    }
                }
            }
            Err(ParseError::InvalidCommand) => {
                error!("Rejecting CDB for unknown command: {:?}", req.cdb);
                Ok(CmdOutput::check_condition(
                    sense::INVALID_COMMAND_OPERATION_CODE,
                ))
            }
            // TODO: SCSI has a provision for INVALID FIELD IN CDB to include the
            // index of the invalid field, but it's not clear if that's mandatory.
            // In any case, QEMU omits it.
            Err(ParseError::InvalidField) => {
                error!("Rejecting CDB with invalid field: {:?}", req.cdb);
                Ok(CmdOutput::check_condition(sense::INVALID_FIELD_IN_CDB))
            }
            Err(ParseError::TooSmall) => Err(CmdError::CdbTooShort),
        }
    }
}
