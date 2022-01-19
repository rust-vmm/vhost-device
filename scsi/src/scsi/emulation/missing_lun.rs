use std::io::{Read, Write};

use super::{
    command::{Cdb, Command, ReportLunsSelectReport, SenseFormat},
    response_data::{respond_report_luns, respond_standard_inquiry_data, SilentlyTruncate},
    EmulatedTarget, LogicalUnit,
};
use crate::scsi::{sense, CmdError, CmdError::DataIn, CmdOutput, Request};

pub struct MissingLun;

impl<W: Write, R: Read> LogicalUnit<W, R> for MissingLun {
    fn execute_command(
        &self,
        req: Request<'_, W, R>,
        target: &EmulatedTarget<W, R>,
    ) -> Result<CmdOutput, CmdError> {
        let parse = Cdb::parse(req.cdb);

        if let Ok(cdb) = parse {
            let mut data_in = SilentlyTruncate::new(
                req.data_in,
                cdb.allocation_length.map_or(usize::MAX, |x| x as usize),
            );

            match cdb.command {
                Command::ReportLuns(select_report) => {
                    match select_report {
                        ReportLunsSelectReport::NoWellKnown | ReportLunsSelectReport::All => {
                            respond_report_luns(&mut data_in, target.luns()).map_err(DataIn)?;
                        }
                        ReportLunsSelectReport::WellKnownOnly
                        | ReportLunsSelectReport::Administrative
                        | ReportLunsSelectReport::TopLevel
                        | ReportLunsSelectReport::SameConglomerate => {
                            respond_report_luns(&mut data_in, vec![].into_iter())
                                .map_err(DataIn)?;
                        }
                    }
                    Ok(CmdOutput::ok())
                }
                Command::Inquiry(page_code) => {
                    // peripheral qualifier 0b011: logical unit not accessible
                    // device type 0x1f: unknown/no device type
                    data_in.write_all(&[0b0110_0000 | 0x1f]).map_err(DataIn)?;
                    match page_code {
                        Some(_) => {
                            // SPC-6 7.7.2: "If the PERIPHERAL QUALIFIER field is
                            // not set to 000b, the contents of the PAGE LENGTH
                            // field and the VPD parameters are outside the
                            // scope of this standard."
                            //
                            // Returning a 0 length and no data seems sensible enough.
                            data_in.write_all(&[0]).map_err(DataIn)?;
                        }
                        None => {
                            respond_standard_inquiry_data(&mut data_in).map_err(DataIn)?;
                        }
                    }
                    Ok(CmdOutput::ok())
                }
                Command::RequestSense(format) => {
                    match format {
                        SenseFormat::Fixed => {
                            data_in
                                .write_all(&sense::LOGICAL_UNIT_NOT_SUPPORTED.to_fixed_sense())
                                .map_err(DataIn)?;
                            Ok(CmdOutput::ok())
                        }
                        SenseFormat::Descriptor => {
                            // Don't support desciptor format.
                            Ok(CmdOutput::check_condition(sense::INVALID_FIELD_IN_CDB))
                        }
                    }
                }
                _ => Ok(CmdOutput::check_condition(
                    sense::LOGICAL_UNIT_NOT_SUPPORTED,
                )),
            }
        } else {
            // invalid command - presumably we don't treat these any differently?
            Ok(CmdOutput::check_condition(
                sense::LOGICAL_UNIT_NOT_SUPPORTED,
            ))
        }
    }
}
