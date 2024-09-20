// SPDX-License-Identifier: Apache-2.0 or BSD-3-Clause

use std::io::{Read, Write};

use super::{
    command::{LunSpecificCommand, SenseFormat},
    response_data::{respond_standard_inquiry_data, SilentlyTruncate},
    target::{LogicalUnit, LunRequest},
};
use crate::scsi::{sense, CmdError, CmdError::DataIn, CmdOutput};

pub struct MissingLun;

impl LogicalUnit for MissingLun {
    fn execute_command(
        &mut self,
        data_in: &mut SilentlyTruncate<&mut dyn Write>,
        _data_out: &mut dyn Read,
        _req: LunRequest,
        cmd: LunSpecificCommand,
    ) -> Result<CmdOutput, CmdError> {
        match cmd {
            LunSpecificCommand::Inquiry(page_code) => {
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
                        respond_standard_inquiry_data(data_in).map_err(DataIn)?;
                    }
                }
                Ok(CmdOutput::ok())
            }
            LunSpecificCommand::RequestSense(format) => {
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
    }
}
