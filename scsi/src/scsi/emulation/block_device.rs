use std::{
    convert::{TryFrom, TryInto},
    fs::File,
    io::{self, Read, Write},
    os::unix::prelude::*,
    path::Path,
};

use log::{debug, error, warn};
use CmdError::DataIn;

use super::{
    command::{
        parse_opcode, Cdb, Command, CommandType, ModePageSelection, ModeSensePageControl,
        ParseError, ParseOpcodeResult, ReportLunsSelectReport, ReportSupportedOpCodesMode,
        SenseFormat, VpdPage, OPCODES,
    },
    mode_page::ModePage,
    response_data::{respond_report_luns, respond_standard_inquiry_data},
    CmdError, CmdOutput, EmulatedTarget, LogicalUnit, Request,
};
use crate::scsi::{emulation::response_data::SilentlyTruncate, sense, TaskAttr};

pub struct BlockDevice {
    file: File,
    block_size: u32,
    write_protected: bool,
    solid_state: bool,
}

impl BlockDevice {
    pub fn new(path: &Path) -> io::Result<Self> {
        // TODO: trying 4096 logical/physical for now. May need to fall
        // back to 512 logical/4096 physical for back compat.
        Ok(Self {
            file: File::open(path)?,
            block_size: 512,
            write_protected: false,
            solid_state: false,
        })
    }

    fn read_blocks(&self, lba: u64, blocks: u64) -> io::Result<Vec<u8>> {
        // TODO: Ideally, this would be a read_vectored directly into guest
        // address space. Instead, we have an allocation and several copies.

        let mut ret = vec![0; (blocks * u64::from(self.block_size)) as usize];

        self.file
            .read_exact_at(&mut ret[..], lba * u64::from(self.block_size))?;

        Ok(ret)
    }

    pub fn size_in_blocks(&self) -> io::Result<u64> {
        let len = self.file.metadata()?.len();
        assert!(len % u64::from(self.block_size) == 0);
        Ok(len / u64::from(self.block_size))
    }

    pub const fn block_size(&self) -> u32 {
        self.block_size
    }

    pub fn set_write_protected(&mut self, wp: bool) {
        self.write_protected = wp;
    }

    pub fn set_solid_state(&mut self, solid_state: bool) {
        self.solid_state = solid_state;
    }
}

impl<W: Write, R: Read> LogicalUnit<W, R> for BlockDevice {
    // TODO: would this be more readable split into functions? I lean towards
    // thinking it just adds boilderplate, but not sure
    #[allow(clippy::too_many_lines, clippy::cognitive_complexity)]
    fn execute_command(
        &self,
        req: Request<'_, W, R>,
        target: &EmulatedTarget<W, R>,
    ) -> Result<CmdOutput, CmdError> {
        if req.crn != 0 {
            // CRN is a weird bit of the protocol we wouldn't ever expect to be used over
            // virtio-scsi; but it's allowed to set it non-zero
            warn!("Recieved non-zero CRN: {}", req.crn);
        }
        if req.task_attr != TaskAttr::Simple {
            // virtio-scsi spec allows us to treat all task attrs as SIMPLE.
            warn!("Ignoring non-simple task attr of {:?}", req.task_attr);
        }
        if req.prio != 0 {
            // My reading of SAM-6 is that priority is purely advisory, so it's fine to
            // ignore it.
            warn!("Ignoring non-zero priority of {}.", req.prio);
        }

        let cdb = match Cdb::parse(req.cdb) {
            Ok(cdb) => cdb,
            Err(ParseError::InvalidCommand) => {
                error!("Rejecting CDB for unknown command: {:?}", req.cdb);
                return Ok(CmdOutput::check_condition(
                    sense::INVALID_COMMAND_OPERATION_CODE,
                ));
            }
            // TODO: SCSI has a provision for INVALID FIELD IN CDB to include the
            // index of the invalid field, but it's not clear if that's mandatory.
            // In any case, QEMU omits it.
            Err(ParseError::InvalidField) => {
                error!("Rejecting CDB with invalid field: {:?}", req.cdb);
                return Ok(CmdOutput::check_condition(sense::INVALID_FIELD_IN_CDB));
            }
            Err(ParseError::TooSmall) => return Err(CmdError::CdbTooShort),
        };

        if cdb.naca {
            // We don't support NACA, and say as much in our INQUIRY data, so if
            // we get it that's an error.
            warn!("Driver set NACA bit, which is unsupported.");
            return Ok(CmdOutput::check_condition(sense::INVALID_FIELD_IN_CDB));
        }

        let mut data_in = SilentlyTruncate::new(
            req.data_in,
            cdb.allocation_length.map_or(usize::MAX, |x| x as usize),
        );

        debug!("Incoming command: {:?}", &cdb);

        match cdb.command {
            Command::TestUnitReady => Ok(CmdOutput::ok()),
            Command::ReportLuns(select_report) => {
                if select_report != ReportLunsSelectReport::NoWellKnown {
                    // TODO: Are any of the other modes worth supporting?
                    warn!("Rejecting unsupported REPORT LUNS mode {:?}", select_report);
                    return Ok(CmdOutput::check_condition(sense::INVALID_FIELD_IN_CDB));
                }

                respond_report_luns(&mut data_in, target.luns()).map_err(DataIn)?;

                Ok(CmdOutput::ok())
            }
            Command::ReadCapacity10 => {
                match self.size_in_blocks() {
                    Ok(size) => {
                        // READ CAPACITY (10) returns a 32-bit LBA, which may not be enough. If it
                        // isn't, we're supposed to return 0xffff_ffff and hope the driver gets the
                        // memo and uses the newer READ CAPACITY (16).

                        // n.b. this is the last block, ie (length-1), not length
                        let final_block: u32 = (size - 1).try_into().unwrap_or(0xffff_ffff);
                        let block_size: u32 = self.block_size();

                        data_in
                            .write_all(&u32::to_be_bytes(final_block))
                            .map_err(DataIn)?;
                        data_in
                            .write_all(&u32::to_be_bytes(block_size))
                            .map_err(DataIn)?;

                        Ok(CmdOutput::ok())
                    }
                    Err(e) => {
                        error!("Error getting image size: {}", e);
                        // TODO: Is this a reasonable sense code to send?
                        Ok(CmdOutput::check_condition(sense::UNRECOVERED_READ_ERROR))
                    }
                }
            }
            Command::ReadCapacity16 => {
                match self.size_in_blocks() {
                    Ok(size) => {
                        // n.b. this is the last block, ie (length-1), not length
                        let final_block: u64 = size - 1;
                        let block_size: u32 = self.block_size();

                        data_in
                            .write_all(&u64::to_be_bytes(final_block))
                            .map_err(DataIn)?;
                        data_in
                            .write_all(&u32::to_be_bytes(block_size))
                            .map_err(DataIn)?;

                        // no protection stuff; 1-to-1 logical/physical blocks
                        data_in.write_all(&[0, 0]).map_err(DataIn)?;

                        // top 2 bits: thin provisioning stuff; other 14 bits are lowest
                        // aligned LBA, which is zero
                        data_in.write_all(&[0b1100_0000, 0]).map_err(DataIn)?;

                        // reserved
                        data_in.write_all(&[0; 16]).map_err(DataIn)?;

                        Ok(CmdOutput::ok())
                    }
                    Err(e) => {
                        error!("Error getting image size: {}", e);
                        // TODO: Is this a reasonable sense code to send?
                        Ok(CmdOutput::check_condition(sense::UNRECOVERED_READ_ERROR))
                    }
                }
            }
            Command::ModeSense6 { mode_page, pc, dbd } => {
                // we use this for the pages array if we only need a single element; lifetime
                // rules mean it has to be declared here
                let single_page_array: [ModePage; 1];

                let pages = match mode_page {
                    ModePageSelection::Single(x) => {
                        single_page_array = [x];
                        &single_page_array
                    }
                    ModePageSelection::AllPageZeros => ModePage::ALL_ZERO,
                };

                let pages_len: u32 = pages.iter().map(|x| u32::from(x.page_length() + 2)).sum();
                // SPC-6r05, 7.5.6: "Logical units that support more than 256 bytes of block
                // descriptors and mode pages should implement ten-byte mode commands. The MODE
                // DATA LENGTH field in the six-byte CDB header limits the transferred data to
                // 256 bytes."
                // Unclear what exactly we're supposed to do if we have more than 256 bytes of
                // mode pages and get sent a MODE SENSE (6). In any case, we don't at the
                // moment; if we ever get that much, this unwrap() will start
                // crashing us and we can figure out what to do.
                let pages_len = u8::try_from(pages_len).unwrap();

                // mode parameter header
                data_in
                    .write_all(&[
                        pages_len + 3, // size in bytes after this one
                        0,             // medium type - 0 for SBC
                        if self.write_protected {
                            0b1001_0000 // WP, support DPOFUA
                        } else {
                            0b0001_0000 // support DPOFUA
                        },
                        0, // block desc length
                    ])
                    .map_err(DataIn)?;

                if !dbd {
                    // TODO: Block descriptors are optional, so we currently
                    // don't provide them. Does any driver
                    // actually use them?
                }

                for page in pages {
                    match pc {
                        ModeSensePageControl::Current | ModeSensePageControl::Default => {
                            page.write(&mut data_in).map_err(DataIn)?;
                        }
                        ModeSensePageControl::Changeable => {
                            // SPC-6 6.14.3: "If the logical unit does not
                            // implement changeable parameters mode pages and
                            // the device server receives a MODE SENSE command
                            // with 01b in the PC field, then the device server
                            // shall terminate the command with CHECK CONDITION
                            // status, with the sense key set to ILLEGAL
                            // REQUEST, and the additional sense code set to
                            // INVALID FIELD IN CDB."
                            return Ok(CmdOutput::check_condition(sense::INVALID_FIELD_IN_CDB));
                        }
                        ModeSensePageControl::Saved => {
                            return Ok(CmdOutput::check_condition(
                                sense::SAVING_PARAMETERS_NOT_SUPPORTED,
                            ))
                        }
                    }
                }

                Ok(CmdOutput::ok())
            }
            Command::Read10 {
                dpo,
                fua,
                lba,
                group_number: _,
                transfer_length,
            } => {
                if dpo {
                    // DPO is just a hint that the guest probably won't access
                    // this any time soon, so we can ignore it
                    debug!("Silently ignoring DPO flag");
                }
                if fua {
                    // Somewhat weirdly, SCSI supports FUA on reads. Here's the
                    // key bit: "A force unit access (FUA) bit set to one
                    // specifies that the device server shall read the logical
                    // blocks from… the medium. If the FUA bit is set to one
                    // and a volatile cache contains a more recent version of a
                    // logical block than… the medium, then, before reading the
                    // logical block, the device server shall write the logical
                    // block to… the medium."

                    // I guess the idea is that you can read something back, and
                    // be absolutely sure what you just read will persist.

                    // So for our purposes, we need to make sure whatever we
                    // return has been saved to disk. fsync()ing the whole image
                    // is a bit blunt, but does the trick.

                    if let Err(e) = self.file.sync_all() {
                        // TODO: I'm not sure how best to report this failure to the guest. For now,
                        // we don't support writes, so it's unlikely fsync() will ever error; even
                        // if it somehow does, we won't have any unflushed writes, so ignoring the
                        // error should be fine; the contents we're reading back should always match
                        // what's on disk.
                        error!("Error syncing file: {}", e);
                    }
                }

                // Ignore group number: AFAICT, it's for separating reads from different
                // workloads in performance metrics, and we don't report anything like that

                let size = match self.size_in_blocks() {
                    Ok(size) => size,
                    Err(e) => {
                        error!("Error getting image size for read: {}", e);
                        return Ok(CmdOutput::check_condition(sense::UNRECOVERED_READ_ERROR));
                    }
                };

                if u64::from(lba) + u64::from(transfer_length) > size {
                    return Ok(CmdOutput::check_condition(
                        sense::LOGICAL_BLOCK_ADDRESS_OUT_OF_RANGE,
                    ));
                }

                let read_result = self.read_blocks(u64::from(lba), u64::from(transfer_length));

                match read_result {
                    Ok(bytes) => {
                        data_in.write_all(&bytes[..]).map_err(DataIn)?;
                        Ok(CmdOutput::ok())
                    }
                    Err(e) => {
                        error!("Error reading image: {}", e);
                        Ok(CmdOutput::check_condition(sense::UNRECOVERED_READ_ERROR))
                    }
                }
            }
            Command::Inquiry(page_code) => {
                // top 3 bits 0: peripheral device code = exists and ready
                // bottom 5 bits 0: device type = block device
                data_in.write_all(&[0]).map_err(DataIn)?;

                if let Some(code) = page_code {
                    let mut out = vec![];
                    match code {
                        VpdPage::SupportedVpdPages => {
                            out.push(VpdPage::SupportedVpdPages.into());
                            out.push(VpdPage::BlockDeviceCharacteristics.into());
                            out.push(VpdPage::LogicalBlockProvisioning.into());
                        }
                        VpdPage::BlockDeviceCharacteristics => {
                            let rotation_rate: u16 = if self.solid_state {
                                1 // non-rotational
                            } else {
                                0 // not reported
                            };
                            out.extend_from_slice(&rotation_rate.to_be_bytes());
                            // nothing worth setting in the rest
                            out.extend_from_slice(&[0; 58]);
                        }
                        VpdPage::LogicalBlockProvisioning => {
                            out.push(0); // don't support threshold sets
                            out.push(0b1110_0100); // support unmapping w/ UNMAP
                                                   // and WRITE SAME (10 & 16),
                                                   // don't support anchored
                                                   // LBAs or group descriptors
                            out.push(0b0000_0010); // thin provisioned
                            out.push(0); // no threshold % support
                        }
                        _ => return Ok(CmdOutput::check_condition(sense::INVALID_FIELD_IN_CDB)),
                    }
                    data_in.write_all(&[code.into()]).map_err(DataIn)?;
                    // unwrap is fine: none of our VPD pages are over 2^16 bits long
                    data_in
                        .write_all(&u16::try_from(out.len()).unwrap().to_be_bytes())
                        .map_err(DataIn)?;
                    data_in.write_all(&out).map_err(DataIn)?;
                } else {
                    respond_standard_inquiry_data(&mut data_in).map_err(DataIn)?;
                }

                Ok(CmdOutput::ok())
            }
            Command::ReportSupportedOperationCodes { rctd, mode } => {
                // helpers for output data format
                fn one_command_supported(
                    data_in: &mut impl Write,
                    ty: CommandType,
                ) -> io::Result<()> {
                    data_in.write_all(&[0])?; // unused flags
                    data_in.write_all(&[0b0000_0011])?; // supported, don't set a bunch of flags
                    let tpl = ty.cdb_template();
                    // unwrap is safe: the length of the template is the length of the CDB, and no
                    // command we support is anywhere near that long
                    data_in.write_all(&u16::try_from(tpl.len()).unwrap().to_be_bytes())?;
                    data_in.write_all(tpl)?;
                    Ok(())
                }
                fn one_command_not_supported(data_in: &mut impl Write) -> io::Result<()> {
                    data_in.write_all(&[0])?; // unused flags
                    data_in.write_all(&[0b0000_0001])?; // not supported
                    data_in.write_all(&[0; 2])?; // cdb len
                    Ok(())
                }
                fn timeout_descriptor(data_in: &mut impl Write) -> io::Result<()> {
                    // timeout descriptor
                    data_in.write_all(&0xa_u16.to_be_bytes())?; // len
                    data_in.write_all(&[0, 0])?; // reserved, cmd specific
                    data_in.write_all(&0_u32.to_be_bytes())?;
                    data_in.write_all(&0_u32.to_be_bytes())?;
                    Ok(())
                }

                match mode {
                    ReportSupportedOpCodesMode::All => {
                        let cmd_len = if rctd { 20 } else { 8 };
                        // unwrap is safe: we're never going to have (2^32 / 20) ~= 2^27 opcodes
                        let len = u32::try_from(OPCODES.len() * cmd_len).unwrap();
                        data_in.write_all(&len.to_be_bytes()).map_err(DataIn)?;
                        for &(ty, (opcode, sa)) in OPCODES {
                            data_in.write_all(&[opcode]).map_err(DataIn)?;
                            data_in.write_all(&[0]).map_err(DataIn)?; // reserved
                            data_in
                                .write_all(&sa.unwrap_or(0).to_be_bytes())
                                .map_err(DataIn)?;
                            data_in.write_all(&[0]).map_err(DataIn)?; // reserved

                            let ctdp: u8 = if rctd { 0b10 } else { 0b00 };
                            let servactv: u8 = if sa.is_some() { 0b1 } else { 0b0 };
                            data_in.write_all(&[ctdp | servactv]).map_err(DataIn)?;

                            // unwrap is safe: cdb template len is cdb len, and those are much
                            // shorter than a u16
                            data_in
                                .write_all(
                                    &u16::try_from(ty.cdb_template().len())
                                        .unwrap()
                                        .to_be_bytes(),
                                )
                                .map_err(DataIn)?;

                            if rctd {
                                timeout_descriptor(&mut data_in).map_err(DataIn)?;
                            }
                        }
                    }
                    ReportSupportedOpCodesMode::OneCommand(opcode) => match parse_opcode(opcode) {
                        ParseOpcodeResult::Command(ty) => {
                            one_command_supported(&mut data_in, ty).map_err(DataIn)?;

                            if rctd {
                                timeout_descriptor(&mut data_in).map_err(DataIn)?;
                            }
                        }
                        ParseOpcodeResult::ServiceAction(_) => {
                            return Ok(CmdOutput::check_condition(sense::INVALID_FIELD_IN_CDB));
                        }
                        ParseOpcodeResult::Invalid => {
                            warn!("Reporting that we don't support command {:#2x}. It might be worth adding.", opcode);
                            one_command_not_supported(&mut data_in).map_err(DataIn)?;
                        }
                    },
                    ReportSupportedOpCodesMode::OneServiceAction(opcode, sa) => {
                        match parse_opcode(opcode) {
                            ParseOpcodeResult::Command(_) => {
                                return Ok(CmdOutput::check_condition(sense::INVALID_FIELD_IN_CDB))
                            }
                            ParseOpcodeResult::ServiceAction(unparsed_sa) => {
                                if let Some(ty) = unparsed_sa.parse(sa) {
                                    one_command_supported(&mut data_in, ty).map_err(DataIn)?;

                                    if rctd {
                                        timeout_descriptor(&mut data_in).map_err(DataIn)?;
                                    }
                                } else {
                                    warn!("Reporting that we don't support command {:#2x}/{:#2x}. It might be worth adding.", opcode, sa);
                                    one_command_not_supported(&mut data_in).map_err(DataIn)?;
                                }
                            }
                            ParseOpcodeResult::Invalid => {
                                // the spec isn't super clear what we're supposed to do here, but I
                                // think an invalid opcode is one for which our implementation
                                // "does not implement service actions", so we say invalid field in
                                // CDB
                                warn!("Reporting that we don't support command {:#2x}/{:#2x}. It might be worth adding.", opcode, sa);
                                return Ok(CmdOutput::check_condition(sense::INVALID_FIELD_IN_CDB));
                            }
                        }
                    }
                    ReportSupportedOpCodesMode::OneCommandOrServiceAction(opcode, sa) => {
                        match parse_opcode(opcode) {
                            ParseOpcodeResult::Command(ty) => {
                                if sa == 0 {
                                    one_command_supported(&mut data_in, ty).map_err(DataIn)?;

                                    if rctd {
                                        timeout_descriptor(&mut data_in).map_err(DataIn)?;
                                    }
                                } else {
                                    one_command_not_supported(&mut data_in).map_err(DataIn)?;
                                }
                            }
                            ParseOpcodeResult::ServiceAction(unparsed_sa) => {
                                if let Some(ty) = unparsed_sa.parse(sa) {
                                    one_command_supported(&mut data_in, ty).map_err(DataIn)?;

                                    if rctd {
                                        timeout_descriptor(&mut data_in).map_err(DataIn)?;
                                    }
                                } else {
                                    warn!("Reporting that we don't support command {:#2x}/{:#2x}. It might be worth adding.", opcode, sa);
                                    one_command_not_supported(&mut data_in).map_err(DataIn)?;
                                }
                            }
                            ParseOpcodeResult::Invalid => {
                                warn!("Reporting that we don't support command {:#2x}[/{:#2x}]. It might be worth adding.", opcode, sa);
                                one_command_not_supported(&mut data_in).map_err(DataIn)?;
                            }
                        }
                    }
                }
                Ok(CmdOutput::ok())
            }
            Command::RequestSense(format) => {
                match format {
                    SenseFormat::Fixed => {
                        data_in
                            .write_all(&sense::NO_ADDITIONAL_SENSE_INFORMATION.to_fixed_sense())
                            .map_err(DataIn)?;
                        Ok(CmdOutput::ok())
                    }
                    SenseFormat::Descriptor => {
                        // Don't support desciptor format.
                        Ok(CmdOutput::check_condition(sense::INVALID_FIELD_IN_CDB))
                    }
                }
            }
        }
    }
}
