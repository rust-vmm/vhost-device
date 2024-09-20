// SPDX-License-Identifier: Apache-2.0 or BSD-3-Clause

use std::{
    convert::{TryFrom, TryInto},
    fs::File,
    io::{self, Read, Write},
    num::{NonZeroU32, NonZeroU64, TryFromIntError},
    ops::{Add, Div, Mul, Sub},
    os::unix::prelude::*,
};

use log::{debug, error, warn};

use super::{
    command::{
        parse_opcode, CommandType, LunSpecificCommand, ModePageSelection, ModeSensePageControl,
        ParseOpcodeResult, ReportSupportedOpCodesMode, SenseFormat, VpdPage, OPCODES,
    },
    mode_page::ModePage,
    response_data::{respond_standard_inquiry_data, SilentlyTruncate},
    target::{LogicalUnit, LunRequest},
};
use crate::scsi::{sense, CmdError, CmdOutput, TaskAttr};

pub enum MediumRotationRate {
    Unreported,
    NonRotating,
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd)]
pub struct ByteOffset(u64);
impl From<u64> for ByteOffset {
    fn from(value: u64) -> Self {
        Self(value)
    }
}
impl From<ByteOffset> for u64 {
    fn from(value: ByteOffset) -> Self {
        value.0
    }
}
impl Div<BlockSize> for ByteOffset {
    type Output = BlockOffset;

    fn div(self, rhs: BlockSize) -> Self::Output {
        BlockOffset(self.0 / NonZeroU64::from(rhs.0))
    }
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd)]
pub struct BlockSize(NonZeroU32);
impl From<BlockSize> for u32 {
    fn from(value: BlockSize) -> Self {
        Self::from(value.0)
    }
}
impl TryFrom<u32> for BlockSize {
    type Error = TryFromIntError;

    fn try_from(value: u32) -> Result<Self, Self::Error> {
        Ok(Self(NonZeroU32::try_from(value)?))
    }
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd)]
pub struct BlockOffset(u64);
impl From<BlockOffset> for u64 {
    fn from(value: BlockOffset) -> Self {
        value.0
    }
}
impl From<u64> for BlockOffset {
    fn from(value: u64) -> Self {
        Self(value)
    }
}
impl Add<Self> for BlockOffset {
    type Output = Self;

    fn add(self, rhs: Self) -> Self::Output {
        Self(self.0 + rhs.0)
    }
}
impl Sub<Self> for BlockOffset {
    type Output = Self;

    fn sub(self, rhs: Self) -> Self::Output {
        Self(self.0 - rhs.0)
    }
}
impl Mul<BlockSize> for BlockOffset {
    type Output = ByteOffset;

    fn mul(self, rhs: BlockSize) -> Self::Output {
        ByteOffset(self.0 * u64::from(NonZeroU64::from(rhs.0)))
    }
}

pub trait BlockDeviceBackend: Send + Sync {
    fn read_exact_at(&mut self, buf: &mut [u8], offset: ByteOffset) -> io::Result<()>;
    fn write_exact_at(&mut self, buf: &[u8], offset: ByteOffset) -> io::Result<()>;
    fn size_in_blocks(&mut self) -> io::Result<BlockOffset>;
    fn block_size(&self) -> BlockSize;
    fn sync(&mut self) -> io::Result<()>;
}

pub struct FileBackend {
    file: File,
    block_size: BlockSize,
}

impl FileBackend {
    pub fn new(file: File) -> Self {
        Self {
            file,
            block_size: BlockSize::try_from(512).expect("512 is valid BlockSize"),
        }
    }
}

impl BlockDeviceBackend for FileBackend {
    fn read_exact_at(&mut self, buf: &mut [u8], offset: ByteOffset) -> io::Result<()> {
        self.file.read_exact_at(buf, u64::from(offset))
    }

    fn write_exact_at(&mut self, buf: &[u8], offset: ByteOffset) -> io::Result<()> {
        self.file.write_all_at(buf, u64::from(offset))
    }

    fn size_in_blocks(&mut self) -> io::Result<BlockOffset> {
        let len = ByteOffset::from(self.file.metadata()?.len());
        assert!(u64::from(len) % NonZeroU64::from(self.block_size.0) == 0);
        Ok(len / self.block_size)
    }

    fn block_size(&self) -> BlockSize {
        self.block_size
    }

    fn sync(&mut self) -> io::Result<()> {
        self.file.sync_data()
    }
}

pub struct BlockDevice<T: BlockDeviceBackend> {
    backend: T,
    write_protected: bool,
    rotation_rate: MediumRotationRate,
}

impl<T: BlockDeviceBackend> BlockDevice<T> {
    pub(crate) const fn new(backend: T) -> Self {
        Self {
            backend,
            write_protected: false,
            rotation_rate: MediumRotationRate::Unreported,
        }
    }

    fn read_blocks(&mut self, lba: BlockOffset, blocks: BlockOffset) -> io::Result<Vec<u8>> {
        // TODO: Ideally, this would be a read_vectored directly into guest
        // address space. Instead, we have an allocation and several copies.

        let mut ret = vec![
            0;
            usize::try_from(u64::from(blocks * self.backend.block_size()))
                .expect("block length in bytes should fit usize")
        ];

        self.backend
            .read_exact_at(&mut ret[..], lba * self.backend.block_size())?;

        Ok(ret)
    }

    fn write_blocks(
        &mut self,
        lba: BlockOffset,
        blocks: BlockOffset,
        reader: &mut dyn Read,
    ) -> io::Result<()> {
        // TODO: Avoid the copies here.
        let mut buf = vec![
            0;
            usize::try_from(u64::from(blocks * self.backend.block_size()))
                .expect("block length in bytes should fit usize")
        ];
        reader.read_exact(&mut buf)?;
        self.backend
            .write_exact_at(&buf, lba * self.backend.block_size())?;

        Ok(())
    }

    fn write_same_block(
        &mut self,
        lba_start: BlockOffset,
        block_count: BlockOffset,
        buf: &[u8],
    ) -> io::Result<()> {
        let block_size = self.backend.block_size();
        for lba in u64::from(lba_start)..u64::from(lba_start + block_count) {
            let lba = BlockOffset(lba);
            self.backend.write_exact_at(buf, lba * block_size)?;
        }
        Ok(())
    }

    pub fn set_write_protected(&mut self, wp: bool) {
        self.write_protected = wp;
    }

    pub fn set_solid_state(&mut self, rotation_rate: MediumRotationRate) {
        self.rotation_rate = rotation_rate;
    }
}

impl<T: BlockDeviceBackend> LogicalUnit for BlockDevice<T> {
    #[allow(clippy::cognitive_complexity)]
    fn execute_command(
        &mut self,
        data_in: &mut SilentlyTruncate<&mut dyn Write>,
        data_out: &mut dyn Read,
        req: LunRequest,
        command: LunSpecificCommand,
    ) -> Result<CmdOutput, CmdError> {
        if req.crn != 0 {
            // CRN is a weird bit of the protocol we wouldn't ever expect to be used over
            // virtio-scsi; but it's allowed to set it non-zero
            warn!("Received non-zero CRN: {}", req.crn);
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

        if req.naca {
            // We don't support NACA, and say as much in our INQUIRY data, so if
            // we get it that's an error.
            warn!("Driver set NACA bit, which is unsupported.");
            return Ok(CmdOutput::check_condition(sense::INVALID_FIELD_IN_CDB));
        }

        debug!("Incoming command: {:?}", command);

        match command {
            LunSpecificCommand::TestUnitReady => Ok(CmdOutput::ok()),
            LunSpecificCommand::ReadCapacity10 => {
                match self.backend.size_in_blocks() {
                    Ok(size) => {
                        // READ CAPACITY (10) returns a 32-bit LBA, which may not be enough. If it
                        // isn't, we're supposed to return 0xffff_ffff and hope the driver gets the
                        // memo and uses the newer READ CAPACITY (16).

                        // n.b. this is the last block, ie (length-1), not length
                        let final_block: u32 = u64::from(size - BlockOffset(1))
                            .try_into()
                            .unwrap_or(0xffff_ffff);
                        let block_size: u32 = u32::from(self.backend.block_size());

                        data_in
                            .write_all(&u32::to_be_bytes(final_block))
                            .map_err(CmdError::DataIn)?;
                        data_in
                            .write_all(&u32::to_be_bytes(block_size))
                            .map_err(CmdError::DataIn)?;

                        Ok(CmdOutput::ok())
                    }
                    Err(e) => {
                        error!("Error getting image size: {}", e);
                        // TODO: Is this a reasonable sense code to send?
                        Ok(CmdOutput::check_condition(sense::UNRECOVERED_READ_ERROR))
                    }
                }
            }
            LunSpecificCommand::ReadCapacity16 => {
                match self.backend.size_in_blocks() {
                    Ok(size) => {
                        // n.b. this is the last block, ie (length-1), not length
                        let final_block = u64::from(size - BlockOffset(1));
                        let block_size = u32::from(self.backend.block_size());

                        data_in
                            .write_all(&u64::to_be_bytes(final_block))
                            .map_err(CmdError::DataIn)?;
                        data_in
                            .write_all(&u32::to_be_bytes(block_size))
                            .map_err(CmdError::DataIn)?;

                        // no protection stuff; 1-to-1 logical/physical blocks
                        data_in.write_all(&[0, 0]).map_err(CmdError::DataIn)?;

                        // top 2 bits: thin provisioning stuff; other 14 bits are lowest
                        // aligned LBA, which is zero
                        data_in
                            .write_all(&[0b1100_0000, 0])
                            .map_err(CmdError::DataIn)?;

                        // reserved
                        data_in.write_all(&[0; 16]).map_err(CmdError::DataIn)?;

                        Ok(CmdOutput::ok())
                    }
                    Err(e) => {
                        error!("Error getting image size: {}", e);
                        // TODO: Is this a reasonable sense code to send?
                        Ok(CmdOutput::check_condition(sense::UNRECOVERED_READ_ERROR))
                    }
                }
            }
            LunSpecificCommand::ModeSense6 { mode_page, pc, dbd } => {
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
                    .map_err(CmdError::DataIn)?;

                if !dbd {
                    // TODO: Block descriptors are optional, so we currently
                    // don't provide them. Does any driver
                    // actually use them?
                }

                for page in pages {
                    match pc {
                        ModeSensePageControl::Current | ModeSensePageControl::Default => {
                            page.write(data_in).map_err(CmdError::DataIn)?;
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
            LunSpecificCommand::Read10 {
                dpo,
                fua,
                lba,
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

                    if let Err(e) = self.backend.sync() {
                        error!("Error syncing file: {}", e);
                        return Ok(CmdOutput::check_condition(sense::TARGET_FAILURE));
                    }
                }

                // Ignore group number: AFAICT, it's for separating reads from different
                // workloads in performance metrics, and we don't report anything like that

                let size = match self.backend.size_in_blocks() {
                    Ok(size) => size,
                    Err(e) => {
                        error!("Error getting image size for read: {}", e);
                        return Ok(CmdOutput::check_condition(sense::UNRECOVERED_READ_ERROR));
                    }
                };

                let lba = BlockOffset(lba.into());
                let transfer_length = BlockOffset(transfer_length.into());

                if lba + transfer_length > size {
                    return Ok(CmdOutput::check_condition(
                        sense::LOGICAL_BLOCK_ADDRESS_OUT_OF_RANGE,
                    ));
                }

                let read_result = self.read_blocks(lba, transfer_length);

                match read_result {
                    Ok(bytes) => {
                        data_in.write_all(&bytes[..]).map_err(CmdError::DataIn)?;
                        Ok(CmdOutput::ok())
                    }
                    Err(e) => {
                        error!("Error reading image: {}", e);
                        Ok(CmdOutput::check_condition(sense::UNRECOVERED_READ_ERROR))
                    }
                }
            }
            LunSpecificCommand::Write10 {
                dpo,
                fua,
                lba,
                transfer_length,
            } => {
                if dpo {
                    // DPO is just a hint that the guest probably won't access
                    // this any time soon, so we can ignore it
                    debug!("Silently ignoring DPO flag");
                }

                let size = match self.backend.size_in_blocks() {
                    Ok(size) => size,
                    Err(e) => {
                        error!("Error getting image size for read: {}", e);
                        return Ok(CmdOutput::check_condition(sense::TARGET_FAILURE));
                    }
                };

                let lba = BlockOffset(lba.into());
                let transfer_length = BlockOffset(transfer_length.into());

                if lba + transfer_length > size {
                    return Ok(CmdOutput::check_condition(
                        sense::LOGICAL_BLOCK_ADDRESS_OUT_OF_RANGE,
                    ));
                }

                let write_result = self.write_blocks(lba, transfer_length, data_out);

                if fua {
                    if let Err(e) = self.backend.sync() {
                        error!("Error syncing file: {}", e);
                        return Ok(CmdOutput::check_condition(sense::TARGET_FAILURE));
                    }
                }

                match write_result {
                    Ok(()) => Ok(CmdOutput::ok()),
                    Err(e) => {
                        error!("Error writing to block device: {}", e);
                        Ok(CmdOutput::check_condition(sense::TARGET_FAILURE))
                    }
                }
            }
            LunSpecificCommand::WriteSame16 {
                lba,
                number_of_logical_blocks,
                anchor,
            } => {
                // We do not support block provisioning
                if anchor {
                    return Ok(CmdOutput::check_condition(sense::INVALID_FIELD_IN_CDB));
                }

                // This command can be used to unmap/discard a region of blocks...
                // TODO: Do something smarter and punch holes into the backend,
                // for now we will just write A LOT of zeros in a very inefficient way.

                let size = match self.backend.size_in_blocks() {
                    Ok(size) => size,
                    Err(e) => {
                        error!("Error getting image size for read: {}", e);
                        return Ok(CmdOutput::check_condition(sense::UNRECOVERED_READ_ERROR));
                    }
                };

                let lba = BlockOffset(lba);
                let number_of_logical_blocks = BlockOffset(number_of_logical_blocks.into());

                if lba + number_of_logical_blocks > size {
                    return Ok(CmdOutput::check_condition(
                        sense::LOGICAL_BLOCK_ADDRESS_OUT_OF_RANGE,
                    ));
                }

                let mut buf = vec![
                    0;
                    usize::try_from(u32::from(self.backend.block_size()))
                        .expect("block_size should fit usize")
                ];
                let read_result = data_out.read_exact(&mut buf);
                if let Err(e) = read_result {
                    error!("Error reading from data_out: {}", e);
                    return Ok(CmdOutput::check_condition(sense::TARGET_FAILURE));
                }

                let write_result = self.write_same_block(lba, number_of_logical_blocks, &buf);

                match write_result {
                    Ok(()) => Ok(CmdOutput::ok()),
                    Err(e) => {
                        error!("Error writing to block device: {}", e);
                        Ok(CmdOutput::check_condition(sense::TARGET_FAILURE))
                    }
                }
            }
            LunSpecificCommand::Inquiry(page_code) => {
                // top 3 bits 0: peripheral device code = exists and ready
                // bottom 5 bits 0: device type = block device
                data_in.write_all(&[0]).map_err(CmdError::DataIn)?;

                if let Some(code) = page_code {
                    let mut out = vec![];
                    match code {
                        VpdPage::SupportedVpdPages => {
                            out.push(VpdPage::SupportedVpdPages.into());
                            out.push(VpdPage::BlockDeviceCharacteristics.into());
                            out.push(VpdPage::LogicalBlockProvisioning.into());
                        }
                        VpdPage::BlockDeviceCharacteristics => {
                            let rotation_rate: u16 = match self.rotation_rate {
                                MediumRotationRate::Unreported => 0,
                                MediumRotationRate::NonRotating => 1,
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

                    data_in
                        .write_all(&[code.into()])
                        .map_err(CmdError::DataIn)?;
                    data_in
                        .write_all(
                            &u16::try_from(out.len())
                                .expect("VPD page < 2^16 bits")
                                .to_be_bytes(),
                        )
                        .map_err(CmdError::DataIn)?;
                    data_in.write_all(&out).map_err(CmdError::DataIn)?;
                } else {
                    respond_standard_inquiry_data(data_in).map_err(CmdError::DataIn)?;
                }

                Ok(CmdOutput::ok())
            }
            LunSpecificCommand::ReportSupportedOperationCodes { rctd, mode } => {
                // helpers for output data format
                fn one_command_supported(
                    data_in: &mut impl Write,
                    ty: CommandType,
                ) -> io::Result<()> {
                    data_in.write_all(&[0])?; // unused flags
                    data_in.write_all(&[0b0000_0011])?; // supported, don't set a bunch of flags
                    let tpl = ty.cdb_template();
                    data_in.write_all(
                        &u16::try_from(tpl.len())
                            .expect("length of TPL to be same as CDB")
                            .to_be_bytes(),
                    )?;
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
                        let len = u32::try_from(OPCODES.len() * cmd_len)
                            .expect("less than (2^32 / 20) ~= 2^27 opcodes");
                        data_in
                            .write_all(&len.to_be_bytes())
                            .map_err(CmdError::DataIn)?;

                        for &(ty, (opcode, sa)) in OPCODES {
                            data_in.write_all(&[opcode]).map_err(CmdError::DataIn)?;
                            data_in.write_all(&[0]).map_err(CmdError::DataIn)?; // reserved
                            data_in
                                .write_all(&sa.unwrap_or(0).to_be_bytes())
                                .map_err(CmdError::DataIn)?;
                            data_in.write_all(&[0]).map_err(CmdError::DataIn)?; // reserved

                            let ctdp: u8 = if rctd { 0b10 } else { 0b00 };
                            let servactv = u8::from(sa.is_some());
                            data_in
                                .write_all(&[ctdp | servactv])
                                .map_err(CmdError::DataIn)?;

                            data_in
                                .write_all(
                                    &u16::try_from(ty.cdb_template().len())
                                        .expect("length of TPL to be same as CDB")
                                        .to_be_bytes(),
                                )
                                .map_err(CmdError::DataIn)?;

                            if rctd {
                                timeout_descriptor(data_in).map_err(CmdError::DataIn)?;
                            }
                        }
                    }
                    ReportSupportedOpCodesMode::OneCommand(opcode) => match parse_opcode(opcode) {
                        ParseOpcodeResult::Command(ty) => {
                            one_command_supported(data_in, ty).map_err(CmdError::DataIn)?;

                            if rctd {
                                timeout_descriptor(data_in).map_err(CmdError::DataIn)?;
                            }
                        }
                        ParseOpcodeResult::ServiceAction(_) => {
                            return Ok(CmdOutput::check_condition(sense::INVALID_FIELD_IN_CDB));
                        }
                        ParseOpcodeResult::Invalid => {
                            warn!("Reporting that we don't support command {:#2x}. It might be worth adding.", opcode);
                            one_command_not_supported(data_in).map_err(CmdError::DataIn)?;
                        }
                    },
                    ReportSupportedOpCodesMode::OneServiceAction(opcode, sa) => {
                        match parse_opcode(opcode) {
                            ParseOpcodeResult::Command(_) => {
                                return Ok(CmdOutput::check_condition(sense::INVALID_FIELD_IN_CDB))
                            }
                            ParseOpcodeResult::ServiceAction(unparsed_sa) => {
                                if let Some(ty) = unparsed_sa.parse(sa) {
                                    one_command_supported(data_in, ty).map_err(CmdError::DataIn)?;

                                    if rctd {
                                        timeout_descriptor(data_in).map_err(CmdError::DataIn)?;
                                    }
                                } else {
                                    warn!("Reporting that we don't support command {:#2x}/{:#2x}. It might be worth adding.", opcode, sa);
                                    one_command_not_supported(data_in).map_err(CmdError::DataIn)?;
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
                                    one_command_supported(data_in, ty).map_err(CmdError::DataIn)?;

                                    if rctd {
                                        timeout_descriptor(data_in).map_err(CmdError::DataIn)?;
                                    }
                                } else {
                                    one_command_not_supported(data_in).map_err(CmdError::DataIn)?;
                                }
                            }
                            ParseOpcodeResult::ServiceAction(unparsed_sa) => {
                                if let Some(ty) = unparsed_sa.parse(sa) {
                                    one_command_supported(data_in, ty).map_err(CmdError::DataIn)?;

                                    if rctd {
                                        timeout_descriptor(data_in).map_err(CmdError::DataIn)?;
                                    }
                                } else {
                                    warn!("Reporting that we don't support command {:#2x}/{:#2x}. It might be worth adding.", opcode, sa);
                                    one_command_not_supported(data_in).map_err(CmdError::DataIn)?;
                                }
                            }
                            ParseOpcodeResult::Invalid => {
                                warn!("Reporting that we don't support command {:#2x}[/{:#2x}]. It might be worth adding.", opcode, sa);
                                one_command_not_supported(data_in).map_err(CmdError::DataIn)?;
                            }
                        }
                    }
                }
                Ok(CmdOutput::ok())
            }
            LunSpecificCommand::RequestSense(format) => {
                match format {
                    SenseFormat::Fixed => {
                        data_in
                            .write_all(&sense::NO_ADDITIONAL_SENSE_INFORMATION.to_fixed_sense())
                            .map_err(CmdError::DataIn)?;
                        Ok(CmdOutput::ok())
                    }
                    SenseFormat::Descriptor => {
                        // Don't support desciptor format.
                        Ok(CmdOutput::check_condition(sense::INVALID_FIELD_IN_CDB))
                    }
                }
            }
            LunSpecificCommand::SynchronizeCache10 => {
                // While SCSI allows just syncing a range, we just sync the entire file
                match self.backend.sync() {
                    Ok(()) => Ok(CmdOutput::ok()),
                    Err(e) => {
                        error!("Error syncing block device: {}", e);
                        Ok(CmdOutput::check_condition(sense::TARGET_FAILURE))
                    }
                }
            }
        }
    }
}
