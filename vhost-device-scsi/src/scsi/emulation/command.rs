// SPDX-License-Identifier: Apache-2.0 or BSD-3-Clause

//! Data structures and parsing code for SCSI commands. A rough overview:
//! We need to deal with opcodes in two places: in parsing commands themselves,
//! and in implementing REPORT SUPPORTED OPERATION CODES. Therefore, we parse
//! commands in two steps. First, we parse the opcode (and sometimes service
//! action) into a `CommandType` (a C-style enum containing just the commands,
//! not their parameters), then using that, we parse the rest of the CDB and
//! obtain a `Cdb`, which consists of a `Command`, an enum representing a
//! command and its parameters, along with some fields shared across many or all
//! commands.

use std::convert::{TryFrom, TryInto};

use log::warn;
use num_enum::TryFromPrimitive;

use crate::scsi::emulation::mode_page::ModePage;

/// One of the modes supported by SCSI's REPORT LUNS command.
#[derive(PartialEq, Eq, TryFromPrimitive, Debug, Copy, Clone)]
#[repr(u8)]
pub enum ReportLunsSelectReport {
    NoWellKnown = 0x0,
    WellKnownOnly = 0x1,
    All = 0x2,
    Administrative = 0x10,
    TopLevel = 0x11,
    SameConglomerate = 0x12,
}

/// A type of "vital product data" page returned by SCSI's INQUIRY command.
#[derive(PartialEq, Eq, Debug, Copy, Clone)]
pub enum VpdPage {
    Ascii(u8),
    Ata,                        // *
    BlockDeviceCharacteristics, // *
    BlockDeviceCharacteristicsExt,
    BlockLimits, // *
    BlockLimitsExt,
    CfaProfile,
    DeviceConstituents,
    DeviceIdentification, // *
    ExtendedInquiry,
    FormatPresets,
    LogicalBlockProvisioning, // *
    ManagementNetworkAddresses,
    ModePagePolicy,
    PowerCondition,
    PowerConsumption,
    PortocolSpecificLogicalUnit,
    ProtocolSpecificPort,
    Referrals,
    ScsiFeatureSets,
    ScsiPorts,
    SoftwareInterfaceIdentification,
    SupportedVpdPages, // *
    ThirdPartyCopy,
    UnitSerialNumber,                // *
    ZonedBlockDeviceCharacteristics, // *
}
// starred ones are ones Linux will use if available

#[derive(PartialEq, Eq, TryFromPrimitive, Debug, Copy, Clone)]
#[repr(u8)]
pub enum ModeSensePageControl {
    Current = 0b00,
    Changeable = 0b01,
    Default = 0b10,
    Saved = 0b11,
}

impl TryFrom<u8> for VpdPage {
    type Error = ();

    fn try_from(val: u8) -> Result<Self, ()> {
        match val {
            0x00 => Ok(Self::SupportedVpdPages),
            0x1..=0x7f => Ok(Self::Ascii(val)),
            0x80 => Ok(Self::UnitSerialNumber),
            0x83 => Ok(Self::DeviceIdentification),
            0x84 => Ok(Self::SoftwareInterfaceIdentification),
            0x85 => Ok(Self::ManagementNetworkAddresses),
            0x86 => Ok(Self::ExtendedInquiry),
            0x87 => Ok(Self::ModePagePolicy),
            0x88 => Ok(Self::ScsiPorts),
            0x89 => Ok(Self::Ata),
            0x8a => Ok(Self::PowerCondition),
            0x8b => Ok(Self::DeviceConstituents),
            0x8c => Ok(Self::CfaProfile),
            0x8d => Ok(Self::PowerConsumption),
            0x8f => Ok(Self::ThirdPartyCopy),
            0x90 => Ok(Self::PortocolSpecificLogicalUnit),
            0x91 => Ok(Self::ProtocolSpecificPort),
            0x92 => Ok(Self::ScsiFeatureSets),
            0xb0 => Ok(Self::BlockLimits),
            0xb1 => Ok(Self::BlockDeviceCharacteristics),
            0xb2 => Ok(Self::LogicalBlockProvisioning),
            0xb3 => Ok(Self::Referrals),
            0xb5 => Ok(Self::BlockDeviceCharacteristicsExt),
            0xb6 => Ok(Self::ZonedBlockDeviceCharacteristics),
            0xb7 => Ok(Self::BlockLimitsExt),
            0xb8 => Ok(Self::FormatPresets),
            _ => Err(()),
        }
    }
}

impl From<VpdPage> for u8 {
    fn from(pc: VpdPage) -> Self {
        match pc {
            VpdPage::Ascii(val) => val,
            VpdPage::Ata => 0x89,
            VpdPage::BlockDeviceCharacteristics => 0xb1,
            VpdPage::BlockDeviceCharacteristicsExt => 0xb5,
            VpdPage::BlockLimits => 0xb0,
            VpdPage::BlockLimitsExt => 0xb7,
            VpdPage::CfaProfile => 0x8c,
            VpdPage::DeviceConstituents => 0x8b,
            VpdPage::DeviceIdentification => 0x83,
            VpdPage::ExtendedInquiry => 0x86,
            VpdPage::FormatPresets => 0xb8,
            VpdPage::LogicalBlockProvisioning => 0xb2,
            VpdPage::ManagementNetworkAddresses => 0x85,
            VpdPage::ModePagePolicy => 0x87,
            VpdPage::PowerCondition => 0x8a,
            VpdPage::PowerConsumption => 0x8d,
            VpdPage::PortocolSpecificLogicalUnit => 0x90,
            VpdPage::ProtocolSpecificPort => 0x91,
            VpdPage::Referrals => 0xb3,
            VpdPage::ScsiFeatureSets => 0x92,
            VpdPage::ScsiPorts => 0x88,
            VpdPage::SoftwareInterfaceIdentification => 0x84,
            VpdPage::SupportedVpdPages => 0x00,
            VpdPage::ThirdPartyCopy => 0x8f,
            VpdPage::UnitSerialNumber => 0x80,
            VpdPage::ZonedBlockDeviceCharacteristics => 0xb6,
        }
    }
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum SenseFormat {
    Fixed,
    Descriptor,
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum ModePageSelection {
    AllPageZeros,
    Single(ModePage),
}

#[derive(Debug)]
pub enum LunIndependentCommand {
    ReportLuns(ReportLunsSelectReport),
}

#[derive(Debug)]
pub enum LunSpecificCommand {
    Inquiry(Option<VpdPage>),
    ModeSense6 {
        pc: ModeSensePageControl,
        mode_page: ModePageSelection,
        /// Disable block descriptors
        dbd: bool,
    },
    Read10 {
        /// Disable page out (i.e. hint that this page won't be accessed again
        /// soon, so we shouldn't bother caching it)
        dpo: bool,
        /// Force unit access (i.e. bypass cache)
        fua: bool,
        lba: u32,
        transfer_length: u16,
    },
    Write10 {
        /// Disable page out (i.e. hint that this page won't be accessed again
        /// soon, so we shouldn't bother caching it)
        dpo: bool,
        /// Force unit access (i.e. bypass cache)
        fua: bool,
        lba: u32,
        transfer_length: u16,
    },
    WriteSame16 {
        lba: u64,
        number_of_logical_blocks: u32,
        anchor: bool,
    },
    ReadCapacity10,
    ReadCapacity16,
    ReportSupportedOperationCodes {
        /// SCSI RCTD bit: whether we should include timeout descriptors.
        rctd: bool,
        mode: ReportSupportedOpCodesMode,
    },
    RequestSense(SenseFormat),
    TestUnitReady,
    SynchronizeCache10,
}

#[derive(Debug)]
pub enum Command {
    LunIndependentCommand(LunIndependentCommand),
    LunSpecificCommand(LunSpecificCommand),
}

#[derive(Clone, Copy, Debug)]
pub enum CommandType {
    Inquiry,
    ModeSense6,
    Read10,
    ReadCapacity10,
    ReadCapacity16,
    ReportLuns,
    ReportSupportedOperationCodes,
    RequestSense,
    TestUnitReady,
    Write10,
    WriteSame16,
    SynchronizeCache10,
}

pub const OPCODES: &[(CommandType, (u8, Option<u16>))] = &[
    (CommandType::TestUnitReady, (0x0, None)),
    (CommandType::RequestSense, (0x3, None)),
    (CommandType::Inquiry, (0x12, None)),
    (CommandType::ModeSense6, (0x1a, None)),
    (CommandType::ReadCapacity10, (0x25, None)),
    (CommandType::Read10, (0x28, None)),
    (CommandType::Write10, (0x2a, None)),
    (CommandType::SynchronizeCache10, (0x35, None)),
    (CommandType::WriteSame16, (0x93, None)),
    (CommandType::ReadCapacity16, (0x9e, Some(0x10))),
    (CommandType::ReportLuns, (0xa0, None)),
    (
        CommandType::ReportSupportedOperationCodes,
        (0xa3, Some(0xc)),
    ),
];

#[derive(Debug, Clone, Copy)]
pub struct UnparsedServiceAction(u8);
impl UnparsedServiceAction {
    pub fn parse(self, service_action: u16) -> Option<CommandType> {
        OPCODES
            .iter()
            .find(|(_, opcode)| *opcode == (self.0, Some(service_action)))
            .map(|&(ty, _)| ty)
    }
}

/// See `parse_opcode`
#[derive(Debug, Clone, Copy)]
pub enum ParseOpcodeResult {
    /// The opcode represents a single command.
    Command(CommandType),
    /// The opcode requires a service action.
    ServiceAction(UnparsedServiceAction),
    /// The opcode is invalid.
    Invalid,
}

/// Determine the command that corresponds to a SCSI opcode.
///
/// This is a little weird. Most SCSI commands are just identified by the
/// opcode - the first byte of the CDB - but some opcodes require a second
/// byte, called the service action. Generally, each distinct service action
/// value is treated as a first-class command. But there's some weirdness
/// around parsing, especially with invalid commands: sometimes, we're
/// expected to behave differently for a valid opcode with an invalid
/// service action vs an invalid opcode.
///
/// To allow for this, we have a two-step parsing API. First, a caller
/// calls `parse_opcode` with the first byte of the CDB. This could return
/// three things:
/// - `Command`: the opcode corresponded to a single-byte command; we're done.
/// - `Invalid`: the opcode isn't recognized at all; we're done.
/// - `ServiceAction`: the opcode is the first byte of a service action; the
///   caller needs to call .parse() on the `UnparsedServiceAction` we returned
///   with the service action byte.
pub fn parse_opcode(opcode: u8) -> ParseOpcodeResult {
    let found = OPCODES.iter().find(|(_, (x, _))| *x == opcode);
    match found {
        Some(&(ty, (_, None))) => ParseOpcodeResult::Command(ty),
        Some((_, (_, Some(_)))) => {
            // we found some service action that uses this opcode; so this is a
            // service action opcode, and we need the service action
            ParseOpcodeResult::ServiceAction(UnparsedServiceAction(opcode))
        }
        None => ParseOpcodeResult::Invalid,
    }
}

impl CommandType {
    fn from_cdb(cdb: &[u8]) -> Result<Self, ParseError> {
        // TODO: Variable-length CDBs put the service action in a different
        // place. This'll need to change if we ever support those. IIRC, Linux
        // doesn't ever use them, so it may never be relevant.
        match parse_opcode(cdb[0]) {
            ParseOpcodeResult::Command(ty) => Ok(ty),
            ParseOpcodeResult::ServiceAction(sa) => sa
                .parse(u16::from(cdb[1] & 0b0001_1111))
                .ok_or(ParseError::InvalidField),
            ParseOpcodeResult::Invalid => Err(ParseError::InvalidCommand),
        }
    }

    /// Return the SCSI "CDB usage data" (see SPC-6 6.34.3) for this command
    /// type.
    ///
    /// Basically, this consists of a structure the size of the CDB for the
    /// command, starting with the opcode and service action (if any), then
    /// proceeding to a bitmap of fields we recognize.
    pub const fn cdb_template(self) -> &'static [u8] {
        match self {
            Self::TestUnitReady => &[
                0x0,
                0b0000_0000,
                0b0000_0000,
                0b0000_0000,
                0b0000_0000,
                0b0000_0100,
            ],
            Self::RequestSense => &[
                0x3,
                0b0000_0001,
                0b0000_0000,
                0b0000_0000,
                0b1111_1111,
                0b0000_0100,
            ],
            Self::ReportLuns => &[
                0xa0,
                0b0000_0000,
                0b1111_1111,
                0b0000_0000,
                0b0000_0000,
                0b0000_0000,
                0b1111_1111,
                0b1111_1111,
                0b1111_1111,
                0b1111_1111,
                0b0000_0000,
                0b0000_0100,
            ],
            Self::ReadCapacity10 => &[
                0x25,
                0b0000_0000,
                0b0000_0000,
                0b0000_0000,
                0b0000_0000,
                0b0000_0000,
                0b0000_0000,
                0b0000_0000,
                0b0000_0000,
                0b0000_0100,
            ],
            Self::ReadCapacity16 => &[
                0x9e,
                0x10,
                0b0000_0000,
                0b0000_0000,
                0b0000_0000,
                0b0000_0000,
                0b0000_0000,
                0b0000_0000,
                0b0000_0000,
                0b0000_0000,
                0b1111_1111,
                0b1111_1111,
                0b1111_1111,
                0b1111_1111,
                0b0000_0000,
                0b0000_0100,
            ],
            Self::ModeSense6 => &[
                0x1a,
                0b0000_1000,
                0b1111_1111,
                0b1111_1111,
                0b1111_1111,
                0b0000_0100,
            ],
            Self::Read10 => &[
                0x28,
                0b1111_1100,
                0b1111_1111,
                0b1111_1111,
                0b1111_1111,
                0b1111_1111,
                0b0011_1111,
                0b1111_1111,
                0b1111_1111,
                0b0000_0100,
            ],
            Self::Write10 => &[
                0x2A,
                0b1111_1100,
                0b1111_1111,
                0b1111_1111,
                0b1111_1111,
                0b1111_1111,
                0b0011_1111,
                0b1111_1111,
                0b1111_1111,
                0b0000_0100,
            ],
            Self::WriteSame16 => &[
                0x93,
                0b1111_1001,
                0b1111_1111,
                0b1111_1111,
                0b1111_1111,
                0b1111_1111,
                0b1111_1111,
                0b1111_1111,
                0b1111_1111,
                0b1111_1111,
                0b1111_1111,
                0b1111_1111,
                0b1111_1111,
                0b1111_1111,
                0b0011_1111,
                0b0000_0100,
            ],
            Self::Inquiry => &[
                0x12,
                0b0000_0001,
                0b1111_1111,
                0b1111_1111,
                0b1111_1111,
                0b0000_0100,
            ],
            Self::ReportSupportedOperationCodes => &[
                0xa3,
                0xc,
                0b1000_0111,
                0b1111_1111,
                0b1111_1111,
                0b1111_1111,
                0b1111_1111,
                0b1111_1111,
                0b1111_1111,
                0b1111_1111,
                0b0000_0000,
                0b0000_0100,
            ],
            Self::SynchronizeCache10 => &[
                0x53,
                0b0000_0010,
                0b1111_1111,
                0b1111_1111,
                0b1111_1111,
                0b1111_1111,
                0b0011_1111,
                0b1111_1111,
                0b1111_1111,
                0b0000_0100,
            ],
        }
    }
}

#[derive(Debug)]
pub struct Cdb {
    pub command: Command,
    pub allocation_length: Option<u32>,
    pub naca: bool,
}

#[derive(Debug, PartialEq, Eq, Copy, Clone)]
pub enum ParseError {
    /// The opcode (specifically the first byte of the CDB) is unknown, i.e. we
    /// should respond with INVALID COMMAND OPERATION CODE
    InvalidCommand,
    /// Another field of the CDB (including the service action, if any) is
    /// invalid, i.e. we should respond with INVALID FIELD IN CDB.
    InvalidField,
    /// The CDB has fewer bytes than necessary for its opcode.
    TooSmall,
}

#[derive(Debug, PartialEq, Eq, Copy, Clone)]
pub enum ReportSupportedOpCodesMode {
    All,
    OneCommand(u8),
    OneServiceAction(u8, u16),
    OneCommandOrServiceAction(u8, u16),
}

impl Cdb {
    // TODO: do we want to ensure reserved fields are 0? SCSI allows, but
    // doesn't require, us to do so.
    pub(crate) fn parse(cdb: &[u8]) -> Result<Self, ParseError> {
        let ct = CommandType::from_cdb(cdb)?;
        if cdb.len() < ct.cdb_template().len() {
            return Err(ParseError::TooSmall);
        }
        // Shrink the cdb down to its size, so accidentally accessing fields past the
        // length panics
        let cdb = &cdb[..ct.cdb_template().len()];

        // unwraps below are safe: they're just calling TryFrom to convert from slices
        // to fixed-size arrays; in each case, we're using constant indexes and we
        // verified above that they're in bounds, so none of them can panic at runtime

        match ct {
            CommandType::Inquiry => {
                // INQUIRY
                let evpd = match cdb[1] {
                    0 => false,
                    1 => true,
                    // obselete or reserved bits set
                    _ => return Err(ParseError::InvalidField),
                };
                let page_code_raw = cdb[2];
                let page_code = match (evpd, page_code_raw) {
                    (false, 0) => None,
                    (true, pc) => Some(pc.try_into().map_err(|_| ParseError::InvalidField)?),
                    (false, _) => return Err(ParseError::InvalidField),
                };
                Ok(Self {
                    command: Command::LunSpecificCommand(LunSpecificCommand::Inquiry(page_code)),
                    allocation_length: Some(u32::from(u16::from_be_bytes(
                        cdb[3..5].try_into().unwrap(),
                    ))),
                    naca: (cdb[5] & 0b0000_0100) != 0,
                })
            }
            CommandType::ModeSense6 => {
                let dbd = match cdb[1] {
                    0b0000_1000 => true,
                    0b0000_0000 => false,
                    _ => return Err(ParseError::InvalidField),
                };
                let pc = (cdb[2] & 0b1100_0000) >> 6;
                let page_code = cdb[2] & 0b0011_1111;
                let subpage_code = cdb[3];
                let mode: ModePageSelection = match (page_code, subpage_code) {
                    (0x8, 0x0) => ModePageSelection::Single(ModePage::Caching),
                    (0x3f, 0x0) => ModePageSelection::AllPageZeros,
                    _ => {
                        warn!(
                            "Rejecting request for unknown mode page {:#2x}/{:#2x}.",
                            page_code, subpage_code
                        );
                        return Err(ParseError::InvalidField);
                    }
                };
                Ok(Self {
                    command: Command::LunSpecificCommand(LunSpecificCommand::ModeSense6 {
                        pc: pc.try_into().map_err(|_| ParseError::InvalidField)?,
                        mode_page: mode,
                        dbd,
                    }),
                    allocation_length: Some(u32::from(cdb[4])),
                    naca: (cdb[5] & 0b0000_0100) != 0,
                })
            }
            CommandType::Read10 => {
                if cdb[1] & 0b1110_0100 != 0 {
                    // Features (protection and rebuild assist) we don't
                    // support; the standard says to respond with INVALID
                    // FIELD IN CDB for these if unsupported
                    return Err(ParseError::InvalidField);
                }
                Ok(Self {
                    command: Command::LunSpecificCommand(LunSpecificCommand::Read10 {
                        dpo: cdb[1] & 0b0001_0000 != 0,
                        fua: cdb[1] & 0b0000_1000 != 0,
                        lba: u32::from_be_bytes(cdb[2..6].try_into().unwrap()),
                        transfer_length: u16::from_be_bytes(cdb[7..9].try_into().unwrap()),
                    }),
                    allocation_length: None,
                    naca: (cdb[9] & 0b0000_0100) != 0,
                })
            }
            CommandType::Write10 => {
                if cdb[1] & 0b1110_0000 != 0 {
                    // Feature (protection) that we don't
                    // support; the standard says to respond with INVALID
                    // FIELD IN CDB for these if unsupported
                    return Err(ParseError::InvalidField);
                }
                Ok(Self {
                    command: Command::LunSpecificCommand(LunSpecificCommand::Write10 {
                        dpo: cdb[1] & 0b0001_0000 != 0,
                        fua: cdb[1] & 0b0000_1000 != 0,
                        lba: u32::from_be_bytes(cdb[2..6].try_into().unwrap()),
                        transfer_length: u16::from_be_bytes(cdb[7..9].try_into().unwrap()),
                    }),
                    allocation_length: None,
                    naca: (cdb[9] & 0b0000_0100) != 0,
                })
            }
            CommandType::WriteSame16 => {
                if cdb[1] & 0b1110_0001 != 0 {
                    warn!("Unsupported field in WriteSame16");
                    // We neither support protections nor logical block provisioning
                    return Err(ParseError::InvalidField);
                }
                Ok(Self {
                    command: Command::LunSpecificCommand(LunSpecificCommand::WriteSame16 {
                        lba: u64::from_be_bytes(cdb[2..10].try_into().expect("lba should fit u64")),
                        number_of_logical_blocks: u32::from_be_bytes(
                            cdb[10..14].try_into().expect("block count should fit u32"),
                        ),
                        anchor: (cdb[1] & 0b0001_0000) != 0,
                    }),
                    allocation_length: None,
                    naca: (cdb[15] & 0b0000_0100) != 0,
                })
            }
            CommandType::SynchronizeCache10 => Ok(Self {
                command: Command::LunSpecificCommand(LunSpecificCommand::SynchronizeCache10),
                allocation_length: None,
                naca: (cdb[9] & 0b0000_0100) != 0,
            }),
            CommandType::ReadCapacity10 => Ok(Self {
                command: Command::LunSpecificCommand(LunSpecificCommand::ReadCapacity10),
                allocation_length: None,
                naca: (cdb[9] & 0b0000_0100) != 0,
            }),
            CommandType::ReadCapacity16 => Ok(Self {
                command: Command::LunSpecificCommand(LunSpecificCommand::ReadCapacity16),
                allocation_length: Some(u32::from_be_bytes(cdb[10..14].try_into().unwrap())),
                naca: (cdb[15] & 0b0000_0100) != 0,
            }),
            CommandType::ReportLuns => Ok(Self {
                command: Command::LunIndependentCommand(LunIndependentCommand::ReportLuns(
                    cdb[2].try_into().map_err(|_| ParseError::InvalidField)?,
                )),
                allocation_length: Some(u32::from_be_bytes(cdb[6..10].try_into().unwrap())),
                naca: (cdb[9] & 0b0000_0100) != 0,
            }),
            CommandType::ReportSupportedOperationCodes => {
                let rctd = cdb[2] & 0b1000_0000 != 0;
                let mode = match cdb[2] & 0b0000_0111 {
                    0b000 => ReportSupportedOpCodesMode::All,
                    0b001 => ReportSupportedOpCodesMode::OneCommand(cdb[3]),
                    0b010 => ReportSupportedOpCodesMode::OneServiceAction(
                        cdb[3],
                        u16::from_be_bytes(cdb[4..6].try_into().unwrap()),
                    ),
                    0b011 => ReportSupportedOpCodesMode::OneCommandOrServiceAction(
                        cdb[3],
                        u16::from_be_bytes(cdb[4..6].try_into().unwrap()),
                    ),
                    _ => return Err(ParseError::InvalidField),
                };

                Ok(Self {
                    command: Command::LunSpecificCommand(
                        LunSpecificCommand::ReportSupportedOperationCodes { rctd, mode },
                    ),
                    allocation_length: Some(u32::from_be_bytes(cdb[6..10].try_into().unwrap())),
                    naca: (cdb[11] & 0b0000_0100) != 0,
                })
            }
            CommandType::RequestSense => {
                let format = if cdb[1] & 0b0000_0001 == 1 {
                    SenseFormat::Descriptor
                } else {
                    SenseFormat::Fixed
                };
                Ok(Self {
                    command: Command::LunSpecificCommand(LunSpecificCommand::RequestSense(format)),
                    allocation_length: Some(u32::from(cdb[4])),
                    naca: (cdb[5] & 0b0000_0100) != 0,
                })
            }
            CommandType::TestUnitReady => Ok(Self {
                command: Command::LunSpecificCommand(LunSpecificCommand::TestUnitReady),
                allocation_length: None,
                naca: (cdb[5] & 0b0000_0100) != 0,
            }),
        }
    }
}
