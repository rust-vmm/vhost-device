// SPDX-License-Identifier: Apache-2.0 or BSD-3-Clause

use super::{do_command_fail, do_command_in, null_image};
use crate::scsi::{
    emulation::{block_device::BlockDevice, target::EmulatedTarget},
    sense,
};

#[test]
fn test_one_command() {
    let mut target = EmulatedTarget::new();
    let dev = BlockDevice::new(null_image());
    target.add_lun(Box::new(dev));

    do_command_in(
        &mut target,
        &[
            0xa3, 0x0c, // REPORT SUPPORTED OPERATION CODES
            0b1,  // reporting options: one command
            0, 1, 2, // opcode: TEST UNIT READY, SA ignored
            0, 0, 1, 0, // allocation length: 256
            0, // reserved
            0, // control
        ],
        &[],
        &[
            0, 0b11, // flags, supported
            0, 6, // cdb len
            0, 0, 0, 0, 0, 0b0100, // usage data
        ],
    );
}

#[test]
fn test_one_command_with_timeout_descriptor() {
    let mut target = EmulatedTarget::new();
    let dev = BlockDevice::new(null_image());
    target.add_lun(Box::new(dev));

    do_command_in(
        &mut target,
        &[
            0xa3, 0x0c, // REPORT SUPPORTED OPERATION CODES
            0x81, // request timeout descs, reporting options: one command
            0, 1, 2, // opcode: TEST UNIT READY, SA ignored
            0, 0, 1, 0, // allocation length: 256
            0, // reserved
            0, // control
        ],
        &[],
        &[
            0, 0b11, // flags, supported
            0, 6, // cdb len
            0, 0, 0, 0, 0, 0b0100, // usage data
            0, 0xa, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, // no timeouts
        ],
    );
}

#[test]
fn test_one_command_unsupported() {
    let mut target = EmulatedTarget::new();
    let dev = BlockDevice::new(null_image());
    target.add_lun(Box::new(dev));

    do_command_in(
        &mut target,
        &[
            0xa3, 0x0c, // REPORT SUPPORTED OPERATION CODES
            0b1,  // reporting options: one command
            0xff, 1, 2, // opcode: vendor specific, SA ignored
            0, 0, 1, 0, // allocation length: 256
            0, // reserved
            0, // control
        ],
        &[],
        &[
            0, 0b01, // flags, not supported
            0, 0, // cdb len
        ],
    );
}

#[test]
fn test_one_command_valid_service_action() {
    let mut target = EmulatedTarget::new();
    let dev = BlockDevice::new(null_image());
    target.add_lun(Box::new(dev));

    do_command_fail(
        &mut target,
        &[
            0xa3, 0x0c, // REPORT SUPPORTED OPERATION CODES
            0b1,  // reporting options: one command
            0x9e, 0, 0x10, // SERVICE ACTION IN (16), READ CAPACITY (16)
            0, 0, 1, 0, // allocation length: 256
            0, // reserved
            0, // control
        ],
        sense::INVALID_FIELD_IN_CDB,
    );
}

#[test]
fn test_one_command_invalid_service_action() {
    let mut target = EmulatedTarget::new();
    let dev = BlockDevice::new(null_image());
    target.add_lun(Box::new(dev));

    do_command_fail(
        &mut target,
        &[
            0xa3, 0x0c, // REPORT SUPPORTED OPERATION CODES
            0b1,  // reporting options: one command
            0x9e, 0, 0xff, // SERVICE ACTION IN (16), invalid
            0, 0, 1, 0, // allocation length: 256
            0, // reserved
            0, // control
        ],
        sense::INVALID_FIELD_IN_CDB,
    );
}

#[test]
fn test_one_service_action() {
    let mut target = EmulatedTarget::new();
    let dev = BlockDevice::new(null_image());
    target.add_lun(Box::new(dev));

    do_command_in(
        &mut target,
        &[
            0xa3, 0x0c, // REPORT SUPPORTED OPERATION CODES
            0b10, // reporting options: one service action
            0x9e, 0, 0x10, // SERVICE ACTION IN (16), READ CAPACITY (16)
            0, 0, 1, 0, // allocation length: 256
            0, // reserved
            0, // control
        ],
        &[],
        &[
            0, 0b11, // flags, supported
            0, 16, // cdb len
            0x9e, 0x10, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 0xff, 0xff, 0,
            0b0100, // usage data
        ],
    );
}

#[test]
fn test_one_service_action_with_timeout_descriptor() {
    let mut target = EmulatedTarget::new();
    let dev = BlockDevice::new(null_image());
    target.add_lun(Box::new(dev));

    do_command_in(
        &mut target,
        &[
            0xa3, 0x0c, // REPORT SUPPORTED OPERATION CODES
            0x82, // request timeout descs, reporting options: one service action
            0x9e, 0, 0x10, // SERVICE ACTION IN (16), READ CAPACITY (16)
            0, 0, 1, 0, // allocation length: 256
            0, // reserved
            0, // control
        ],
        &[],
        &[
            0, 0b11, // flags, supported
            0, 16, // cdb len
            0x9e, 0x10, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 0xff, 0xff, 0,
            0b0100, // usage data
            0, 0xa, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, // no timeouts
        ],
    );
}

#[test]
fn test_one_service_action_unknown_opcode() {
    let mut target = EmulatedTarget::new();
    let dev = BlockDevice::new(null_image());
    target.add_lun(Box::new(dev));

    // not entirely sure this behavior is correct; see comment in implementation
    do_command_fail(
        &mut target,
        &[
            0xa3, 0x0c, // REPORT SUPPORTED OPERATION CODES
            0b10, // reporting options: one service action
            0xff, 1, 2, // opcode: vendor specific, unimplemented
            0, 0, 1, 0, // allocation length: 256
            0, // reserved
            0, // control
        ],
        sense::INVALID_FIELD_IN_CDB,
    );
}

#[test]
fn test_one_service_action_unknown_service_action() {
    let mut target = EmulatedTarget::new();
    let dev = BlockDevice::new(null_image());
    target.add_lun(Box::new(dev));

    do_command_in(
        &mut target,
        &[
            0xa3, 0x0c, // REPORT SUPPORTED OPERATION CODES
            0b10, // reporting options: one service action
            0x9e, 0, 0xff, // SERVICE ACTION IN (16), invalid SA
            0, 0, 1, 0, // allocation length: 256
            0, // reserved
            0, // control
        ],
        &[],
        &[
            0, 0b01, // flags, not supported
            0, 0, // cdb len
        ],
    );
}

#[test]
fn test_one_service_action_not_service_action() {
    let mut target = EmulatedTarget::new();
    let dev = BlockDevice::new(null_image());
    target.add_lun(Box::new(dev));

    do_command_fail(
        &mut target,
        &[
            0xa3, 0x0c, // REPORT SUPPORTED OPERATION CODES
            0b10, // reporting options: one service action
            0, 1, 2, // TEST UNIT READY
            0, 0, 1, 0, // allocation length: 256
            0, // reserved
            0, // control
        ],
        sense::INVALID_FIELD_IN_CDB,
    );
}

// rest of these tests are for "mode 3", which the spec calls 011b and our
// implementation calls OneCommandOrServiceAction, but that's a mouthful so just
// use "mode 3" for test names

#[test]
fn test_mode_3_opcode_without_service_action() {
    let mut target = EmulatedTarget::new();
    let dev = BlockDevice::new(null_image());
    target.add_lun(Box::new(dev));

    do_command_in(
        &mut target,
        &[
            0xa3, 0x0c, // REPORT SUPPORTED OPERATION CODES
            0b11, // reporting options: mode 3
            0, 0, 0, // opcode: TEST UNIT READY, SA: 0
            0, 0, 1, 0, // allocation length: 256
            0, // reserved
            0, // control
        ],
        &[],
        &[
            0, 0b11, // flags, supported
            0, 6, // cdb len
            0, 0, 0, 0, 0, 0b0100, // usage data
        ],
    );
}

#[test]
fn test_mode_3_with_timeout_descriptor() {
    let mut target = EmulatedTarget::new();
    let dev = BlockDevice::new(null_image());
    target.add_lun(Box::new(dev));

    do_command_in(
        &mut target,
        &[
            0xa3, 0x0c, // REPORT SUPPORTED OPERATION CODES
            0x83, // request timeout descs, reporting options: mode 3
            0, 0, 0, // opcode: TEST UNIT READY, SA: 0
            0, 0, 1, 0, // allocation length: 256
            0, // reserved
            0, // control
        ],
        &[],
        &[
            0, 0b11, // flags, supported
            0, 6, // cdb len
            0, 0, 0, 0, 0, 0b0100, // usage data
            0, 0xa, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, // no timeouts
        ],
    );
}

#[test]
fn test_mode_3_opcode_with_unnecessary_service_action() {
    let mut target = EmulatedTarget::new();
    let dev = BlockDevice::new(null_image());
    target.add_lun(Box::new(dev));

    do_command_in(
        &mut target,
        &[
            0xa3, 0x0c, // REPORT SUPPORTED OPERATION CODES
            0b11, // reporting options: mode 3
            0, 0, 1, // opcode: TEST UNIT READY, SA: 1
            0, 0, 1, 0, // allocation length: 256
            0, // reserved
            0, // control
        ],
        &[],
        &[
            0, 0b01, // flags, not supported
            0, 0, // cdb len
        ],
    );
}

#[test]
fn test_mode_3_invalid_opcode() {
    let mut target = EmulatedTarget::new();
    let dev = BlockDevice::new(null_image());
    target.add_lun(Box::new(dev));

    do_command_in(
        &mut target,
        &[
            0xa3, 0x0c, // REPORT SUPPORTED OPERATION CODES
            0b11, // reporting options: mode 3
            0xff, 0, 0, // opcode: vendor specific
            0, 0, 1, 0, // allocation length: 256
            0, // reserved
            0, // control
        ],
        &[],
        &[
            0, 0b01, // flags, not supported
            0, 0, // cdb len
        ],
    );
}

#[test]
fn test_mode_3_service_action() {
    let mut target = EmulatedTarget::new();
    let dev = BlockDevice::new(null_image());
    target.add_lun(Box::new(dev));

    do_command_in(
        &mut target,
        &[
            0xa3, 0x0c, // REPORT SUPPORTED OPERATION CODES
            0b11, // reporting options: mode 3
            0x9e, 0, 0x10, // opcode: SERVICE ACTION IN (16), READ CAPACITY (16)
            0, 0, 1, 0, // allocation length: 256
            0, // reserved
            0, // control
        ],
        &[],
        &[
            0, 0b11, // flags, supported
            0, 16, // cdb len
            0x9e, 0x10, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 0xff, 0xff, 0,
            0b0100, // usage data
        ],
    );
}

#[test]
fn test_mode_3_service_action_with_timeout_descriptor() {
    let mut target = EmulatedTarget::new();
    let dev = BlockDevice::new(null_image());
    target.add_lun(Box::new(dev));

    do_command_in(
        &mut target,
        &[
            0xa3, 0x0c, // REPORT SUPPORTED OPERATION CODES
            0x83, // request timeout desc, tireporting options: mode 3
            0x9e, 0, 0x10, // opcode: SERVICE ACTION IN (16), READ CAPACITY (16)
            0, 0, 1, 0, // allocation length: 256
            0, // reserved
            0, // control
        ],
        &[],
        &[
            0, 0b11, // flags, supported
            0, 16, // cdb len
            0x9e, 0x10, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 0xff, 0xff, 0,
            0b0100, // usage data
            0, 0xa, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, // no timeouts
        ],
    );
}

#[test]
fn test_mode_3_invalid_service_action() {
    let mut target = EmulatedTarget::new();
    let dev = BlockDevice::new(null_image());
    target.add_lun(Box::new(dev));

    do_command_in(
        &mut target,
        &[
            0xa3, 0x0c, // REPORT SUPPORTED OPERATION CODES
            0b11, // reporting options: mode 3
            0x9e, 0, 0xff, // opcode: SERVICE ACTION IN (16), invalid SA
            0, 0, 1, 0, // allocation length: 256
            0, // reserved
            0, // control
        ],
        &[],
        &[
            0, 0b01, // flags, not supported
            0, 0, // cdb len
        ],
    );
}
