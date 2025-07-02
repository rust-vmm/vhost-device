// SPDX-License-Identifier: Apache-2.0 or BSD-3-Clause

//! Tests for stuff shared between commands.

use assert_matches::assert_matches;
use std::io::ErrorKind;

use super::{do_command_fail, test_image};
use crate::scsi::{
    emulation::{block_device::BlockDevice, target::EmulatedTarget},
    sense, CmdError, Request, Target, TaskAttr,
};

#[test]
fn test_invalid_opcode() {
    let mut target = EmulatedTarget::new();
    let dev = BlockDevice::new(test_image());
    target.add_lun(Box::new(dev));

    do_command_fail(
        &mut target,
        &[
            0xff, // vendor specific, unused by us
            0, 0, 0, 0, 0,
        ],
        sense::INVALID_COMMAND_OPERATION_CODE,
    );
}

#[test]
fn test_invalid_service_action() {
    let mut target = EmulatedTarget::new();
    let dev = BlockDevice::new(test_image());
    target.add_lun(Box::new(dev));

    do_command_fail(
        &mut target,
        &[
            0xa3, // MAINTENANCE IN
            0x1f, // vendor specific, unused by us
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        ],
        sense::INVALID_FIELD_IN_CDB,
    );
}

#[test]
fn test_short_data_out_buffer() {
    let mut target = EmulatedTarget::new();
    let dev = BlockDevice::new(test_image());
    target.add_lun(Box::new(dev));

    let mut data_in: &mut [u8] = &mut [];
    let mut data_out: &[u8] = &[0_u8; 511];

    let res = target.execute_command(
        0,
        &mut data_out,
        &mut data_in,
        Request {
            id: 0,
            cdb: &[
                0x28, // READ (10)
                0,    // flags
                0, 0, 0, 15, // LBA: 5
                0,  // reserved, group #
                0, 1, // transfer length: 1
                0, // control
            ],
            task_attr: TaskAttr::Simple,
            crn: 0,
            prio: 0,
        },
    );

    if let CmdError::DataIn(e) = res.unwrap_err() {
        assert_eq!(e.kind(), ErrorKind::WriteZero);
    } else {
        panic!();
    }
}

#[test]
fn test_short_cdb() {
    let mut target: EmulatedTarget = EmulatedTarget::new();
    let dev = BlockDevice::new(test_image());
    target.add_lun(Box::new(dev));

    let mut data_in: &mut [u8] = &mut [];
    let mut data_out: &[u8] = &[];

    let res = target.execute_command(
        0,
        &mut data_out,
        &mut data_in,
        Request {
            id: 0,
            cdb: &[
                0x28, // READ (10)
            ],
            task_attr: TaskAttr::Simple,
            crn: 0,
            prio: 0,
        },
    );

    assert_matches!(res.unwrap_err(), CmdError::CdbTooShort);
}
