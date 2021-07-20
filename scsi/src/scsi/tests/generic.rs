//! Tests for stuff shared between commands.

use std::{io::ErrorKind, path::Path};

use super::do_command_fail;
use crate::scsi::{
    emulation::{block_device::BlockDevice, EmulatedTarget},
    sense, CmdError, Request, Target, TaskAttr,
};

#[test]
fn test_invalid_opcode() {
    let mut target: EmulatedTarget<Vec<u8>, &[u8]> = EmulatedTarget::new();
    let dev = BlockDevice::new(Path::new("src/scsi/tests/test.img")).unwrap();
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
    let mut target: EmulatedTarget<Vec<u8>, &[u8]> = EmulatedTarget::new();
    let dev = BlockDevice::new(Path::new("src/scsi/tests/test.img")).unwrap();
    target.add_lun(Box::new(dev));

    do_command_fail(
        &mut target,
        &[
            0xa3, // MAINTAINANCE IN
            0x1f, // vendor specific, unused by us
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        ],
        sense::INVALID_FIELD_IN_CDB,
    );
}

#[test]
fn test_short_data_out_buffer() {
    let mut target: EmulatedTarget<&mut [u8], &[u8]> = EmulatedTarget::new();
    let dev = BlockDevice::new(Path::new("src/scsi/tests/test.img")).unwrap();
    target.add_lun(Box::new(dev));

    let mut data_in: &mut [u8] = &mut [];
    let mut data_out: &[u8] = &[0; 511];

    let res = target.execute_command(
        0,
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
            data_in: &mut data_in,
            data_out: &mut data_out,
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
    let mut target: EmulatedTarget<&mut [u8], &[u8]> = EmulatedTarget::new();
    let dev = BlockDevice::new(Path::new("src/scsi/tests/test.img")).unwrap();
    target.add_lun(Box::new(dev));

    let mut data_in: &mut [u8] = &mut [];
    let mut data_out: &[u8] = &[];

    let res = target.execute_command(
        0,
        Request {
            id: 0,
            cdb: &[
                0x28, // READ (10)
            ],
            task_attr: TaskAttr::Simple,
            data_in: &mut data_in,
            data_out: &mut data_out,
            crn: 0,
            prio: 0,
        },
    );

    assert!(matches!(res.unwrap_err(), CmdError::CdbTooShort));
}
