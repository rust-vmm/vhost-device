use super::{do_command_fail_lun, do_command_in_lun, null_image};
use crate::scsi::{
    emulation::{block_device::BlockDevice, EmulatedTarget},
    sense,
};

#[test]
fn test_report_luns() {
    let mut target: EmulatedTarget<Vec<u8>, &[u8]> = EmulatedTarget::new();
    for _ in 0..5 {
        let dev = BlockDevice::new(null_image());
        target.add_lun(Box::new(dev));
    }

    let select_reports = &[0x0, 0x2]; // all but well known, all

    for &sr in select_reports {
        do_command_in_lun(
            &mut target,
            6,
            &[
                0xa0, // REPORT LUNS
                0,    // reserved
                sr,   // select report
                0, 0, 0, // reserved
                0, 0, 1, 0, // alloc length: 256
                0, 0,
            ],
            &[
                0, 0, 0, 40, // length: 5*8 = 40
                0, 0, 0, 0, // reserved
                0, 0, 0, 0, 0, 0, 0, 0, // LUN 0
                0, 1, 0, 0, 0, 0, 0, 0, // LUN 1
                0, 2, 0, 0, 0, 0, 0, 0, // LUN 2
                0, 3, 0, 0, 0, 0, 0, 0, // LUN 3
                0, 4, 0, 0, 0, 0, 0, 0, // LUN 4
            ],
        );
    }
}

#[test]
fn test_report_luns_empty() {
    let mut target: EmulatedTarget<Vec<u8>, &[u8]> = EmulatedTarget::new();
    for _ in 0..5 {
        let dev = BlockDevice::new(null_image());
        target.add_lun(Box::new(dev));
    }

    // well-known only and several modes explictly defined to return an empty list
    // for all but ceratin types of recieving LUNs
    let select_reports = &[0x1, 0x10, 0x11, 0x12];

    for &sr in select_reports {
        do_command_in_lun(
            &mut target,
            6,
            &[
                0xa0, // REPORT LUNS
                0,    // reserved
                sr,   // select report
                0, 0, 0, // reserved
                0, 0, 1, 0, // alloc length: 256
                0, 0,
            ],
            &[
                0, 0, 0, 0, // length: 0
                0, 0, 0, 0, // reserved
            ],
        );
    }
}

#[test]
fn test_request_sense() {
    let mut target: EmulatedTarget<Vec<u8>, &[u8]> = EmulatedTarget::new();
    let dev = BlockDevice::new(null_image());
    target.add_lun(Box::new(dev));

    do_command_in_lun(
        &mut target,
        1,
        &[
            0x3, // REQUEST SENSE
            0,   // fixed format sense data
            0, 0,   // reserved
            255, // alloc length
            0,   // control
        ],
        &sense::LOGICAL_UNIT_NOT_SUPPORTED.to_fixed_sense(),
    );
}

#[test]
fn test_request_sense_descriptor_format() {
    let mut target: EmulatedTarget<Vec<u8>, &[u8]> = EmulatedTarget::new();
    let dev = BlockDevice::new(null_image());
    target.add_lun(Box::new(dev));

    do_command_fail_lun(
        &mut target,
        1,
        &[
            0x3, // REQUEST SENSE
            1,   // descriptor format sense data
            0, 0,   // reserved
            255, // alloc length
            0,   // control
        ],
        sense::INVALID_FIELD_IN_CDB,
    );
}

#[test]
fn test_inquiry() {
    let mut target: EmulatedTarget<Vec<u8>, &[u8]> = EmulatedTarget::new();
    let dev = BlockDevice::new(null_image());
    target.add_lun(Box::new(dev));

    do_command_in_lun(
        &mut target,
        1,
        &[
            0x12, // INQUIRY
            0,    // EVPD bit: 0
            0,    // page code
            1, 0, // alloc length: 256
            0, // control
        ],
        // some empty comments to get rustfmt to do something vaguely sensible
        &[
            0x7f, // device not accessible, unknown type
            0,    // features
            0x7,  // version
            0x12, // response data format v2, HiSup = 1
            91,   // addl length
            0, 0, 0, // unsupported features
            // vendor
            b'r', b'u', b's', b't', b'-', b'v', b'm', b'm', //
            // product
            b'v', b'h', b'o', b's', b't', b'-', b'u', b's', b'e', b'r', b'-', b's', b'c', b's',
            b'i', b' ', //
            // revision
            b'v', b'0', b' ', b' ', //
            // reserved/obselete/vendor specific
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            // version descriptors
            0x0, 0xc0, // SAM-6
            0x05, 0xc0, // SPC-5 (no code assigned for 6 yet)
            0x06, 0x0, // SBC-4
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, //
            // reserved
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        ],
    );
}

#[test]
fn test_other_command() {
    let mut target: EmulatedTarget<Vec<u8>, &[u8]> = EmulatedTarget::new();
    let dev = BlockDevice::new(null_image());
    target.add_lun(Box::new(dev));

    do_command_fail_lun(
        &mut target,
        1,
        &[
            0, // TEST UNIT READY
            0, 0, 0, 0, // reserved
            0, // control
        ],
        // some empty comments to get rustfmt to do something vaguely sensible
        sense::LOGICAL_UNIT_NOT_SUPPORTED,
    );
}

#[test]
fn test_invalid_command() {
    let mut target: EmulatedTarget<Vec<u8>, &[u8]> = EmulatedTarget::new();
    let dev = BlockDevice::new(null_image());
    target.add_lun(Box::new(dev));

    do_command_fail_lun(
        &mut target,
        1,
        &[
            0xff, // vendor specific
            0, 0, 0, 0, // reserved
            0, // control
        ],
        // some empty comments to get rustfmt to do something vaguely sensible
        sense::LOGICAL_UNIT_NOT_SUPPORTED,
    );
}
