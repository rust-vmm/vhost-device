// SPDX-License-Identifier: Apache-2.0 or BSD-3-Clause

#![cfg(test)]

mod bad_lun;
mod generic;
mod report_supported_operation_codes;

use std::{
    fs::File,
    io::Write,
    sync::{Arc, Mutex},
};

use tempfile::tempfile;

use super::{
    block_device::{
        BlockDevice, BlockDeviceBackend, BlockOffset, BlockSize, ByteOffset, FileBackend,
    },
    target::EmulatedTarget,
};
use crate::scsi::{
    sense::{self, SenseTriple},
    CmdOutput, Request, Target, TaskAttr,
};

#[derive(Clone)]
struct TestBackend {
    data: Arc<Mutex<[u8; 512 * 16]>>,
}

impl TestBackend {
    fn new() -> Self {
        TestBackend {
            data: Arc::new(Mutex::new([0; 512 * 16])),
        }
    }
}

impl BlockDeviceBackend for TestBackend {
    fn read_exact_at(&mut self, buf: &mut [u8], offset: ByteOffset) -> std::io::Result<()> {
        let data = self.data.lock().unwrap();

        let offset = usize::try_from(u64::from(offset)).expect("offset should fit usize");
        buf.copy_from_slice(&data[offset..(offset + buf.len())]);
        Ok(())
    }

    fn write_exact_at(&mut self, buf: &[u8], offset: ByteOffset) -> std::io::Result<()> {
        let mut data = self.data.lock().unwrap();

        let offset = usize::try_from(u64::from(offset)).expect("offset should fit usize");
        data[offset..(offset + buf.len())].copy_from_slice(buf);
        Ok(())
    }

    fn size_in_blocks(&mut self) -> std::io::Result<BlockOffset> {
        Ok(ByteOffset::from(
            u64::try_from(self.data.lock().unwrap().len()).expect("size_in_blocks should fit u64"),
        ) / self.block_size())
    }

    fn block_size(&self) -> BlockSize {
        BlockSize::try_from(512).expect("512 should be a valid BlockSize")
    }

    fn sync(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

fn null_image() -> FileBackend {
    FileBackend::new(File::open("/dev/null").unwrap())
}

fn test_image() -> FileBackend {
    let mut f = tempfile().unwrap();
    // generate 16 512-byte sectors, each of which consist of a single
    // repeated hex character, i.e.
    // sector 00: 0000000....0000
    // sector 15: fffffff....ffff
    for chr in b'0'..=b'9' {
        f.write_all(&[chr; 512]).unwrap();
    }
    for chr in b'a'..=b'f' {
        f.write_all(&[chr; 512]).unwrap();
    }
    FileBackend::new(f)
}

fn do_command_in_lun(
    target: &mut EmulatedTarget,
    lun: u16,
    cdb: &[u8],
    data_out: &[u8],
    expected_data_in: &[u8],
) {
    let mut data_in = Vec::new();

    let res = target.execute_command(
        lun,
        &mut &data_out[..],
        &mut data_in,
        Request {
            id: 0,
            cdb,
            task_attr: TaskAttr::Simple,
            crn: 0,
            prio: 0,
        },
    );

    assert_eq!(res.unwrap(), CmdOutput::ok());
    assert_eq!(&data_in, expected_data_in);
}

fn do_command_fail_lun(
    target: &mut EmulatedTarget,
    lun: u16,
    cdb: &[u8],
    expected_error: SenseTriple,
) {
    let mut data_in = Vec::new();
    let mut data_out: &[u8] = &[];

    let res = target.execute_command(
        lun,
        &mut data_out,
        &mut data_in,
        Request {
            id: 0,
            cdb,
            task_attr: TaskAttr::Simple,
            crn: 0,
            prio: 0,
        },
    );

    assert_eq!(res.unwrap(), CmdOutput::check_condition(expected_error));
    assert_eq!(&data_in, &[]);
}

fn do_command_in(
    target: &mut EmulatedTarget,
    cdb: &[u8],
    data_out: &[u8],
    expected_data_in: &[u8],
) {
    do_command_in_lun(target, 0, cdb, data_out, expected_data_in);
}

fn do_command_fail(target: &mut EmulatedTarget, cdb: &[u8], expected_error: SenseTriple) {
    do_command_fail_lun(target, 0, cdb, expected_error);
}

fn block_size_512() -> BlockSize {
    BlockSize::try_from(512).expect("512 should be a valid block_size")
}

#[test]
fn test_test_unit_ready() {
    let mut target = EmulatedTarget::new();
    let dev = BlockDevice::new(null_image());
    target.add_lun(Box::new(dev));

    do_command_in(&mut target, &[0, 0, 0, 0, 0, 0], &[], &[]);
}

#[test]
fn test_report_luns() {
    let mut target = EmulatedTarget::new();
    for _ in 0..5 {
        let dev = BlockDevice::new(null_image());
        target.add_lun(Box::new(dev));
    }

    do_command_in(
        &mut target,
        &[
            0xa0, // REPORT LUNS
            0,    // reserved
            0,    // select report
            0, 0, 0, // reserved
            0, 0, 1, 0, // alloc length: 256
            0, 0,
        ],
        &[],
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

#[test]
fn test_read_10() {
    let mut target = EmulatedTarget::new();
    let dev = BlockDevice::new(test_image());
    target.add_lun(Box::new(dev));

    // TODO: this test relies on the default logical block size of 512. We should
    // make that explicit.

    do_command_in(
        &mut target,
        &[
            0x28, // READ (10)
            0,    // flags
            0, 0, 0, 5, // LBA: 5
            0, // reserved, group #
            0, 1, // transfer length: 1
            0, // control
        ],
        &[],
        &[b'5'; 512],
    );
}

#[test]
fn test_read_10_last_block() {
    let mut target = EmulatedTarget::new();
    let dev = BlockDevice::new(test_image());
    target.add_lun(Box::new(dev));

    // TODO: this test relies on the default logical block size of 512. We should
    // make that explicit.

    do_command_in(
        &mut target,
        &[
            0x28, // READ (10)
            0,    // flags
            0, 0, 0, 15, // LBA: 5
            0,  // reserved, group #
            0, 1, // transfer length: 1
            0, // control
        ],
        &[],
        &[b'f'; 512],
    );
}

#[test]
fn test_read_10_out_of_range() {
    let mut target = EmulatedTarget::new();
    let dev = BlockDevice::new(test_image());
    target.add_lun(Box::new(dev));

    // TODO: this test relies on the default logical block size of 512. We should
    // make that explicit.

    do_command_fail(
        &mut target,
        &[
            0x28, // READ (10)
            0,    // flags
            0, 0, 0, 16, // LBA: 16
            0,  // reserved, group #
            0, 1, // transfer length: 1
            0, // control
        ],
        sense::LOGICAL_BLOCK_ADDRESS_OUT_OF_RANGE,
    );
}

#[test]
fn test_read_10_cross_out() {
    let mut target = EmulatedTarget::new();
    let dev = BlockDevice::new(null_image());
    target.add_lun(Box::new(dev));

    // TODO: this test relies on the default logical block size of 512. We should
    // make that explicit.

    do_command_fail(
        &mut target,
        &[
            0x28, // READ (10)
            0,    // flags
            0, 0, 0, 15, // LBA: 15
            0,  // reserved, group #
            0, 2, // transfer length: 2
            0, // control
        ],
        sense::LOGICAL_BLOCK_ADDRESS_OUT_OF_RANGE,
    );
}

#[test]
fn test_write_10() {
    let mut target = EmulatedTarget::new();
    let mut backend = TestBackend::new();
    let dev = BlockDevice::new(backend.clone());
    target.add_lun(Box::new(dev));

    // TODO: this test relies on the default logical block size of 512. We should
    // make that explicit.

    {
        let data_out = [b'w'; 512];

        do_command_in(
            &mut target,
            &[
                0x2a, // WRITE (10)
                0,    // flags
                0, 0, 0, 5, // LBA: 5
                0, // reserved, group #
                0, 1, // transfer length: 1
                0, // control
            ],
            &data_out,
            &[],
        );

        let mut buf = [0_u8; 512];
        backend
            .read_exact_at(&mut buf, BlockOffset::from(5) * block_size_512())
            .expect("Reading should work");
        assert_eq!(data_out, buf);
    }
}

#[test]
fn test_read_capacity_10() {
    let mut target = EmulatedTarget::new();
    let dev = BlockDevice::new(test_image());
    target.add_lun(Box::new(dev));

    // TODO: this test relies on the default logical block size of 512. We should
    // make that explicit.

    // TODO: we should test behavior with ≥ 2 TiB images. But not sure how we
    // can do that reliably without risking using 2 TiB of disk

    do_command_in(
        &mut target,
        &[
            0x25, // READ CAPACITY (10)
            0, 0, 0, 0, 0, 0, 0, 0, // flags
            0, // control
        ],
        &[],
        &[
            0, 0, 0, 15, // returned LBA (last valid LBA),
            0, 0, 2, 0, // block size (512)
        ],
    );
}

#[test]
fn test_read_capacity_16() {
    let mut target = EmulatedTarget::new();
    let dev = BlockDevice::new(test_image());
    target.add_lun(Box::new(dev));

    // TODO: this test relies on the default logical block size of 512. We should
    // make that explicit.

    do_command_in(
        &mut target,
        &[
            0x9e, 0x10, // READ CAPACITY (16)
            0, 0, 0, 0, 0, 0, 0, 0, // obsolete
            0, 0, 0, 32, // allocation length: 32
            0,  // obselete/reserved
            0,  // control
        ],
        &[],
        &[
            0, 0, 0, 0, 0, 0, 0, 15, // returned LBA (last valid LBA),
            0, 0, 2, 0,    // block size (512)
            0,    // reserved, zoned stuff, protection stuff
            0,    // one PB per LB
            0xc0, // thin provisioning, unmapped blocks read 0
            0,    // LBA 0 is aligned (top bits above)
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, // reserved
        ],
    );
}

#[test]
fn test_inquiry() {
    let mut target = EmulatedTarget::new();
    let dev = BlockDevice::new(null_image());
    target.add_lun(Box::new(dev));

    do_command_in(
        &mut target,
        &[
            0x12, // INQUIRY
            0,    // EVPD bit: 0
            0,    // page code
            1, 0, // alloc length: 256
            0, // control
        ],
        &[],
        // some empty comments to get rustfmt to do something vaguely sensible
        &[
            0,    // accessible; direct acccess block device
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
            0x06, 0, // SBC-4
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, //
            // reserved
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        ],
    );
}

#[test]
fn test_request_sense() {
    let mut target = EmulatedTarget::new();
    let dev = BlockDevice::new(null_image());
    target.add_lun(Box::new(dev));

    do_command_in(
        &mut target,
        &[
            0x3, // INQUIRY
            0,   // desc bit: 0
            0, 0,   // reserved
            255, // alloc length
            0,   // control
        ],
        &[],
        // We'll always return this - modern SCSI has autosense, so any errors are sent with the
        // response to the command that caused them (and therefore immediately cleared), and
        // REQUEST SENSE returns an actual error only under some exceptional circumstances
        // we don't implement.
        &sense::NO_ADDITIONAL_SENSE_INFORMATION.to_fixed_sense(),
    );
}

#[test]
fn test_request_sense_descriptor_format() {
    let mut target = EmulatedTarget::new();
    let dev = BlockDevice::new(null_image());
    target.add_lun(Box::new(dev));

    do_command_fail(
        &mut target,
        &[
            0x3, // INQUIRY
            1,   // desc bit: 1
            0, 0,   // reserved
            255, // alloc length
            0,   // control
        ],
        // We don't support descriptor format sense data.
        sense::INVALID_FIELD_IN_CDB,
    );
}
