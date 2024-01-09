// CAN virtio bindings
//
// Copyright 2023-2024 VIRTUAL OPEN SYSTEMS SAS. All Rights Reserved.
//          Timos Ampelikiotis <t.ampelikiotis@virtualopensystems.com>
//
// SPDX-License-Identifier: Apache-2.0 or BSD-3-Clause

use vm_memory::{ByteValued, Le16, Le32};

/// CAN FRAME Flags and Masks
pub(crate) const CAN_EFF_FLAG: u32 = 0x80000000; // EFF/SFF is set in the MSB
pub(crate) const CAN_RTR_FLAG: u32 = 0x40000000; // remote transmission request
pub(crate) const CAN_ERR_FLAG: u32 = 0x20000000; // error message frame
pub(crate) const CAN_SFF_MASK: u32 = 0x000007FF; // standard frame format (SFF)
pub(crate) const CAN_EFF_MASK: u32 = 0x1FFFFFFF; // extended frame format (EFF)
#[allow(dead_code)]
pub(crate) const CAN_FRMF_BRS: u32 = 0x01; // bit rate switch (2nd bitrate for data)
#[allow(dead_code)]
pub(crate) const CAN_FRMF_ESI: u32 = 0x02; // error state ind. of transmitting node
pub(crate) const CAN_FRMF_TYPE_FD: u32 = 0x10; // internal bit ind. of CAN FD frame
pub(crate) const CAN_ERR_BUSOFF: u32 = 0x00000040; // bus off

/// CANFD frame's valid data lengths
pub(crate) const CANFD_VALID_LENGTHS: [u32; 7] = [12, 16, 20, 24, 32, 48, 64];

/// CAN controller states
pub(crate) const CAN_CS_STARTED: u8 = 0x01;
pub(crate) const CAN_CS_STOPPED: u8 = 0x02;

/// CAN flags to determine type of CAN FRAME Id
pub(crate) const VIRTIO_CAN_FLAGS_EXTENDED: u32 = 0x8000;
pub(crate) const VIRTIO_CAN_FLAGS_FD: u32 = 0x4000;
pub(crate) const VIRTIO_CAN_FLAGS_RTR: u32 = 0x2000;

pub(crate) const VIRTIO_CAN_FLAGS_VALID_MASK: u32 =
    VIRTIO_CAN_FLAGS_EXTENDED | VIRTIO_CAN_FLAGS_FD | VIRTIO_CAN_FLAGS_RTR;

pub(crate) const VIRTIO_CAN_TX: u16 = 0x0001;
pub(crate) const VIRTIO_CAN_RX: u16 = 0x0101;

/// Feature bit numbers
pub const VIRTIO_CAN_F_CAN_CLASSIC: u16 = 0;
pub const VIRTIO_CAN_F_CAN_FD: u16 = 1;
pub const VIRTIO_CAN_S_CTRL_BUSOFF: u16 = 2; /* Controller BusOff */
#[allow(dead_code)]
pub const VIRTIO_CAN_F_LATE_TX_ACK: u16 = 2;
pub const VIRTIO_CAN_F_RTR_FRAMES: u16 = 3;

/// Possible values of the status field
pub const VIRTIO_CAN_RESULT_OK: u8 = 0x0;
pub const VIRTIO_CAN_RESULT_NOT_OK: u8 = 0x1;

/// CAN Control messages
pub const VIRTIO_CAN_SET_CTRL_MODE_START: u16 = 0x0201;
pub const VIRTIO_CAN_SET_CTRL_MODE_STOP: u16 = 0x0202;

/// Virtio Can Configuration
#[derive(Copy, Clone, Debug, Default, PartialEq)]
#[repr(C)]
pub(crate) struct VirtioCanConfig {
    /// CAN controller status
    pub(crate) status: Le16,
}

// SAFETY: The layout of the structure is fixed and can be initialized by
// reading its content from byte array.
unsafe impl ByteValued for VirtioCanConfig {}

/// Virtio CAN Request / Response messages
///
/// The response message is a stream of bytes, where first byte represents the
/// status, and rest is message specific data.

#[derive(Copy, Clone, Default)]
#[repr(C)]
pub struct VirtioCanTxResponse {
    pub result: i8,
}

// SAFETY: The layout of the structure is fixed and can be initialized by
// reading its content from byte array.
unsafe impl ByteValued for VirtioCanTxResponse {}

#[derive(Copy, Clone, Debug, PartialEq)]
#[repr(C)]
pub struct VirtioCanFrame {
    pub msg_type: Le16,
    pub length: Le16,   /* 0..8 CC, 0..64 CAN­FD, 0..2048 CAN­XL, 12 bits */
    pub reserved: Le32, /* May be needed in part for CAN XL priority */
    pub flags: Le32,
    pub can_id: Le32,
    pub sdu: [u8; 64],
}

// SAFETY: The layout of the structure is fixed and can be initialized by
// reading its content from byte array.
unsafe impl ByteValued for VirtioCanFrame {}

impl Default for VirtioCanFrame {
    fn default() -> Self {
        VirtioCanFrame {
            msg_type: Le16::default(),
            length: Le16::default(),
            reserved: Le32::default(),
            flags: Le32::default(),
            can_id: Le32::default(),
            sdu: [0; 64], // Initialize "sdu" with default value (0 in this case)
        }
    }
}

#[derive(Copy, Clone, Debug, PartialEq, Default)]
#[repr(C)]
pub struct VirtioCanHeader {
    pub msg_type: Le16,
    pub length: Le16,   /* 0..8 CC, 0..64 CAN­FD, 0..2048 CAN­XL, 12 bits */
    pub reserved: Le32, /* May be needed in part for CAN XL priority */
    pub flags: Le32,
    pub can_id: Le32,
}

// SAFETY: The layout of the structure is fixed and can be initialized by
// reading its content from byte array.
unsafe impl ByteValued for VirtioCanHeader {}

#[derive(Copy, Clone, Default)]
#[repr(C)]
pub struct VirtioCanCtrlRequest {
    pub msg_type: Le16,
}

// SAFETY: The layout of the structure is fixed and can be initialized by
// reading its content from byte array.
unsafe impl ByteValued for VirtioCanCtrlRequest {}

#[derive(Copy, Clone, Default)]
#[repr(C)]
pub struct VirtioCanCtrlResponse {
    pub result: i8,
}

// SAFETY: The layout of the structure is fixed and can be initialized by
// reading its content from byte array.
unsafe impl ByteValued for VirtioCanCtrlResponse {}
