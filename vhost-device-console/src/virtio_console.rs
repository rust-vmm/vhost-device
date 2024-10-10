// Console virtio bindings
//
// Copyright 2023-2024 VIRTUAL OPEN SYSTEMS SAS. All Rights Reserved.
//          Timos Ampelikiotis <t.ampelikiotis@virtualopensystems.com>
//
// SPDX-License-Identifier: Apache-2.0 or BSD-3-Clause

use vm_memory::{ByteValued, Le16, Le32};

/// Feature bit numbers
#[allow(dead_code)]
pub const VIRTIO_CONSOLE_F_SIZE: u16 = 0;
pub const VIRTIO_CONSOLE_F_MULTIPORT: u16 = 1;
#[allow(dead_code)]
pub const VIRTIO_CONSOLE_F_EMERG_WRITE: u16 = 2;

/// Console virtio control messages
pub const VIRTIO_CONSOLE_DEVICE_READY: u16 = 0;
pub const VIRTIO_CONSOLE_PORT_ADD: u16 = 1;
#[allow(dead_code)]
pub const VIRTIO_CONSOLE_PORT_REMOVE: u16 = 2;
pub const VIRTIO_CONSOLE_PORT_READY: u16 = 3;
pub const VIRTIO_CONSOLE_CONSOLE_PORT: u16 = 4;
#[allow(dead_code)]
pub const VIRTIO_CONSOLE_RESIZE: u16 = 5;
pub const VIRTIO_CONSOLE_PORT_OPEN: u16 = 6;
pub const VIRTIO_CONSOLE_PORT_NAME: u16 = 7;

/// Virtio Console Config
#[derive(Copy, Clone, Debug, Default, PartialEq)]
#[repr(C)]
pub(crate) struct VirtioConsoleConfig {
    pub cols: Le16,
    pub rows: Le16,
    pub max_nr_ports: Le32,
    pub emerg_wr: Le32,
}

// SAFETY: The layout of the structure is fixed and can be initialized by
// reading its content from byte array.
unsafe impl ByteValued for VirtioConsoleConfig {}

#[derive(Copy, Clone, Debug, Default, PartialEq)]
#[repr(C)]
pub(crate) struct VirtioConsoleControl {
    pub id: Le32,
    pub event: Le16,
    pub value: Le16,
}

impl VirtioConsoleControl {
    pub fn to_le_bytes(self) -> Vec<u8> {
        let mut buffer = Vec::new();

        buffer.extend_from_slice(&self.id.to_native().to_le_bytes());
        buffer.extend_from_slice(&self.event.to_native().to_le_bytes());
        buffer.extend_from_slice(&self.value.to_native().to_le_bytes());
        buffer
    }
}
