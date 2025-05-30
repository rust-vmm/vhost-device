// Copyright 2024 Red Hat Inc
// Copyright 2019 The ChromiumOS Authors
//
// SPDX-License-Identifier: Apache-2.0 or BSD-3-Clause

#![allow(non_camel_case_types)]

use std::{
    cmp::min,
    convert::From,
    ffi::CStr,
    fmt::{self, Display},
    io::{self, Read, Write},
    marker::PhantomData,
    mem::{size_of, size_of_val},
};

use log::trace;
use rutabaga_gfx::RutabagaError;
use thiserror::Error;
pub use virtio_bindings::virtio_gpu::{
    virtio_gpu_ctrl_type_VIRTIO_GPU_CMD_CTX_ATTACH_RESOURCE as VIRTIO_GPU_CMD_CTX_ATTACH_RESOURCE,
    virtio_gpu_ctrl_type_VIRTIO_GPU_CMD_CTX_CREATE as VIRTIO_GPU_CMD_CTX_CREATE,
    virtio_gpu_ctrl_type_VIRTIO_GPU_CMD_CTX_DESTROY as VIRTIO_GPU_CMD_CTX_DESTROY,
    virtio_gpu_ctrl_type_VIRTIO_GPU_CMD_CTX_DETACH_RESOURCE as VIRTIO_GPU_CMD_CTX_DETACH_RESOURCE,
    virtio_gpu_ctrl_type_VIRTIO_GPU_CMD_GET_CAPSET as VIRTIO_GPU_CMD_GET_CAPSET,
    virtio_gpu_ctrl_type_VIRTIO_GPU_CMD_GET_CAPSET_INFO as VIRTIO_GPU_CMD_GET_CAPSET_INFO,
    virtio_gpu_ctrl_type_VIRTIO_GPU_CMD_GET_DISPLAY_INFO as VIRTIO_GPU_CMD_GET_DISPLAY_INFO,
    virtio_gpu_ctrl_type_VIRTIO_GPU_CMD_GET_EDID as VIRTIO_GPU_CMD_GET_EDID,
    virtio_gpu_ctrl_type_VIRTIO_GPU_CMD_MOVE_CURSOR as VIRTIO_GPU_CMD_MOVE_CURSOR,
    virtio_gpu_ctrl_type_VIRTIO_GPU_CMD_RESOURCE_ASSIGN_UUID as VIRTIO_GPU_CMD_RESOURCE_ASSIGN_UUID,
    virtio_gpu_ctrl_type_VIRTIO_GPU_CMD_RESOURCE_ATTACH_BACKING as VIRTIO_GPU_CMD_RESOURCE_ATTACH_BACKING,
    virtio_gpu_ctrl_type_VIRTIO_GPU_CMD_RESOURCE_CREATE_2D as VIRTIO_GPU_CMD_RESOURCE_CREATE_2D,
    virtio_gpu_ctrl_type_VIRTIO_GPU_CMD_RESOURCE_CREATE_3D as VIRTIO_GPU_CMD_RESOURCE_CREATE_3D,
    virtio_gpu_ctrl_type_VIRTIO_GPU_CMD_RESOURCE_CREATE_BLOB as VIRTIO_GPU_CMD_RESOURCE_CREATE_BLOB,
    virtio_gpu_ctrl_type_VIRTIO_GPU_CMD_RESOURCE_DETACH_BACKING as VIRTIO_GPU_CMD_RESOURCE_DETACH_BACKING,
    virtio_gpu_ctrl_type_VIRTIO_GPU_CMD_RESOURCE_FLUSH as VIRTIO_GPU_CMD_RESOURCE_FLUSH,
    virtio_gpu_ctrl_type_VIRTIO_GPU_CMD_RESOURCE_MAP_BLOB as VIRTIO_GPU_CMD_RESOURCE_MAP_BLOB,
    virtio_gpu_ctrl_type_VIRTIO_GPU_CMD_RESOURCE_UNMAP_BLOB as VIRTIO_GPU_CMD_RESOURCE_UNMAP_BLOB,
    virtio_gpu_ctrl_type_VIRTIO_GPU_CMD_RESOURCE_UNREF as VIRTIO_GPU_CMD_RESOURCE_UNREF,
    virtio_gpu_ctrl_type_VIRTIO_GPU_CMD_SET_SCANOUT as VIRTIO_GPU_CMD_SET_SCANOUT,
    virtio_gpu_ctrl_type_VIRTIO_GPU_CMD_SET_SCANOUT_BLOB as VIRTIO_GPU_CMD_SET_SCANOUT_BLOB,
    virtio_gpu_ctrl_type_VIRTIO_GPU_CMD_SUBMIT_3D as VIRTIO_GPU_CMD_SUBMIT_3D,
    virtio_gpu_ctrl_type_VIRTIO_GPU_CMD_TRANSFER_FROM_HOST_3D as VIRTIO_GPU_CMD_TRANSFER_FROM_HOST_3D,
    virtio_gpu_ctrl_type_VIRTIO_GPU_CMD_TRANSFER_TO_HOST_2D as VIRTIO_GPU_CMD_TRANSFER_TO_HOST_2D,
    virtio_gpu_ctrl_type_VIRTIO_GPU_CMD_TRANSFER_TO_HOST_3D as VIRTIO_GPU_CMD_TRANSFER_TO_HOST_3D,
    virtio_gpu_ctrl_type_VIRTIO_GPU_CMD_UPDATE_CURSOR as VIRTIO_GPU_CMD_UPDATE_CURSOR,
    virtio_gpu_ctrl_type_VIRTIO_GPU_RESP_ERR_INVALID_CONTEXT_ID as VIRTIO_GPU_RESP_ERR_INVALID_CONTEXT_ID,
    virtio_gpu_ctrl_type_VIRTIO_GPU_RESP_ERR_INVALID_PARAMETER as VIRTIO_GPU_RESP_ERR_INVALID_PARAMETER,
    virtio_gpu_ctrl_type_VIRTIO_GPU_RESP_ERR_INVALID_RESOURCE_ID as VIRTIO_GPU_RESP_ERR_INVALID_RESOURCE_ID,
    virtio_gpu_ctrl_type_VIRTIO_GPU_RESP_ERR_INVALID_SCANOUT_ID as VIRTIO_GPU_RESP_ERR_INVALID_SCANOUT_ID,
    virtio_gpu_ctrl_type_VIRTIO_GPU_RESP_ERR_OUT_OF_MEMORY as VIRTIO_GPU_RESP_ERR_OUT_OF_MEMORY,
    virtio_gpu_ctrl_type_VIRTIO_GPU_RESP_ERR_UNSPEC as VIRTIO_GPU_RESP_ERR_UNSPEC,
    virtio_gpu_ctrl_type_VIRTIO_GPU_RESP_OK_CAPSET as VIRTIO_GPU_RESP_OK_CAPSET,
    virtio_gpu_ctrl_type_VIRTIO_GPU_RESP_OK_CAPSET_INFO as VIRTIO_GPU_RESP_OK_CAPSET_INFO,
    virtio_gpu_ctrl_type_VIRTIO_GPU_RESP_OK_DISPLAY_INFO as VIRTIO_GPU_RESP_OK_DISPLAY_INFO,
    virtio_gpu_ctrl_type_VIRTIO_GPU_RESP_OK_EDID as VIRTIO_GPU_RESP_OK_EDID,
    virtio_gpu_ctrl_type_VIRTIO_GPU_RESP_OK_MAP_INFO as VIRTIO_GPU_RESP_OK_MAP_INFO,
    virtio_gpu_ctrl_type_VIRTIO_GPU_RESP_OK_NODATA as VIRTIO_GPU_RESP_OK_NODATA,
    virtio_gpu_ctrl_type_VIRTIO_GPU_RESP_OK_RESOURCE_UUID as VIRTIO_GPU_RESP_OK_RESOURCE_UUID,
};
use virtio_queue::{Reader, Writer};
use vm_memory::{ByteValued, GuestAddress, Le32, Le64};

use crate::device::{self, Error};

pub const QUEUE_SIZE: usize = 1024;
pub const NUM_QUEUES: usize = 2;

pub const CONTROL_QUEUE: u16 = 0;
pub const CURSOR_QUEUE: u16 = 1;
pub const POLL_EVENT: u16 = 3;

pub const VIRTIO_GPU_MAX_SCANOUTS: u32 = 16;

/// `CHROMIUM(b/277982577)` success responses
pub const VIRTIO_GPU_RESP_OK_RESOURCE_PLANE_INFO: u32 = 0x11FF;

/// Create a OS-specific handle from guest memory (not upstreamed).
pub const VIRTIO_GPU_BLOB_FLAG_CREATE_GUEST_HANDLE: u32 = 0x0008;

pub const VIRTIO_GPU_FLAG_FENCE: u32 = 1 << 0;
pub const VIRTIO_GPU_FLAG_INFO_RING_IDX: u32 = 1 << 1;

/// Virtio Gpu Configuration
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
#[repr(C)]
pub struct VirtioGpuConfig {
    /// Signals pending events to the driver
    pub events_read: Le32,
    /// Clears pending events in the device
    pub events_clear: Le32,
    /// Maximum number of scanouts supported by the device
    pub num_scanouts: Le32,
    /// Maximum number of capability sets supported by the device
    pub num_capsets: Le32,
}

// SAFETY: The layout of the structure is fixed and can be initialized by
// reading its content from byte array.
unsafe impl ByteValued for VirtioGpuConfig {}

#[derive(Debug, PartialEq, Eq)]
pub struct InvalidCommandType(u32);

impl std::fmt::Display for InvalidCommandType {
    fn fmt(&self, fmt: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(fmt, "Invalid command type {}", self.0)
    }
}

impl From<InvalidCommandType> for crate::device::Error {
    fn from(val: InvalidCommandType) -> Self {
        Self::InvalidCommandType(val.0)
    }
}

impl std::error::Error for InvalidCommandType {}

#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
#[repr(C)]
pub struct virtio_gpu_ctrl_hdr {
    pub type_: Le32,
    pub flags: Le32,
    pub fence_id: Le64,
    pub ctx_id: Le32,
    pub ring_idx: u8,
    pub padding: [u8; 3],
}

// SAFETY: The layout of the structure is fixed and can be initialized by
// reading its content from byte array.
unsafe impl ByteValued for virtio_gpu_ctrl_hdr {}

/// Data passed in the cursor `vq`

#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
#[repr(C)]
pub struct virtio_gpu_cursor_pos {
    pub scanout_id: Le32,
    pub x: Le32,
    pub y: Le32,
    pub padding: Le32,
}

// SAFETY: The layout of the structure is fixed and can be initialized by
// reading its content from byte array.
unsafe impl ByteValued for virtio_gpu_cursor_pos {}

// VIRTIO_GPU_CMD_UPDATE_CURSOR, VIRTIO_GPU_CMD_MOVE_CURSOR
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
#[repr(C)]
pub struct virtio_gpu_update_cursor {
    /// update & move
    pub pos: virtio_gpu_cursor_pos,
    /// update only
    pub resource_id: Le32,
    /// update only
    pub hot_x: Le32,
    /// update only
    pub hot_y: Le32,
    pub padding: Le32,
}

// SAFETY: The layout of the structure is fixed and can be initialized by
// reading its content from byte array.
unsafe impl ByteValued for virtio_gpu_update_cursor {}

/// Data passed in the control `vq`, 2d related

#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
#[repr(C)]
pub struct virtio_gpu_rect {
    pub x: Le32,
    pub y: Le32,
    pub width: Le32,
    pub height: Le32,
}

// SAFETY: The layout of the structure is fixed and can be initialized by
// reading its content from byte array.
unsafe impl ByteValued for virtio_gpu_rect {}

// VIRTIO_GPU_CMD_GET_EDID
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
#[repr(C)]
pub struct virtio_gpu_get_edid {
    pub scanout: Le32,
    pub padding: Le32,
}

// SAFETY: The layout of the structure is fixed and can be initialized by
// reading its content from byte array.
unsafe impl ByteValued for virtio_gpu_get_edid {}

// VIRTIO_GPU_CMD_RESOURCE_UNREF
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
#[repr(C)]
pub struct virtio_gpu_resource_unref {
    pub resource_id: Le32,
    pub padding: Le32,
}

// SAFETY: The layout of the structure is fixed and can be initialized by
// reading its content from byte array.
unsafe impl ByteValued for virtio_gpu_resource_unref {}

// VIRTIO_GPU_CMD_RESOURCE_CREATE_2D: create a 2d resource with a format
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
#[repr(C)]
pub struct virtio_gpu_resource_create_2d {
    pub resource_id: Le32,
    pub format: Le32,
    pub width: Le32,
    pub height: Le32,
}

// SAFETY: The layout of the structure is fixed and can be initialized by
// reading its content from byte array.
unsafe impl ByteValued for virtio_gpu_resource_create_2d {}

// VIRTIO_GPU_CMD_SET_SCANOUT
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
#[repr(C)]
pub struct virtio_gpu_set_scanout {
    pub r: virtio_gpu_rect,
    pub scanout_id: Le32,
    pub resource_id: Le32,
}

// SAFETY: The layout of the structure is fixed and can be initialized by
// reading its content from byte array.
unsafe impl ByteValued for virtio_gpu_set_scanout {}

// VIRTIO_GPU_CMD_RESOURCE_FLUSH
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
#[repr(C)]
pub struct virtio_gpu_resource_flush {
    pub r: virtio_gpu_rect,
    pub resource_id: Le32,
    pub padding: Le32,
}

// SAFETY: The layout of the structure is fixed and can be initialized by
// reading its content from byte array.
unsafe impl ByteValued for virtio_gpu_resource_flush {}

// VIRTIO_GPU_CMD_TRANSFER_TO_HOST_2D: simple transfer to_host
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
#[repr(C)]
pub struct virtio_gpu_transfer_to_host_2d {
    pub r: virtio_gpu_rect,
    pub offset: Le64,
    pub resource_id: Le32,
    pub padding: Le32,
}

// SAFETY: The layout of the structure is fixed and can be initialized by
// reading its content from byte array.
unsafe impl ByteValued for virtio_gpu_transfer_to_host_2d {}

#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
#[repr(C)]
pub struct virtio_gpu_mem_entry {
    pub addr: Le64,
    pub length: Le32,
    pub padding: Le32,
}

// SAFETY: The layout of the structure is fixed and can be initialized by
// reading its content from byte array.
unsafe impl ByteValued for virtio_gpu_mem_entry {}

// VIRTIO_GPU_CMD_RESOURCE_ATTACH_BACKING
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
#[repr(C)]
pub struct virtio_gpu_resource_attach_backing {
    pub resource_id: Le32,
    pub nr_entries: Le32,
}

// SAFETY: The layout of the structure is fixed and can be initialized by
// reading its content from byte array.
unsafe impl ByteValued for virtio_gpu_resource_attach_backing {}

// VIRTIO_GPU_CMD_RESOURCE_DETACH_BACKING
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
#[repr(C)]
pub struct virtio_gpu_resource_detach_backing {
    pub resource_id: Le32,
    pub padding: Le32,
}

// SAFETY: The layout of the structure is fixed and can be initialized by
// reading its content from byte array.
unsafe impl ByteValued for virtio_gpu_resource_detach_backing {}

#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
#[repr(C)]
pub struct virtio_gpu_display_one {
    pub r: virtio_gpu_rect,
    pub enabled: Le32,
    pub flags: Le32,
}

// SAFETY: The layout of the structure is fixed and can be initialized by
// reading its content from byte array.
unsafe impl ByteValued for virtio_gpu_display_one {}

#[derive(Copy, Clone, Debug, Default)]
#[repr(C)]
pub struct virtio_gpu_resp_display_info {
    pub hdr: virtio_gpu_ctrl_hdr,
    pub pmodes: [virtio_gpu_display_one; VIRTIO_GPU_MAX_SCANOUTS as usize],
}

// SAFETY: The layout of the structure is fixed and can be initialized by
// reading its content from byte array.
unsafe impl ByteValued for virtio_gpu_resp_display_info {}

const EDID_BLOB_MAX_SIZE: usize = 1024;

#[derive(Debug, Copy, Clone)]
#[repr(C)]
pub struct virtio_gpu_resp_edid {
    pub hdr: virtio_gpu_ctrl_hdr,
    pub size: Le32,
    pub padding: Le32,
    pub edid: [u8; EDID_BLOB_MAX_SIZE],
}

// SAFETY: The layout of the structure is fixed and can be initialized by
// reading its content from byte array.
unsafe impl ByteValued for virtio_gpu_resp_edid {}

// data passed in the control vq, 3d related

#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
#[repr(C)]
pub struct virtio_gpu_box {
    pub x: Le32,
    pub y: Le32,
    pub z: Le32,
    pub w: Le32,
    pub h: Le32,
    pub d: Le32,
}

// SAFETY: The layout of the structure is fixed and can be initialized by
// reading its content from byte array.
unsafe impl ByteValued for virtio_gpu_box {}

// VIRTIO_GPU_CMD_TRANSFER_TO_HOST_3D, VIRTIO_GPU_CMD_TRANSFER_FROM_HOST_3D
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
#[repr(C)]
pub struct virtio_gpu_transfer_host_3d {
    pub box_: virtio_gpu_box,
    pub offset: Le64,
    pub resource_id: Le32,
    pub level: Le32,
    pub stride: Le32,
    pub layer_stride: Le32,
}

// SAFETY: The layout of the structure is fixed and can be initialized by
// reading its content from byte array.
unsafe impl ByteValued for virtio_gpu_transfer_host_3d {}

// VIRTIO_GPU_CMD_RESOURCE_CREATE_3D
pub const VIRTIO_GPU_RESOURCE_FLAG_Y_0_TOP: u32 = 1 << 0;
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
#[repr(C)]
pub struct virtio_gpu_resource_create_3d {
    pub resource_id: Le32,
    pub target: Le32,
    pub format: Le32,
    pub bind: Le32,
    pub width: Le32,
    pub height: Le32,
    pub depth: Le32,
    pub array_size: Le32,
    pub last_level: Le32,
    pub nr_samples: Le32,
    pub flags: Le32,
    pub padding: Le32,
}

// SAFETY: The layout of the structure is fixed and can be initialized by
// reading its content from byte array.
unsafe impl ByteValued for virtio_gpu_resource_create_3d {}

// VIRTIO_GPU_CMD_CTX_CREATE
pub const VIRTIO_GPU_CONTEXT_INIT_CAPSET_ID_MASK: u32 = 1 << 0;
#[derive(Copy, Clone, PartialEq, Eq)]
#[repr(C)]
pub struct virtio_gpu_ctx_create {
    pub nlen: Le32,
    pub context_init: Le32,
    pub debug_name: [u8; 64],
}

// SAFETY: The layout of the structure is fixed and can be initialized by
// reading its content from byte array.
unsafe impl ByteValued for virtio_gpu_ctx_create {}

impl Default for virtio_gpu_ctx_create {
    fn default() -> Self {
        Self {
            nlen: 0.into(),
            context_init: 0.into(),
            debug_name: [0; 64],
        }
    }
}

impl virtio_gpu_ctx_create {
    pub fn get_debug_name(&self) -> String {
        CStr::from_bytes_with_nul(
            &self.debug_name[..min(64, <Le32 as Into<u32>>::into(self.nlen) as usize)],
        )
        .map_or_else(
            |err| format!("Err({err})"),
            |c_str| c_str.to_string_lossy().into_owned(),
        )
    }
}
impl fmt::Debug for virtio_gpu_ctx_create {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("virtio_gpu_ctx_create")
            .field("debug_name", &self.get_debug_name())
            .field("context_init", &self.context_init)
            .finish_non_exhaustive()
    }
}

// VIRTIO_GPU_CMD_CTX_DESTROY
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
#[repr(C)]
pub struct virtio_gpu_ctx_destroy {}

// SAFETY: The layout of the structure is fixed and can be initialized by
// reading its content from byte array.
unsafe impl ByteValued for virtio_gpu_ctx_destroy {}

// VIRTIO_GPU_CMD_CTX_ATTACH_RESOURCE, VIRTIO_GPU_CMD_CTX_DETACH_RESOURCE
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
#[repr(C)]
pub struct virtio_gpu_ctx_resource {
    pub resource_id: Le32,
    pub padding: Le32,
}

// SAFETY: The layout of the structure is fixed and can be initialized by
// reading its content from byte array.
unsafe impl ByteValued for virtio_gpu_ctx_resource {}

// VIRTIO_GPU_CMD_SUBMIT_3D
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
#[repr(C)]
pub struct virtio_gpu_cmd_submit {
    pub size: Le32,

    // The in-fence IDs are prepended to the cmd_buf and memory layout
    // of the VIRTIO_GPU_CMD_SUBMIT_3D buffer looks like this:
    //   _________________
    //   | CMD_SUBMIT_3D |
    //   -----------------
    //   |  header       |
    //   |  in-fence IDs |
    //   |  cmd_buf      |
    //   -----------------
    //
    // This makes in-fence IDs naturally aligned to the sizeof(u64) inside
    // of the virtio buffer.
    pub num_in_fences: Le32,
}

// SAFETY: The layout of the structure is fixed and can be initialized by
// reading its content from byte array.
unsafe impl ByteValued for virtio_gpu_cmd_submit {}

// VIRTIO_GPU_CMD_GET_CAPSET_INFO
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
#[repr(C)]
pub struct virtio_gpu_get_capset_info {
    pub capset_index: Le32,
    pub padding: Le32,
}

// SAFETY: The layout of the structure is fixed and can be initialized by
// reading its content from byte array.
unsafe impl ByteValued for virtio_gpu_get_capset_info {}

// VIRTIO_GPU_RESP_OK_CAPSET_INFO
#[derive(Copy, Clone, Debug, Default)]
#[repr(C)]
pub struct virtio_gpu_resp_capset_info {
    pub hdr: virtio_gpu_ctrl_hdr,
    pub capset_id: Le32,
    pub capset_max_version: Le32,
    pub capset_max_size: Le32,
    pub padding: Le32,
}

// SAFETY: The layout of the structure is fixed and can be initialized by
// reading its content from byte array.
unsafe impl ByteValued for virtio_gpu_resp_capset_info {}

// VIRTIO_GPU_CMD_GET_CAPSET
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
#[repr(C)]
pub struct virtio_gpu_get_capset {
    pub capset_id: Le32,
    pub capset_version: Le32,
}

// SAFETY: The layout of the structure is fixed and can be initialized by
// reading its content from byte array.
unsafe impl ByteValued for virtio_gpu_get_capset {}

// VIRTIO_GPU_RESP_OK_CAPSET
#[derive(Copy, Clone, Debug, Default)]
#[repr(C)]
pub struct virtio_gpu_resp_capset {
    pub hdr: virtio_gpu_ctrl_hdr,
    pub capset_data: PhantomData<[u8]>,
}

// SAFETY: The layout of the structure is fixed and can be initialized by
// reading its content from byte array.
unsafe impl ByteValued for virtio_gpu_resp_capset {}

// VIRTIO_GPU_RESP_OK_RESOURCE_PLANE_INFO
#[derive(Copy, Clone, Debug, Default)]
#[repr(C)]
pub struct virtio_gpu_resp_resource_plane_info {
    pub hdr: virtio_gpu_ctrl_hdr,
    pub count: Le32,
    pub padding: Le32,
    pub format_modifier: Le64,
    pub strides: [Le32; 4],
    pub offsets: [Le32; 4],
}

// SAFETY: The layout of the structure is fixed and can be initialized by
// reading its content from byte array.
unsafe impl ByteValued for virtio_gpu_resp_resource_plane_info {}

pub const PLANE_INFO_MAX_COUNT: usize = 4;

pub const VIRTIO_GPU_EVENT_DISPLAY: u32 = 1 << 0;

#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
#[repr(C)]
pub struct virtio_gpu_resource_create_blob {
    pub resource_id: Le32,
    pub blob_mem: Le32,
    pub blob_flags: Le32,
    pub nr_entries: Le32,
    pub blob_id: Le64,
    pub size: Le64,
}

// SAFETY: The layout of the structure is fixed and can be initialized by
// reading its content from byte array.
unsafe impl ByteValued for virtio_gpu_resource_create_blob {}

#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
#[repr(C)]
pub struct virtio_gpu_resource_map_blob {
    pub resource_id: Le32,
    pub padding: Le32,
    pub offset: Le64,
}

// SAFETY: The layout of the structure is fixed and can be initialized by
// reading its content from byte array.
unsafe impl ByteValued for virtio_gpu_resource_map_blob {}

#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
#[repr(C)]
pub struct virtio_gpu_resource_unmap_blob {
    pub resource_id: Le32,
    pub padding: Le32,
}

// SAFETY: The layout of the structure is fixed and can be initialized by
// reading its content from byte array.
unsafe impl ByteValued for virtio_gpu_resource_unmap_blob {}

#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
#[repr(C)]
pub struct virtio_gpu_resp_map_info {
    pub hdr: virtio_gpu_ctrl_hdr,
    pub map_info: Le32,
    pub padding: Le32,
}

// SAFETY: The layout of the structure is fixed and can be initialized by
// reading its content from byte array.
unsafe impl ByteValued for virtio_gpu_resp_map_info {}

#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
#[repr(C)]
pub struct virtio_gpu_resource_assign_uuid {
    pub resource_id: Le32,
    pub padding: Le32,
}

// SAFETY: The layout of the structure is fixed and can be initialized by
// reading its content from byte array.
unsafe impl ByteValued for virtio_gpu_resource_assign_uuid {}

#[derive(Copy, Clone, Debug, Default)]
#[repr(C)]
pub struct virtio_gpu_resp_resource_uuid {
    pub hdr: virtio_gpu_ctrl_hdr,
    pub uuid: [u8; 16],
}

// SAFETY: The layout of the structure is fixed and can be initialized by
// reading its content from byte array.
unsafe impl ByteValued for virtio_gpu_resp_resource_uuid {}

// VIRTIO_GPU_CMD_SET_SCANOUT_BLOB
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
#[repr(C)]
pub struct virtio_gpu_set_scanout_blob {
    pub r: virtio_gpu_rect,
    pub scanout_id: Le32,
    pub resource_id: Le32,
    pub width: Le32,
    pub height: Le32,
    pub format: Le32,
    pub padding: Le32,
    pub strides: [Le32; 4],
    pub offsets: [Le32; 4],
}

// SAFETY: The layout of the structure is fixed and can be initialized by
// reading its content from byte array.
unsafe impl ByteValued for virtio_gpu_set_scanout_blob {}

// simple formats for fbcon/X use
pub const VIRTIO_GPU_FORMAT_B8G8R8A8_UNORM: u32 = 1;
pub const VIRTIO_GPU_FORMAT_B8G8R8X8_UNORM: u32 = 2;
pub const VIRTIO_GPU_FORMAT_A8R8G8B8_UNORM: u32 = 3;
pub const VIRTIO_GPU_FORMAT_X8R8G8B8_UNORM: u32 = 4;
pub const VIRTIO_GPU_FORMAT_R8G8B8A8_UNORM: u32 = 67;
pub const VIRTIO_GPU_FORMAT_X8B8G8R8_UNORM: u32 = 68;
pub const VIRTIO_GPU_FORMAT_A8B8G8R8_UNORM: u32 = 121;
pub const VIRTIO_GPU_FORMAT_R8G8B8X8_UNORM: u32 = 134;

/// A virtio gpu command and associated metadata specific to each command.
#[derive(Clone, PartialEq, Eq)]
pub enum GpuCommand {
    GetDisplayInfo,
    GetEdid(virtio_gpu_get_edid),
    ResourceCreate2d(virtio_gpu_resource_create_2d),
    ResourceUnref(virtio_gpu_resource_unref),
    SetScanout(virtio_gpu_set_scanout),
    SetScanoutBlob(virtio_gpu_set_scanout_blob),
    ResourceFlush(virtio_gpu_resource_flush),
    TransferToHost2d(virtio_gpu_transfer_to_host_2d),
    ResourceAttachBacking(
        virtio_gpu_resource_attach_backing,
        Vec<(GuestAddress, usize)>,
    ),
    ResourceDetachBacking(virtio_gpu_resource_detach_backing),
    GetCapsetInfo(virtio_gpu_get_capset_info),
    GetCapset(virtio_gpu_get_capset),
    CtxCreate(virtio_gpu_ctx_create),
    CtxDestroy(virtio_gpu_ctx_destroy),
    CtxAttachResource(virtio_gpu_ctx_resource),
    CtxDetachResource(virtio_gpu_ctx_resource),
    ResourceCreate3d(virtio_gpu_resource_create_3d),
    TransferToHost3d(virtio_gpu_transfer_host_3d),
    TransferFromHost3d(virtio_gpu_transfer_host_3d),
    CmdSubmit3d {
        cmd_data: Vec<u8>,
        fence_ids: Vec<u64>,
    },
    ResourceCreateBlob(virtio_gpu_resource_create_blob),
    ResourceMapBlob(virtio_gpu_resource_map_blob),
    ResourceUnmapBlob(virtio_gpu_resource_unmap_blob),
    UpdateCursor(virtio_gpu_update_cursor),
    MoveCursor(virtio_gpu_update_cursor),
    ResourceAssignUuid(virtio_gpu_resource_assign_uuid),
}

/// An error indicating something went wrong decoding a `GpuCommand`. These
/// correspond to `VIRTIO_GPU_CMD_*`.
#[derive(Error, Debug)]
pub enum GpuCommandDecodeError {
    /// The type of the command was invalid.
    #[error("invalid command type ({0})")]
    InvalidType(u32),
    /// An I/O error occurred.
    #[error("an I/O error occurred: {0}")]
    IO(io::Error),
    #[error("Descriptor read failed")]
    DescriptorReadFailed,
}

impl From<io::Error> for GpuCommandDecodeError {
    fn from(e: io::Error) -> Self {
        Self::IO(e)
    }
}

impl From<device::Error> for GpuCommandDecodeError {
    fn from(_: device::Error) -> Self {
        Self::DescriptorReadFailed
    }
}

impl From<device::Error> for GpuResponseEncodeError {
    fn from(_: device::Error) -> Self {
        Self::DescriptorWriteFailed
    }
}

impl fmt::Debug for GpuCommand {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct(self.command_name()).finish()
    }
}

impl GpuCommand {
    pub const fn command_name(&self) -> &'static str {
        use GpuCommand::*;
        match self {
            GetDisplayInfo => "GetDisplayInfo",
            GetEdid(_info) => "GetEdid",
            ResourceCreate2d(_info) => "ResourceCreate2d",
            ResourceUnref(_info) => "ResourceUnref",
            SetScanout(_info) => "SetScanout",
            SetScanoutBlob(_info) => "SetScanoutBlob",
            ResourceFlush(_info) => "ResourceFlush",
            TransferToHost2d(_info) => "TransferToHost2d",
            ResourceAttachBacking(_info, _vecs) => "ResourceAttachBacking",
            ResourceDetachBacking(_info) => "ResourceDetachBacking",
            GetCapsetInfo(_info) => "GetCapsetInfo",
            GetCapset(_info) => "GetCapset",
            CtxCreate(_info) => "CtxCreate",
            CtxDestroy(_info) => "CtxDestroy",
            CtxAttachResource(_info) => "CtxAttachResource",
            CtxDetachResource(_info) => "CtxDetachResource",
            ResourceCreate3d(_info) => "ResourceCreate3d",
            TransferToHost3d(_info) => "TransferToHost3d",
            TransferFromHost3d(_info) => "TransferFromHost3d",
            CmdSubmit3d { .. } => "CmdSubmit3d",
            ResourceCreateBlob(_info) => "ResourceCreateBlob",
            ResourceMapBlob(_info) => "ResourceMapBlob",
            ResourceUnmapBlob(_info) => "ResourceUnmapBlob",
            UpdateCursor(_info) => "UpdateCursor",
            MoveCursor(_info) => "MoveCursor",
            ResourceAssignUuid(_info) => "ResourceAssignUuid",
        }
    }

    /// Decodes a command from the given chunk of memory.
    pub fn decode(
        reader: &mut Reader,
    ) -> Result<(virtio_gpu_ctrl_hdr, Self), GpuCommandDecodeError> {
        use self::GpuCommand::*;
        let hdr = reader
            .read_obj::<virtio_gpu_ctrl_hdr>()
            .map_err(|_| Error::DescriptorReadFailed)?;
        trace!(
            "Decoding GpuCommand 0x{:0x}",
            <Le32 as Into<u32>>::into(hdr.type_)
        );
        let cmd = match hdr.type_.into() {
            VIRTIO_GPU_CMD_GET_DISPLAY_INFO => GetDisplayInfo,
            VIRTIO_GPU_CMD_GET_EDID => {
                GetEdid(reader.read_obj().map_err(|_| Error::DescriptorReadFailed)?)
            }
            VIRTIO_GPU_CMD_RESOURCE_CREATE_2D => {
                ResourceCreate2d(reader.read_obj().map_err(|_| Error::DescriptorReadFailed)?)
            }
            VIRTIO_GPU_CMD_RESOURCE_UNREF => {
                ResourceUnref(reader.read_obj().map_err(|_| Error::DescriptorReadFailed)?)
            }
            VIRTIO_GPU_CMD_SET_SCANOUT => {
                SetScanout(reader.read_obj().map_err(|_| Error::DescriptorReadFailed)?)
            }
            VIRTIO_GPU_CMD_SET_SCANOUT_BLOB => {
                SetScanoutBlob(reader.read_obj().map_err(|_| Error::DescriptorReadFailed)?)
            }
            VIRTIO_GPU_CMD_RESOURCE_FLUSH => {
                ResourceFlush(reader.read_obj().map_err(|_| Error::DescriptorReadFailed)?)
            }
            VIRTIO_GPU_CMD_TRANSFER_TO_HOST_2D => {
                TransferToHost2d(reader.read_obj().map_err(|_| Error::DescriptorReadFailed)?)
            }
            VIRTIO_GPU_CMD_RESOURCE_ATTACH_BACKING => {
                let info: virtio_gpu_resource_attach_backing =
                    reader.read_obj().map_err(|_| Error::DescriptorReadFailed)?;
                let mut entries =
                    Vec::with_capacity(<Le32 as Into<u32>>::into(info.nr_entries) as usize);
                for _ in 0..info.nr_entries.into() {
                    let entry: virtio_gpu_mem_entry =
                        reader.read_obj().map_err(|_| Error::DescriptorReadFailed)?;
                    entries.push((
                        GuestAddress(entry.addr.into()),
                        <Le32 as Into<u32>>::into(entry.length) as usize,
                    ));
                }
                ResourceAttachBacking(info, entries)
            }
            VIRTIO_GPU_CMD_RESOURCE_DETACH_BACKING => {
                ResourceDetachBacking(reader.read_obj().map_err(|_| Error::DescriptorReadFailed)?)
            }
            VIRTIO_GPU_CMD_GET_CAPSET_INFO => {
                GetCapsetInfo(reader.read_obj().map_err(|_| Error::DescriptorReadFailed)?)
            }
            VIRTIO_GPU_CMD_GET_CAPSET => {
                GetCapset(reader.read_obj().map_err(|_| Error::DescriptorReadFailed)?)
            }
            VIRTIO_GPU_CMD_CTX_CREATE => {
                CtxCreate(reader.read_obj().map_err(|_| Error::DescriptorReadFailed)?)
            }
            VIRTIO_GPU_CMD_CTX_DESTROY => {
                CtxDestroy(reader.read_obj().map_err(|_| Error::DescriptorReadFailed)?)
            }
            VIRTIO_GPU_CMD_CTX_ATTACH_RESOURCE => {
                CtxAttachResource(reader.read_obj().map_err(|_| Error::DescriptorReadFailed)?)
            }
            VIRTIO_GPU_CMD_CTX_DETACH_RESOURCE => {
                CtxDetachResource(reader.read_obj().map_err(|_| Error::DescriptorReadFailed)?)
            }
            VIRTIO_GPU_CMD_RESOURCE_CREATE_3D => {
                ResourceCreate3d(reader.read_obj().map_err(|_| Error::DescriptorReadFailed)?)
            }
            VIRTIO_GPU_CMD_TRANSFER_TO_HOST_3D => {
                TransferToHost3d(reader.read_obj().map_err(|_| Error::DescriptorReadFailed)?)
            }
            VIRTIO_GPU_CMD_TRANSFER_FROM_HOST_3D => {
                TransferFromHost3d(reader.read_obj().map_err(|_| Error::DescriptorReadFailed)?)
            }
            VIRTIO_GPU_CMD_SUBMIT_3D => {
                let info: virtio_gpu_cmd_submit =
                    reader.read_obj().map_err(|_| Error::DescriptorReadFailed)?;

                let mut cmd_data = vec![0; <Le32 as Into<u32>>::into(info.size) as usize];
                let mut fence_ids: Vec<u64> =
                    Vec::with_capacity(<Le32 as Into<u32>>::into(info.num_in_fences) as usize);

                for _ in 0..info.num_in_fences.into() {
                    let fence_id = reader
                        .read_obj::<u64>()
                        .map_err(|_| Error::DescriptorReadFailed)?;
                    fence_ids.push(fence_id);
                }

                reader
                    .read_exact(&mut cmd_data[..])
                    .map_err(|_| Error::DescriptorReadFailed)?;

                CmdSubmit3d {
                    cmd_data,
                    fence_ids,
                }
            }
            VIRTIO_GPU_CMD_RESOURCE_CREATE_BLOB => {
                ResourceCreateBlob(reader.read_obj().map_err(|_| Error::DescriptorReadFailed)?)
            }
            VIRTIO_GPU_CMD_RESOURCE_MAP_BLOB => {
                ResourceMapBlob(reader.read_obj().map_err(|_| Error::DescriptorReadFailed)?)
            }
            VIRTIO_GPU_CMD_RESOURCE_UNMAP_BLOB => {
                ResourceUnmapBlob(reader.read_obj().map_err(|_| Error::DescriptorReadFailed)?)
            }
            VIRTIO_GPU_CMD_UPDATE_CURSOR => {
                UpdateCursor(reader.read_obj().map_err(|_| Error::DescriptorReadFailed)?)
            }
            VIRTIO_GPU_CMD_MOVE_CURSOR => {
                MoveCursor(reader.read_obj().map_err(|_| Error::DescriptorReadFailed)?)
            }
            VIRTIO_GPU_CMD_RESOURCE_ASSIGN_UUID => {
                ResourceAssignUuid(reader.read_obj().map_err(|_| Error::DescriptorReadFailed)?)
            }
            _ => return Err(GpuCommandDecodeError::InvalidType(hdr.type_.into())),
        };

        Ok((hdr, cmd))
    }
}

#[derive(Debug, PartialEq, Eq)]
pub struct GpuResponsePlaneInfo {
    pub stride: u32,
    pub offset: u32,
}

/// A response to a `GpuCommand`. These correspond to `VIRTIO_GPU_RESP_*`.
#[derive(Debug)]
pub enum GpuResponse {
    OkNoData,
    OkDisplayInfo(Vec<(u32, u32, bool)>),
    OkEdid {
        /// The EDID display data blob (as specified by VESA)
        blob: Box<[u8]>,
    },
    OkCapsetInfo {
        capset_id: u32,
        version: u32,
        size: u32,
    },
    OkCapset(Vec<u8>),
    OkResourcePlaneInfo {
        format_modifier: u64,
        plane_info: Vec<GpuResponsePlaneInfo>,
    },
    OkResourceUuid {
        uuid: [u8; 16],
    },
    OkMapInfo {
        map_info: u32,
    },
    ErrUnspec,
    ErrRutabaga(RutabagaError),
    ErrScanout {
        num_scanouts: u32,
    },
    ErrOutOfMemory,
    ErrInvalidScanoutId,
    ErrInvalidResourceId,
    ErrInvalidContextId,
    ErrInvalidParameter,
}

impl From<RutabagaError> for GpuResponse {
    fn from(e: RutabagaError) -> Self {
        Self::ErrRutabaga(e)
    }
}

impl Display for GpuResponse {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use self::GpuResponse::{ErrRutabaga, ErrScanout};
        match self {
            ErrRutabaga(e) => write!(f, "renderer error: {e}"),
            ErrScanout { num_scanouts } => write!(f, "non-zero scanout: {num_scanouts}"),
            _ => Ok(()),
        }
    }
}

/// An error indicating something went wrong decoding a `GpuCommand`.
#[derive(Error, Debug)]
pub enum GpuResponseEncodeError {
    /// An I/O error occurred.
    #[error("an I/O error occurred: {0}")]
    IO(io::Error),
    /// Size conversion failed
    #[error("Size conversion failed")]
    SizeOverflow,
    /// More displays than are valid were in a `OkDisplayInfo`.
    #[error("{0} is more displays than are valid")]
    TooManyDisplays(usize),
    /// More planes than are valid were in a `OkResourcePlaneInfo`.
    #[error("{0} is more planes than are valid")]
    TooManyPlanes(usize),
    #[error("Descriptor write failed")]
    DescriptorWriteFailed,
}

impl From<io::Error> for GpuResponseEncodeError {
    fn from(e: io::Error) -> Self {
        Self::IO(e)
    }
}

pub type VirtioGpuResult = std::result::Result<GpuResponse, GpuResponse>;

impl GpuResponse {
    /// Encodes a this `GpuResponse` into `resp` and the given set of metadata.
    pub fn encode(
        &self,
        flags: u32,
        fence_id: u64,
        ctx_id: u32,
        ring_idx: u8,
        writer: &mut Writer,
    ) -> Result<u32, GpuResponseEncodeError> {
        let hdr = virtio_gpu_ctrl_hdr {
            type_: self.get_type().into(),
            flags: flags.into(),
            fence_id: fence_id.into(),
            ctx_id: ctx_id.into(),
            ring_idx,
            padding: Default::default(),
        };
        let len = match *self {
            Self::OkDisplayInfo(ref info) => {
                if info.len() > VIRTIO_GPU_MAX_SCANOUTS as usize {
                    return Err(GpuResponseEncodeError::TooManyDisplays(info.len()));
                }
                let mut disp_info = virtio_gpu_resp_display_info {
                    hdr,
                    pmodes: Default::default(),
                };
                for (disp_mode, &(width, height, enabled)) in disp_info.pmodes.iter_mut().zip(info)
                {
                    disp_mode.r.width = width.into();
                    disp_mode.r.height = height.into();
                    disp_mode.enabled = u32::from(enabled).into();
                }
                writer
                    .write_obj(disp_info)
                    .map_err(|_| Error::DescriptorWriteFailed)?;
                size_of_val(&disp_info)
            }
            Self::OkEdid { ref blob } => {
                let Ok(size) = u32::try_from(blob.len()) else {
                    return Err(GpuResponseEncodeError::SizeOverflow);
                };
                let mut edid_info = virtio_gpu_resp_edid {
                    hdr,
                    size: size.into(),
                    edid: [0; EDID_BLOB_MAX_SIZE],
                    padding: Le32::default(),
                };
                edid_info.edid.copy_from_slice(blob);
                writer
                    .write_obj(edid_info)
                    .map_err(|_| Error::DescriptorWriteFailed)?;
                size_of_val(&edid_info)
            }
            Self::OkCapsetInfo {
                capset_id,
                version,
                size,
            } => {
                writer
                    .write_obj(virtio_gpu_resp_capset_info {
                        hdr,
                        capset_id: capset_id.into(),
                        capset_max_version: version.into(),
                        capset_max_size: size.into(),
                        padding: 0u32.into(),
                    })
                    .map_err(|_| Error::DescriptorWriteFailed)?;
                size_of::<virtio_gpu_resp_capset_info>()
            }
            Self::OkCapset(ref data) => {
                writer
                    .write_obj(hdr)
                    .map_err(|_| Error::DescriptorWriteFailed)?;
                writer
                    .write(data)
                    .map_err(|_| Error::DescriptorWriteFailed)?;
                size_of_val(&hdr) + data.len()
            }
            Self::OkResourcePlaneInfo {
                format_modifier,
                ref plane_info,
            } => {
                if plane_info.len() > PLANE_INFO_MAX_COUNT {
                    return Err(GpuResponseEncodeError::TooManyPlanes(plane_info.len()));
                }
                let mut strides = [Le32::default(); PLANE_INFO_MAX_COUNT];
                let mut offsets = [Le32::default(); PLANE_INFO_MAX_COUNT];
                for (plane_index, plane) in plane_info.iter().enumerate() {
                    strides[plane_index] = plane.stride.into();
                    offsets[plane_index] = plane.offset.into();
                }
                let Ok(count) = u32::try_from(plane_info.len()) else {
                    return Err(GpuResponseEncodeError::SizeOverflow);
                };
                let plane_info = virtio_gpu_resp_resource_plane_info {
                    hdr,
                    count: count.into(),
                    padding: 0u32.into(),
                    format_modifier: format_modifier.into(),
                    strides,
                    offsets,
                };
                if writer.available_bytes() >= size_of_val(&plane_info) {
                    size_of_val(&plane_info)
                } else {
                    // In case there is too little room in the response slice to store the
                    // entire virtio_gpu_resp_resource_plane_info, convert response to a regular
                    // VIRTIO_GPU_RESP_OK_NODATA and attempt to return that.
                    writer
                        .write_obj(virtio_gpu_ctrl_hdr {
                            type_: Le32::from(VIRTIO_GPU_RESP_OK_NODATA),
                            ..hdr
                        })
                        .map_err(|_| Error::DescriptorWriteFailed)?;
                    size_of_val(&hdr)
                }
            }
            Self::OkResourceUuid { uuid } => {
                let resp_info = virtio_gpu_resp_resource_uuid { hdr, uuid };

                writer
                    .write_obj(resp_info)
                    .map_err(|_| Error::DescriptorWriteFailed)?;
                size_of_val(&resp_info)
            }
            Self::OkMapInfo { map_info } => {
                let resp_info = virtio_gpu_resp_map_info {
                    hdr,
                    map_info: map_info.into(),
                    padding: Le32::default(),
                };

                writer
                    .write_obj(resp_info)
                    .map_err(|_| Error::DescriptorWriteFailed)?;
                size_of_val(&resp_info)
            }
            _ => {
                writer
                    .write_obj(hdr)
                    .map_err(|_| Error::DescriptorWriteFailed)?;
                size_of_val(&hdr)
            }
        };
        let len = u32::try_from(len).map_err(|_| GpuResponseEncodeError::SizeOverflow)?;

        Ok(len)
    }

    /// Gets the `VIRTIO_GPU_*` enum value that corresponds to this variant.
    pub const fn get_type(&self) -> u32 {
        match self {
            Self::OkNoData => VIRTIO_GPU_RESP_OK_NODATA,
            Self::OkDisplayInfo(_) => VIRTIO_GPU_RESP_OK_DISPLAY_INFO,
            Self::OkEdid { .. } => VIRTIO_GPU_RESP_OK_EDID,
            Self::OkCapsetInfo { .. } => VIRTIO_GPU_RESP_OK_CAPSET_INFO,
            Self::OkCapset(_) => VIRTIO_GPU_RESP_OK_CAPSET,
            Self::OkResourcePlaneInfo { .. } => VIRTIO_GPU_RESP_OK_RESOURCE_PLANE_INFO,
            Self::OkResourceUuid { .. } => VIRTIO_GPU_RESP_OK_RESOURCE_UUID,
            Self::OkMapInfo { .. } => VIRTIO_GPU_RESP_OK_MAP_INFO,
            Self::ErrUnspec | Self::ErrRutabaga(_) | Self::ErrScanout { .. } => {
                VIRTIO_GPU_RESP_ERR_UNSPEC
            }
            Self::ErrOutOfMemory => VIRTIO_GPU_RESP_ERR_OUT_OF_MEMORY,
            Self::ErrInvalidScanoutId => VIRTIO_GPU_RESP_ERR_INVALID_SCANOUT_ID,
            Self::ErrInvalidResourceId => VIRTIO_GPU_RESP_ERR_INVALID_RESOURCE_ID,
            Self::ErrInvalidContextId => VIRTIO_GPU_RESP_ERR_INVALID_CONTEXT_ID,
            Self::ErrInvalidParameter => VIRTIO_GPU_RESP_ERR_INVALID_PARAMETER,
        }
    }
}

#[cfg(test)]
mod tests {
    use virtio_bindings::virtio_ring::VRING_DESC_F_WRITE;
    use virtio_queue::{
        desc::{split::Descriptor as SplitDescriptor, RawDescriptor},
        mock::MockSplitQueue,
    };
    use vm_memory::GuestMemoryMmap;

    use super::*;

    #[test]
    fn test_virtio_gpu_config() {
        // Test VirtioGpuConfig size
        assert_eq!(std::mem::size_of::<VirtioGpuConfig>(), 16);
    }

    #[test]
    fn test_invalid_command_type_display() {
        let error = InvalidCommandType(42);
        assert_eq!(format!("{error}"), "Invalid command type 42");
    }

    #[test]
    fn test_gpu_response_display() {
        let err_rutabaga = GpuResponse::ErrRutabaga(RutabagaError::InvalidContextId);
        assert_eq!(
            format!("{err_rutabaga}"),
            "renderer error: invalid context id"
        );

        let err_scanout = GpuResponse::ErrScanout { num_scanouts: 3 };
        assert_eq!(format!("{err_scanout}"), "non-zero scanout: 3");
    }

    #[test]
    fn test_invalid_type_error() {
        let error = GpuCommandDecodeError::InvalidType(42);
        assert_eq!(format!("{error}"), "invalid command type (42)");
    }

    // Test io_error conversion to gpu command decode error
    #[test]
    fn test_io_error() {
        let io_error = io::Error::new(io::ErrorKind::Other, "Test IO error");
        let gpu_error: GpuCommandDecodeError = io_error.into();
        match gpu_error {
            GpuCommandDecodeError::IO(_) => (),
            _ => panic!("Expected IO error"),
        }
    }

    //Test vhu_error conversion to gpu command decode/encode error
    #[test]
    fn test_device_error() {
        let device_error = device::Error::DescriptorReadFailed;
        let gpu_error: GpuCommandDecodeError = device_error.into();
        match gpu_error {
            GpuCommandDecodeError::DescriptorReadFailed => (),
            _ => panic!("Expected DescriptorReadFailed error"),
        }
        let device_error = device::Error::DescriptorWriteFailed;
        let gpu_error: GpuResponseEncodeError = device_error.into();
        match gpu_error {
            GpuResponseEncodeError::DescriptorWriteFailed => (),
            _ => panic!("Expected DescriptorWriteFailed error"),
        }
    }

    #[test]
    fn test_gpu_command_debug() {
        use GpuCommand::*;

        let test_cases = vec![
            (GetDisplayInfo, "GetDisplayInfo"),
            (GetEdid(virtio_gpu_get_edid::default()), "GetEdid"),
            (
                ResourceCreate2d(virtio_gpu_resource_create_2d::default()),
                "ResourceCreate2d",
            ),
            (
                ResourceUnref(virtio_gpu_resource_unref::default()),
                "ResourceUnref",
            ),
            (SetScanout(virtio_gpu_set_scanout::default()), "SetScanout"),
            (
                SetScanoutBlob(virtio_gpu_set_scanout_blob::default()),
                "SetScanoutBlob",
            ),
            (
                ResourceFlush(virtio_gpu_resource_flush::default()),
                "ResourceFlush",
            ),
            (
                TransferToHost2d(virtio_gpu_transfer_to_host_2d::default()),
                "TransferToHost2d",
            ),
            (
                ResourceDetachBacking(virtio_gpu_resource_detach_backing::default()),
                "ResourceDetachBacking",
            ),
            (
                GetCapsetInfo(virtio_gpu_get_capset_info::default()),
                "GetCapsetInfo",
            ),
            (GetCapset(virtio_gpu_get_capset::default()), "GetCapset"),
            (CtxCreate(virtio_gpu_ctx_create::default()), "CtxCreate"),
            (CtxDestroy(virtio_gpu_ctx_destroy::default()), "CtxDestroy"),
            (
                CtxAttachResource(virtio_gpu_ctx_resource::default()),
                "CtxAttachResource",
            ),
            (
                CtxDetachResource(virtio_gpu_ctx_resource::default()),
                "CtxDetachResource",
            ),
            (
                ResourceCreate3d(virtio_gpu_resource_create_3d::default()),
                "ResourceCreate3d",
            ),
            (
                TransferToHost3d(virtio_gpu_transfer_host_3d::default()),
                "TransferToHost3d",
            ),
            (
                TransferFromHost3d(virtio_gpu_transfer_host_3d::default()),
                "TransferFromHost3d",
            ),
            (
                CmdSubmit3d {
                    cmd_data: Vec::new(),
                    fence_ids: Vec::new(),
                },
                "CmdSubmit3d",
            ),
            (
                ResourceCreateBlob(virtio_gpu_resource_create_blob::default()),
                "ResourceCreateBlob",
            ),
            (
                ResourceMapBlob(virtio_gpu_resource_map_blob::default()),
                "ResourceMapBlob",
            ),
            (
                ResourceUnmapBlob(virtio_gpu_resource_unmap_blob::default()),
                "ResourceUnmapBlob",
            ),
            (
                UpdateCursor(virtio_gpu_update_cursor::default()),
                "UpdateCursor",
            ),
            (
                MoveCursor(virtio_gpu_update_cursor::default()),
                "MoveCursor",
            ),
            (
                ResourceAssignUuid(virtio_gpu_resource_assign_uuid::default()),
                "ResourceAssignUuid",
            ),
        ];

        for (command, expected) in test_cases {
            assert_eq!(format!("{command:?}"), expected);
        }
    }

    #[test]
    fn test_virtio_gpu_ctx_create_debug() {
        let bytes = b"test_debug\0";
        let original = virtio_gpu_ctx_create {
            debug_name: {
                let mut debug_name = [0; 64];
                debug_name[..bytes.len()].copy_from_slice(bytes);
                debug_name
            },
            context_init: 0.into(),
            nlen: (bytes.len() as u32).into(),
        };

        let debug_string = format!("{original:?}");
        assert_eq!(
            debug_string,
            "virtio_gpu_ctx_create { debug_name: \"test_debug\", context_init: Le32(0), .. }"
        );
    }

    #[test]
    fn test_gpu_response_encode() {
        let mem = GuestMemoryMmap::<()>::from_ranges(&[(GuestAddress(0), 16384)]).unwrap();

        let vq = MockSplitQueue::new(&mem, 8);
        let desc_chain = vq
            .build_desc_chain(&[RawDescriptor::from(SplitDescriptor::new(
                0x1000,
                8192,
                VRING_DESC_F_WRITE as u16,
                0,
            ))])
            .unwrap();

        let mut writer = desc_chain
            .clone()
            .writer(&mem)
            .map_err(Error::CreateWriter)
            .unwrap();

        let resp = GpuResponse::OkNoData;
        let resp_ok_nodata = GpuResponse::encode(&resp, 0, 0, 0, 0, &mut writer).unwrap();
        assert_eq!(resp_ok_nodata, 24);

        let resp = GpuResponse::OkDisplayInfo(vec![(0, 0, false)]);
        let resp_display_info = GpuResponse::encode(&resp, 0, 0, 0, 0, &mut writer).unwrap();
        assert_eq!(resp_display_info, 408);

        let edid_data: Box<[u8]> = Box::new([0u8; 1024]);
        let resp = GpuResponse::OkEdid { blob: edid_data };
        let resp_edid = GpuResponse::encode(&resp, 0, 0, 0, 0, &mut writer).unwrap();
        assert_eq!(resp_edid, 1056);

        let resp = GpuResponse::OkCapset(vec![]);
        let resp_capset = GpuResponse::encode(&resp, 0, 0, 0, 0, &mut writer).unwrap();
        assert_eq!(resp_capset, 24);

        let resp = GpuResponse::OkCapsetInfo {
            capset_id: 0,
            version: 0,
            size: 0,
        };
        let resp_capset = GpuResponse::encode(&resp, 0, 0, 0, 0, &mut writer).unwrap();
        assert_eq!(resp_capset, 40);

        let resp = GpuResponse::OkResourcePlaneInfo {
            format_modifier: 0,
            plane_info: vec![],
        };
        let resp_resource_planeinfo = GpuResponse::encode(&resp, 0, 0, 0, 0, &mut writer).unwrap();
        assert_eq!(resp_resource_planeinfo, 72);

        let resp = GpuResponse::OkResourceUuid { uuid: [0u8; 16] };
        let resp_resource_uuid = GpuResponse::encode(&resp, 0, 0, 0, 0, &mut writer).unwrap();
        assert_eq!(resp_resource_uuid, 40);

        let resp = GpuResponse::OkMapInfo { map_info: 0 };
        let resp_map_info = GpuResponse::encode(&resp, 0, 0, 0, 0, &mut writer).unwrap();
        assert_eq!(resp_map_info, 32);
    }
}
