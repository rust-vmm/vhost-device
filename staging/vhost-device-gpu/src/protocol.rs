// Copyright 2024 Red Hat Inc
// Copyright 2019 The ChromiumOS Authors
//
// SPDX-License-Identifier: Apache-2.0 or BSD-3-Clause

#![allow(non_camel_case_types)]

use log::trace;
use std::{
    cmp::min,
    convert::From,
    ffi::CStr,
    fmt::{self, Display},
    io::{self, Read, Write},
    marker::PhantomData,
    mem::{size_of, size_of_val},
};

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
use vm_memory::{ByteValued, GuestAddress, Le32};
use zerocopy::{AsBytes, FromBytes};

use crate::device::{self, Error};

pub const QUEUE_SIZE: usize = 1024;
pub const NUM_QUEUES: usize = 2;

pub const CONTROL_QUEUE: u16 = 0;
pub const CURSOR_QUEUE: u16 = 1;
pub const POLL_EVENT: u16 = NUM_QUEUES as u16 + 1;

pub const VIRTIO_GPU_MAX_SCANOUTS: usize = 16;

/* CHROMIUM(b/277982577): success responses */
pub const VIRTIO_GPU_RESP_OK_RESOURCE_PLANE_INFO: u32 = 0x11FF;

/* Create a OS-specific handle from guest memory (not upstreamed). */
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

#[derive(Copy, Clone, Debug, Default, AsBytes, FromBytes, PartialEq, Eq)]
#[repr(C)]
pub struct virtio_gpu_ctrl_hdr {
    pub type_: u32,
    pub flags: u32,
    pub fence_id: u64,
    pub ctx_id: u32,
    pub ring_idx: u8,
    pub padding: [u8; 3],
}
unsafe impl ByteValued for virtio_gpu_ctrl_hdr {}

/* data passed in the cursor vq */

#[derive(Copy, Clone, Debug, Default, FromBytes, AsBytes, PartialEq, Eq)]
#[repr(C)]
pub struct virtio_gpu_cursor_pos {
    pub scanout_id: u32,
    pub x: u32,
    pub y: u32,
    pub padding: u32,
}
unsafe impl ByteValued for virtio_gpu_cursor_pos {}

/* VIRTIO_GPU_CMD_UPDATE_CURSOR, VIRTIO_GPU_CMD_MOVE_CURSOR */
#[derive(Copy, Clone, Debug, Default, FromBytes, AsBytes, PartialEq, Eq)]
#[repr(C)]
pub struct virtio_gpu_update_cursor {
    pub pos: virtio_gpu_cursor_pos, /* update & move */
    pub resource_id: u32,           /* update only */
    pub hot_x: u32,                 /* update only */
    pub hot_y: u32,                 /* update only */
    pub padding: u32,
}
unsafe impl ByteValued for virtio_gpu_update_cursor {}

/* data passed in the control vq, 2d related */

#[derive(Copy, Clone, Debug, Default, FromBytes, AsBytes, PartialEq, Eq)]
#[repr(C)]
pub struct virtio_gpu_rect {
    pub x: u32,
    pub y: u32,
    pub width: u32,
    pub height: u32,
}
unsafe impl ByteValued for virtio_gpu_rect {}

/* VIRTIO_GPU_CMD_GET_EDID */
#[derive(Copy, Clone, Debug, Default, FromBytes, AsBytes, PartialEq, Eq)]
#[repr(C)]
pub struct virtio_gpu_get_edid {
    pub scanout: u32,
    pub padding: u32,
}
unsafe impl ByteValued for virtio_gpu_get_edid {}

/* VIRTIO_GPU_CMD_RESOURCE_UNREF */
#[derive(Copy, Clone, Debug, Default, FromBytes, AsBytes, PartialEq, Eq)]
#[repr(C)]
pub struct virtio_gpu_resource_unref {
    pub resource_id: u32,
    pub padding: u32,
}
unsafe impl ByteValued for virtio_gpu_resource_unref {}

/* VIRTIO_GPU_CMD_RESOURCE_CREATE_2D: create a 2d resource with a format */
#[derive(Copy, Clone, Debug, Default, FromBytes, AsBytes, PartialEq, Eq)]
#[repr(C)]
pub struct virtio_gpu_resource_create_2d {
    pub resource_id: u32,
    pub format: u32,
    pub width: u32,
    pub height: u32,
}
unsafe impl ByteValued for virtio_gpu_resource_create_2d {}

/* VIRTIO_GPU_CMD_SET_SCANOUT */
#[derive(Copy, Clone, Debug, Default, FromBytes, AsBytes, PartialEq, Eq)]
#[repr(C)]
pub struct virtio_gpu_set_scanout {
    pub r: virtio_gpu_rect,
    pub scanout_id: u32,
    pub resource_id: u32,
}
unsafe impl ByteValued for virtio_gpu_set_scanout {}

/* VIRTIO_GPU_CMD_RESOURCE_FLUSH */
#[derive(Copy, Clone, Debug, Default, FromBytes, AsBytes, PartialEq, Eq)]
#[repr(C)]
pub struct virtio_gpu_resource_flush {
    pub r: virtio_gpu_rect,
    pub resource_id: u32,
    pub padding: u32,
}
unsafe impl ByteValued for virtio_gpu_resource_flush {}

/* VIRTIO_GPU_CMD_TRANSFER_TO_HOST_2D: simple transfer to_host */
#[derive(Copy, Clone, Debug, Default, FromBytes, AsBytes, PartialEq, Eq)]
#[repr(C)]
pub struct virtio_gpu_transfer_to_host_2d {
    pub r: virtio_gpu_rect,
    pub offset: u64,
    pub resource_id: u32,
    pub padding: u32,
}
unsafe impl ByteValued for virtio_gpu_transfer_to_host_2d {}

#[derive(Copy, Clone, Debug, Default, AsBytes, FromBytes, PartialEq, Eq)]
#[repr(C)]
pub struct virtio_gpu_mem_entry {
    pub addr: u64,
    pub length: u32,
    pub padding: u32,
}
unsafe impl ByteValued for virtio_gpu_mem_entry {}

/* VIRTIO_GPU_CMD_RESOURCE_ATTACH_BACKING */
#[derive(Copy, Clone, Debug, Default, FromBytes, AsBytes, PartialEq, Eq)]
#[repr(C)]
pub struct virtio_gpu_resource_attach_backing {
    pub resource_id: u32,
    pub nr_entries: u32,
}
unsafe impl ByteValued for virtio_gpu_resource_attach_backing {}

/* VIRTIO_GPU_CMD_RESOURCE_DETACH_BACKING */
#[derive(Copy, Clone, Debug, Default, FromBytes, AsBytes, PartialEq, Eq)]
#[repr(C)]
pub struct virtio_gpu_resource_detach_backing {
    pub resource_id: u32,
    pub padding: u32,
}
unsafe impl ByteValued for virtio_gpu_resource_detach_backing {}

#[derive(Copy, Clone, Debug, Default, FromBytes, AsBytes, PartialEq, Eq)]
#[repr(C)]
pub struct virtio_gpu_display_one {
    pub r: virtio_gpu_rect,
    pub enabled: u32,
    pub flags: u32,
}
unsafe impl ByteValued for virtio_gpu_display_one {}

#[derive(Copy, Clone, Debug, Default, FromBytes, AsBytes)]
#[repr(C)]
pub struct virtio_gpu_resp_display_info {
    pub hdr: virtio_gpu_ctrl_hdr,
    pub pmodes: [virtio_gpu_display_one; VIRTIO_GPU_MAX_SCANOUTS],
}
unsafe impl ByteValued for virtio_gpu_resp_display_info {}

const EDID_BLOB_MAX_SIZE: usize = 1024;

#[derive(Debug, Copy, Clone)]
#[repr(C)]
pub struct virtio_gpu_resp_edid {
    pub hdr: virtio_gpu_ctrl_hdr,
    pub size: u32,
    pub padding: u32,
    pub edid: [u8; EDID_BLOB_MAX_SIZE],
}

unsafe impl ByteValued for virtio_gpu_resp_edid {}

/* data passed in the control vq, 3d related */

#[derive(Copy, Clone, Debug, Default, FromBytes, AsBytes, PartialEq, Eq)]
#[repr(C)]
pub struct virtio_gpu_box {
    pub x: u32,
    pub y: u32,
    pub z: u32,
    pub w: u32,
    pub h: u32,
    pub d: u32,
}
unsafe impl ByteValued for virtio_gpu_box {}

/* VIRTIO_GPU_CMD_TRANSFER_TO_HOST_3D, VIRTIO_GPU_CMD_TRANSFER_FROM_HOST_3D */
#[derive(Copy, Clone, Debug, Default, FromBytes, AsBytes, PartialEq, Eq)]
#[repr(C)]
pub struct virtio_gpu_transfer_host_3d {
    pub box_: virtio_gpu_box,
    pub offset: u64,
    pub resource_id: u32,
    pub level: u32,
    pub stride: u32,
    pub layer_stride: u32,
}
unsafe impl ByteValued for virtio_gpu_transfer_host_3d {}

/* VIRTIO_GPU_CMD_RESOURCE_CREATE_3D */
pub const VIRTIO_GPU_RESOURCE_FLAG_Y_0_TOP: u32 = 1 << 0;
#[derive(Copy, Clone, Debug, Default, FromBytes, AsBytes, PartialEq, Eq)]
#[repr(C)]
pub struct virtio_gpu_resource_create_3d {
    pub resource_id: u32,
    pub target: u32,
    pub format: u32,
    pub bind: u32,
    pub width: u32,
    pub height: u32,
    pub depth: u32,
    pub array_size: u32,
    pub last_level: u32,
    pub nr_samples: u32,
    pub flags: u32,
    pub padding: u32,
}
unsafe impl ByteValued for virtio_gpu_resource_create_3d {}

/* VIRTIO_GPU_CMD_CTX_CREATE */
pub const VIRTIO_GPU_CONTEXT_INIT_CAPSET_ID_MASK: u32 = 1 << 0;
#[derive(Copy, FromBytes, AsBytes, PartialEq, Eq)]
#[repr(C)]
pub struct virtio_gpu_ctx_create {
    pub nlen: u32,
    pub context_init: u32,
    pub debug_name: [u8; 64],
}
unsafe impl ByteValued for virtio_gpu_ctx_create {}

impl Default for virtio_gpu_ctx_create {
    fn default() -> Self {
        unsafe { ::std::mem::zeroed() }
    }
}

impl Clone for virtio_gpu_ctx_create {
    fn clone(&self) -> virtio_gpu_ctx_create {
        *self
    }
}

impl fmt::Debug for virtio_gpu_ctx_create {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let debug_name = CStr::from_bytes_with_nul(&self.debug_name[..min(64, self.nlen as usize)])
            .map_or_else(
                |err| format!("Err({})", err),
                |c_str| c_str.to_string_lossy().into_owned(),
            );
        f.debug_struct(stringify!("virtio_gpu_ctx_create"))
            .field("debug_name", &debug_name)
            .field("context_init", &self.context_init)
            .finish()
    }
}

/* VIRTIO_GPU_CMD_CTX_DESTROY */
#[derive(Copy, Clone, Debug, Default, FromBytes, AsBytes, PartialEq, Eq)]
#[repr(C)]
pub struct virtio_gpu_ctx_destroy {}
unsafe impl ByteValued for virtio_gpu_ctx_destroy {}

/* VIRTIO_GPU_CMD_CTX_ATTACH_RESOURCE, VIRTIO_GPU_CMD_CTX_DETACH_RESOURCE */
#[derive(Copy, Clone, Debug, Default, FromBytes, AsBytes, PartialEq, Eq)]
#[repr(C)]
pub struct virtio_gpu_ctx_resource {
    pub resource_id: u32,
    pub padding: u32,
}
unsafe impl ByteValued for virtio_gpu_ctx_resource {}

/* VIRTIO_GPU_CMD_SUBMIT_3D */
#[derive(Copy, Clone, Debug, Default, FromBytes, AsBytes, PartialEq, Eq)]
#[repr(C)]
pub struct virtio_gpu_cmd_submit {
    pub size: u32,

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
    pub num_in_fences: u32,
}
unsafe impl ByteValued for virtio_gpu_cmd_submit {}

pub const VIRTIO_GPU_CAPSET_VIRGL: u32 = 1;
pub const VIRTIO_GPU_CAPSET_VIRGL2: u32 = 2;
pub const VIRTIO_GPU_CAPSET_GFXSTREAM: u32 = 3;
pub const VIRTIO_GPU_CAPSET_VENUS: u32 = 4;
pub const VIRTIO_GPU_CAPSET_CROSS_DOMAIN: u32 = 5;

/* VIRTIO_GPU_CMD_GET_CAPSET_INFO */
#[derive(Copy, Clone, Debug, Default, FromBytes, AsBytes, PartialEq, Eq)]
#[repr(C)]
pub struct virtio_gpu_get_capset_info {
    pub capset_index: u32,
    pub padding: u32,
}
unsafe impl ByteValued for virtio_gpu_get_capset_info {}

/* VIRTIO_GPU_RESP_OK_CAPSET_INFO */
#[derive(Copy, Clone, Debug, Default, FromBytes, AsBytes)]
#[repr(C)]
pub struct virtio_gpu_resp_capset_info {
    pub hdr: virtio_gpu_ctrl_hdr,
    pub capset_id: u32,
    pub capset_max_version: u32,
    pub capset_max_size: u32,
    pub padding: u32,
}
unsafe impl ByteValued for virtio_gpu_resp_capset_info {}

/* VIRTIO_GPU_CMD_GET_CAPSET */
#[derive(Copy, Clone, Debug, Default, FromBytes, AsBytes, PartialEq, Eq)]
#[repr(C)]
pub struct virtio_gpu_get_capset {
    pub capset_id: u32,
    pub capset_version: u32,
}
unsafe impl ByteValued for virtio_gpu_get_capset {}

/* VIRTIO_GPU_RESP_OK_CAPSET */
#[derive(Copy, Clone, Debug, Default)]
#[repr(C)]
pub struct virtio_gpu_resp_capset {
    pub hdr: virtio_gpu_ctrl_hdr,
    pub capset_data: PhantomData<[u8]>,
}
unsafe impl ByteValued for virtio_gpu_resp_capset {}

/* VIRTIO_GPU_RESP_OK_RESOURCE_PLANE_INFO */
#[derive(Copy, Clone, Debug, Default, FromBytes, AsBytes)]
#[repr(C)]
pub struct virtio_gpu_resp_resource_plane_info {
    pub hdr: virtio_gpu_ctrl_hdr,
    pub count: u32,
    pub padding: u32,
    pub format_modifier: u64,
    pub strides: [u32; 4],
    pub offsets: [u32; 4],
}
unsafe impl ByteValued for virtio_gpu_resp_resource_plane_info {}

pub const PLANE_INFO_MAX_COUNT: usize = 4;

pub const VIRTIO_GPU_EVENT_DISPLAY: u32 = 1 << 0;

#[derive(Copy, Clone, Debug, Default, FromBytes, AsBytes, PartialEq, Eq)]
#[repr(C)]
pub struct virtio_gpu_resource_create_blob {
    pub resource_id: u32,
    pub blob_mem: u32,
    pub blob_flags: u32,
    pub nr_entries: u32,
    pub blob_id: u64,
    pub size: u64,
}
unsafe impl ByteValued for virtio_gpu_resource_create_blob {}

#[derive(Copy, Clone, Debug, Default, FromBytes, AsBytes, PartialEq, Eq)]
#[repr(C)]
pub struct virtio_gpu_resource_map_blob {
    pub resource_id: u32,
    pub padding: u32,
    pub offset: u64,
}
unsafe impl ByteValued for virtio_gpu_resource_map_blob {}

#[derive(Copy, Clone, Debug, Default, FromBytes, AsBytes, PartialEq, Eq)]
#[repr(C)]
pub struct virtio_gpu_resource_unmap_blob {
    pub resource_id: u32,
    pub padding: u32,
}
unsafe impl ByteValued for virtio_gpu_resource_unmap_blob {}

#[derive(Copy, Clone, Debug, Default, FromBytes, AsBytes, PartialEq, Eq)]
#[repr(C)]
pub struct virtio_gpu_resp_map_info {
    pub hdr: virtio_gpu_ctrl_hdr,
    pub map_info: u32,
    pub padding: u32,
}
unsafe impl ByteValued for virtio_gpu_resp_map_info {}

#[derive(Copy, Clone, Debug, Default, FromBytes, AsBytes, PartialEq, Eq)]
#[repr(C)]
pub struct virtio_gpu_resource_assign_uuid {
    pub resource_id: u32,
    pub padding: u32,
}
unsafe impl ByteValued for virtio_gpu_resource_assign_uuid {}

#[derive(Copy, Clone, Debug, Default, FromBytes, AsBytes)]
#[repr(C)]
pub struct virtio_gpu_resp_resource_uuid {
    pub hdr: virtio_gpu_ctrl_hdr,
    pub uuid: [u8; 16],
}
unsafe impl ByteValued for virtio_gpu_resp_resource_uuid {}

/* VIRTIO_GPU_CMD_SET_SCANOUT_BLOB */
#[derive(Copy, Clone, Debug, Default, FromBytes, AsBytes, PartialEq, Eq)]
#[repr(C)]
pub struct virtio_gpu_set_scanout_blob {
    pub r: virtio_gpu_rect,
    pub scanout_id: u32,
    pub resource_id: u32,
    pub width: u32,
    pub height: u32,
    pub format: u32,
    pub padding: u32,
    pub strides: [u32; 4],
    pub offsets: [u32; 4],
}
unsafe impl ByteValued for virtio_gpu_set_scanout_blob {}

/* simple formats for fbcon/X use */
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

/// An error indicating something went wrong decoding a `GpuCommand`. These correspond to
/// `VIRTIO_GPU_CMD_*`.
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
    fn from(e: io::Error) -> GpuCommandDecodeError {
        GpuCommandDecodeError::IO(e)
    }
}

impl From<device::Error> for GpuCommandDecodeError {
    fn from(_: device::Error) -> Self {
        GpuCommandDecodeError::DescriptorReadFailed
    }
}

impl From<device::Error> for GpuResponseEncodeError {
    fn from(_: device::Error) -> Self {
        GpuResponseEncodeError::DescriptorWriteFailed
    }
}

impl fmt::Debug for GpuCommand {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use self::GpuCommand::*;
        match self {
            GetDisplayInfo => f.debug_struct("GetDisplayInfo").finish(),
            GetEdid(_info) => f.debug_struct("GetEdid").finish(),
            ResourceCreate2d(_info) => f.debug_struct("ResourceCreate2d").finish(),
            ResourceUnref(_info) => f.debug_struct("ResourceUnref").finish(),
            SetScanout(_info) => f.debug_struct("SetScanout").finish(),
            SetScanoutBlob(_info) => f.debug_struct("SetScanoutBlob").finish(),
            ResourceFlush(_info) => f.debug_struct("ResourceFlush").finish(),
            TransferToHost2d(_info) => f.debug_struct("TransferToHost2d").finish(),
            ResourceAttachBacking(_info, _vecs) => f.debug_struct("ResourceAttachBacking").finish(),
            ResourceDetachBacking(_info) => f.debug_struct("ResourceDetachBacking").finish(),
            GetCapsetInfo(_info) => f.debug_struct("GetCapsetInfo").finish(),
            GetCapset(_info) => f.debug_struct("GetCapset").finish(),
            CtxCreate(_info) => f.debug_struct("CtxCreate").finish(),
            CtxDestroy(_info) => f.debug_struct("CtxDestroy").finish(),
            CtxAttachResource(_info) => f.debug_struct("CtxAttachResource").finish(),
            CtxDetachResource(_info) => f.debug_struct("CtxDetachResource").finish(),
            ResourceCreate3d(_info) => f.debug_struct("ResourceCreate3d").finish(),
            TransferToHost3d(_info) => f.debug_struct("TransferToHost3d").finish(),
            TransferFromHost3d(_info) => f.debug_struct("TransferFromHost3d").finish(),
            CmdSubmit3d { .. } => f.debug_struct("CmdSubmit3d").finish(),
            ResourceCreateBlob(_info) => f.debug_struct("ResourceCreateBlob").finish(),
            ResourceMapBlob(_info) => f.debug_struct("ResourceMapBlob").finish(),
            ResourceUnmapBlob(_info) => f.debug_struct("ResourceUnmapBlob").finish(),
            UpdateCursor(_info) => f.debug_struct("UpdateCursor").finish(),
            MoveCursor(_info) => f.debug_struct("MoveCursor").finish(),
            ResourceAssignUuid(_info) => f.debug_struct("ResourceAssignUuid").finish(),
        }
    }
}

impl GpuCommand {
    /// Decodes a command from the given chunk of memory.
    pub fn decode(
        reader: &mut Reader,
    ) -> Result<(virtio_gpu_ctrl_hdr, GpuCommand), GpuCommandDecodeError> {
        use self::GpuCommand::*;
        let hdr = reader
            .read_obj::<virtio_gpu_ctrl_hdr>()
            .map_err(|_| Error::DescriptorReadFailed)?;
        trace!("Decoding GpuCommand 0x{:0x}", hdr.type_);
        let cmd = match hdr.type_ {
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
                let mut entries = Vec::with_capacity(info.nr_entries as usize);
                for _ in 0..info.nr_entries {
                    let entry: virtio_gpu_mem_entry =
                        reader.read_obj().map_err(|_| Error::DescriptorReadFailed)?;
                    entries.push((GuestAddress(entry.addr), entry.length as usize))
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

                let mut cmd_data = vec![0; info.size as usize];
                let mut fence_ids: Vec<u64> = Vec::with_capacity(info.num_in_fences as usize);

                for _ in 0..info.num_in_fences {
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
            _ => return Err(GpuCommandDecodeError::InvalidType(hdr.type_)),
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
    fn from(e: RutabagaError) -> GpuResponse {
        GpuResponse::ErrRutabaga(e)
    }
}

impl Display for GpuResponse {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use self::GpuResponse::*;
        match self {
            ErrRutabaga(e) => write!(f, "renderer error: {}", e),
            ErrScanout { num_scanouts } => write!(f, "non-zero scanout: {}", num_scanouts),
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
    fn from(e: io::Error) -> GpuResponseEncodeError {
        GpuResponseEncodeError::IO(e)
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
            type_: self.get_type(),
            flags,
            fence_id,
            ctx_id,
            ring_idx,
            padding: Default::default(),
        };
        let len = match *self {
            GpuResponse::OkDisplayInfo(ref info) => {
                if info.len() > VIRTIO_GPU_MAX_SCANOUTS {
                    return Err(GpuResponseEncodeError::TooManyDisplays(info.len()));
                }
                let mut disp_info = virtio_gpu_resp_display_info {
                    hdr,
                    pmodes: Default::default(),
                };
                for (disp_mode, &(width, height, enabled)) in disp_info.pmodes.iter_mut().zip(info)
                {
                    disp_mode.r.width = width;
                    disp_mode.r.height = height;
                    disp_mode.enabled = enabled as u32;
                }
                writer
                    .write_obj(disp_info)
                    .map_err(|_| Error::DescriptorWriteFailed)?;
                size_of_val(&disp_info)
            }
            GpuResponse::OkEdid { ref blob } => {
                let mut edid_info = virtio_gpu_resp_edid {
                    hdr,
                    size: blob.len() as u32,
                    edid: [0; EDID_BLOB_MAX_SIZE],
                    padding: Default::default(),
                };
                edid_info.edid.copy_from_slice(blob);
                writer
                    .write_obj(edid_info)
                    .map_err(|_| Error::DescriptorWriteFailed)?;
                size_of_val(&edid_info)
            }
            GpuResponse::OkCapsetInfo {
                capset_id,
                version,
                size,
            } => {
                writer
                    .write_obj(virtio_gpu_resp_capset_info {
                        hdr,
                        capset_id,
                        capset_max_version: version,
                        capset_max_size: size,
                        padding: 0u32,
                    })
                    .map_err(|_| Error::DescriptorWriteFailed)?;
                size_of::<virtio_gpu_resp_capset_info>()
            }
            GpuResponse::OkCapset(ref data) => {
                writer
                    .write_obj(hdr)
                    .map_err(|_| Error::DescriptorWriteFailed)?;
                writer
                    .write(data)
                    .map_err(|_| Error::DescriptorWriteFailed)?;
                size_of_val(&hdr) + data.len()
            }
            GpuResponse::OkResourcePlaneInfo {
                format_modifier,
                ref plane_info,
            } => {
                if plane_info.len() > PLANE_INFO_MAX_COUNT {
                    return Err(GpuResponseEncodeError::TooManyPlanes(plane_info.len()));
                }
                let mut strides = [u32::default(); PLANE_INFO_MAX_COUNT];
                let mut offsets = [u32::default(); PLANE_INFO_MAX_COUNT];
                for (plane_index, plane) in plane_info.iter().enumerate() {
                    strides[plane_index] = plane.stride;
                    offsets[plane_index] = plane.offset;
                }
                let plane_info = virtio_gpu_resp_resource_plane_info {
                    hdr,
                    count: plane_info.len() as u32,
                    padding: 0u32,
                    format_modifier,
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
                            type_: VIRTIO_GPU_RESP_OK_NODATA,
                            ..hdr
                        })
                        .map_err(|_| Error::DescriptorWriteFailed)?;
                    size_of_val(&hdr)
                }
            }
            GpuResponse::OkResourceUuid { uuid } => {
                let resp_info = virtio_gpu_resp_resource_uuid { hdr, uuid };

                writer
                    .write_obj(resp_info)
                    .map_err(|_| Error::DescriptorWriteFailed)?;
                size_of_val(&resp_info)
            }
            GpuResponse::OkMapInfo { map_info } => {
                let resp_info = virtio_gpu_resp_map_info {
                    hdr,
                    map_info,
                    padding: Default::default(),
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
        Ok(len as u32)
    }

    /// Gets the `VIRTIO_GPU_*` enum value that corresponds to this variant.
    pub fn get_type(&self) -> u32 {
        match self {
            GpuResponse::OkNoData => VIRTIO_GPU_RESP_OK_NODATA,
            GpuResponse::OkDisplayInfo(_) => VIRTIO_GPU_RESP_OK_DISPLAY_INFO,
            GpuResponse::OkEdid { .. } => VIRTIO_GPU_RESP_OK_EDID,
            GpuResponse::OkCapsetInfo { .. } => VIRTIO_GPU_RESP_OK_CAPSET_INFO,
            GpuResponse::OkCapset(_) => VIRTIO_GPU_RESP_OK_CAPSET,
            GpuResponse::OkResourcePlaneInfo { .. } => VIRTIO_GPU_RESP_OK_RESOURCE_PLANE_INFO,
            GpuResponse::OkResourceUuid { .. } => VIRTIO_GPU_RESP_OK_RESOURCE_UUID,
            GpuResponse::OkMapInfo { .. } => VIRTIO_GPU_RESP_OK_MAP_INFO,
            GpuResponse::ErrUnspec => VIRTIO_GPU_RESP_ERR_UNSPEC,
            GpuResponse::ErrRutabaga(_) => VIRTIO_GPU_RESP_ERR_UNSPEC,
            GpuResponse::ErrScanout { num_scanouts: _ } => VIRTIO_GPU_RESP_ERR_UNSPEC,
            GpuResponse::ErrOutOfMemory => VIRTIO_GPU_RESP_ERR_OUT_OF_MEMORY,
            GpuResponse::ErrInvalidScanoutId => VIRTIO_GPU_RESP_ERR_INVALID_SCANOUT_ID,
            GpuResponse::ErrInvalidResourceId => VIRTIO_GPU_RESP_ERR_INVALID_RESOURCE_ID,
            GpuResponse::ErrInvalidContextId => VIRTIO_GPU_RESP_ERR_INVALID_CONTEXT_ID,
            GpuResponse::ErrInvalidParameter => VIRTIO_GPU_RESP_ERR_INVALID_PARAMETER,
        }
    }
}

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn test_virtio_gpu_config() {
        // Test VirtioGpuConfig size
        assert_eq!(std::mem::size_of::<VirtioGpuConfig>(), 16);
    }

    #[test]
    fn test_invalid_command_type_display() {
        let error = InvalidCommandType(42);
        assert_eq!(format!("{}", error), "Invalid command type 42");
    }

    #[test]
    fn test_gpu_response_display() {
        let err_rutabaga = GpuResponse::ErrRutabaga(RutabagaError::InvalidContextId);
        assert_eq!(
            format!("{}", err_rutabaga),
            "renderer error: invalid context id"
        );

        let err_scanout = GpuResponse::ErrScanout { num_scanouts: 3 };
        assert_eq!(format!("{}", err_scanout), "non-zero scanout: 3");
    }

    #[test]
    fn test_invalid_type_error() {
        let error = GpuCommandDecodeError::InvalidType(42);
        assert_eq!(format!("{}", error), "invalid command type (42)");
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
    fn test_debug() {
        let get_display_info = GpuCommand::GetDisplayInfo;
        let get_edid = GpuCommand::GetEdid(virtio_gpu_get_edid::default());
        let resource_create_2d =
            GpuCommand::ResourceCreate2d(virtio_gpu_resource_create_2d::default());
        let resource_unref = GpuCommand::ResourceUnref(virtio_gpu_resource_unref::default());
        let set_scanout = GpuCommand::SetScanout(virtio_gpu_set_scanout::default());
        let set_scanout_blob = GpuCommand::SetScanoutBlob(virtio_gpu_set_scanout_blob::default());
        let resource_flush = GpuCommand::ResourceFlush(virtio_gpu_resource_flush::default());
        let transfer_to_host_2d =
            GpuCommand::TransferToHost2d(virtio_gpu_transfer_to_host_2d::default());
        //let resource_attach_backing = GpuCommand::ResourceAttachBacking(virtio_gpu_resource_attach_backing::default(), vec![1]);
        let resource_detach_backing =
            GpuCommand::ResourceDetachBacking(virtio_gpu_resource_detach_backing::default());
        let get_capset_info = GpuCommand::GetCapsetInfo(virtio_gpu_get_capset_info::default());
        let get_capset = GpuCommand::GetCapset(virtio_gpu_get_capset::default());
        let ctx_create = GpuCommand::CtxCreate(virtio_gpu_ctx_create::default());
        let ctx_destroy = GpuCommand::CtxDestroy(virtio_gpu_ctx_destroy::default());
        let ctx_attach_resource = GpuCommand::CtxAttachResource(virtio_gpu_ctx_resource::default());
        let ctx_detach_resource = GpuCommand::CtxDetachResource(virtio_gpu_ctx_resource::default());
        let resource_create_3d =
            GpuCommand::ResourceCreate3d(virtio_gpu_resource_create_3d::default());
        let transfer_to_host_3d =
            GpuCommand::TransferToHost3d(virtio_gpu_transfer_host_3d::default());
        let transfer_from_host_3d =
            GpuCommand::TransferFromHost3d(virtio_gpu_transfer_host_3d::default());
        let cmd_submit_3d = GpuCommand::CmdSubmit3d {
            cmd_data: Vec::new(),
            fence_ids: Vec::new(),
        };
        let resource_create_blob =
            GpuCommand::ResourceCreateBlob(virtio_gpu_resource_create_blob::default());
        let resource_map_blob =
            GpuCommand::ResourceMapBlob(virtio_gpu_resource_map_blob::default());
        let resource_unmap_blob =
            GpuCommand::ResourceUnmapBlob(virtio_gpu_resource_unmap_blob::default());
        let update_cursor = GpuCommand::UpdateCursor(virtio_gpu_update_cursor::default());
        let move_cursor = GpuCommand::MoveCursor(virtio_gpu_update_cursor::default());
        let resource_assign_uuid =
            GpuCommand::ResourceAssignUuid(virtio_gpu_resource_assign_uuid::default());

        let expected_debug_output_display = "GetDisplayInfo";
        let expected_debug_output_edid = "GetEdid";
        let expected_debug_output_create2d = "ResourceCreate2d";
        let expected_debug_output_unref = "ResourceUnref";
        let expected_debug_output_scanout = "SetScanout";
        let expected_debug_output_scanout_blob = "SetScanoutBlob";
        let expected_debug_output_flush = "ResourceFlush";
        let expected_debug_output_transfer_to_host_2d = "TransferToHost2d";
        let expected_debug_output_detach_backing = "ResourceDetachBacking";
        let expected_debug_output_get_capset_info = "GetCapsetInfo";
        let expected_debug_output_get_capset = "GetCapset";
        let expected_debug_output_ctx_create = "CtxCreate";
        let expected_debug_output_ctx_destroy = "CtxDestroy";
        let expected_debug_output_ctx_attach_resource = "CtxAttachResource";
        let expected_debug_output_ctx_detach_resource = "CtxDetachResource";
        let expected_debug_output_resource_create_3d = "ResourceCreate3d";
        let expected_debug_output_transfer_to_host_3d = "TransferToHost3d";
        let expected_debug_output_transfer_from_host_3d = "TransferFromHost3d";
        let expected_debug_output_cmd_submit_3d = "CmdSubmit3d";
        let expected_debug_output_create_blob = "ResourceCreateBlob";
        let expected_debug_output_map_blob = "ResourceMapBlob";
        let expected_debug_output_unmap_blob = "ResourceUnmapBlob";
        let expected_debug_output_update_cursor = "UpdateCursor";
        let expected_debug_output_move_cursor = "MoveCursor";
        let expected_debug_output_assign_uuid = "ResourceAssignUuid";

        assert_eq!(
            format!("{:?}", get_display_info),
            expected_debug_output_display
        );
        assert_eq!(format!("{:?}", get_edid), expected_debug_output_edid);
        assert_eq!(
            format!("{:?}", resource_create_2d),
            expected_debug_output_create2d
        );
        assert_eq!(format!("{:?}", resource_unref), expected_debug_output_unref);
        assert_eq!(format!("{:?}", set_scanout), expected_debug_output_scanout);
        assert_eq!(
            format!("{:?}", set_scanout_blob),
            expected_debug_output_scanout_blob
        );
        assert_eq!(format!("{:?}", resource_flush), expected_debug_output_flush);
        assert_eq!(
            format!("{:?}", transfer_to_host_2d),
            expected_debug_output_transfer_to_host_2d
        );
        assert_eq!(
            format!("{:?}", resource_detach_backing),
            expected_debug_output_detach_backing
        );
        assert_eq!(
            format!("{:?}", get_capset_info),
            expected_debug_output_get_capset_info
        );
        assert_eq!(
            format!("{:?}", get_capset),
            expected_debug_output_get_capset
        );
        assert_eq!(
            format!("{:?}", ctx_create),
            expected_debug_output_ctx_create
        );
        assert_eq!(
            format!("{:?}", ctx_destroy),
            expected_debug_output_ctx_destroy
        );
        assert_eq!(
            format!("{:?}", ctx_attach_resource),
            expected_debug_output_ctx_attach_resource
        );
        assert_eq!(
            format!("{:?}", ctx_detach_resource),
            expected_debug_output_ctx_detach_resource
        );
        assert_eq!(
            format!("{:?}", resource_create_3d),
            expected_debug_output_resource_create_3d
        );
        assert_eq!(
            format!("{:?}", transfer_to_host_3d),
            expected_debug_output_transfer_to_host_3d
        );
        assert_eq!(
            format!("{:?}", transfer_from_host_3d),
            expected_debug_output_transfer_from_host_3d
        );
        assert_eq!(
            format!("{:?}", cmd_submit_3d),
            expected_debug_output_cmd_submit_3d
        );
        assert_eq!(
            format!("{:?}", resource_create_blob),
            expected_debug_output_create_blob
        );
        assert_eq!(
            format!("{:?}", resource_map_blob),
            expected_debug_output_map_blob
        );
        assert_eq!(
            format!("{:?}", resource_unmap_blob),
            expected_debug_output_unmap_blob
        );
        assert_eq!(
            format!("{:?}", update_cursor),
            expected_debug_output_update_cursor
        );
        assert_eq!(
            format!("{:?}", move_cursor),
            expected_debug_output_move_cursor
        );
        assert_eq!(
            format!("{:?}", resource_assign_uuid),
            expected_debug_output_assign_uuid
        );

        let bytes = b"test_debug\0";
        let original = virtio_gpu_ctx_create {
            debug_name: {
                let mut debug_name = [0; 64];
                debug_name[..bytes.len()].copy_from_slice(bytes);
                debug_name
            },
            context_init: 0,
            nlen: bytes.len() as u32,
        };

        let debug_string = format!("{:?}", original);

        assert_eq!(
            debug_string,
            "\"virtio_gpu_ctx_create\" { debug_name: \"test_debug\", context_init: 0 }"
        );
    }
}
