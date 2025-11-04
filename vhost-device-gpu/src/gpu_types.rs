// Copyright 2025 Red Hat Inc
//
// SPDX-License-Identifier: Apache-2.0 or BSD-3-Clause

/// Generates an implementation of `From<Transfer3DDesc>` for any compatible
/// target struct.
macro_rules! impl_transfer3d_from_desc {
    ($target:path) => {
        impl From<Transfer3DDesc> for $target {
            fn from(desc: Transfer3DDesc) -> Self {
                Self {
                    x: desc.x,
                    y: desc.y,
                    z: desc.z,
                    w: desc.w,
                    h: desc.h,
                    d: desc.d,
                    level: desc.level,
                    stride: desc.stride,
                    layer_stride: desc.layer_stride,
                    offset: desc.offset,
                }
            }
        }
    };
}

macro_rules! impl_from_resource_create3d {
    ($target:ty) => {
        impl From<ResourceCreate3d> for $target {
            fn from(r: ResourceCreate3d) -> Self {
                Self {
                    target: r.target,
                    format: r.format,
                    bind: r.bind,
                    width: r.width,
                    height: r.height,
                    depth: r.depth,
                    array_size: r.array_size,
                    last_level: r.last_level,
                    nr_samples: r.nr_samples,
                    flags: r.flags,
                }
            }
        }
    };
}

use std::{collections::BTreeMap, os::raw::c_void};

use rutabaga_gfx::Transfer3D;
use virglrenderer::Transfer3D as VirglTransfer3D;

use crate::protocol::virtio_gpu_rect;

#[derive(Debug, Clone, Copy)]
pub struct Transfer3DDesc {
    pub x: u32,
    pub y: u32,
    pub z: u32,
    pub w: u32,
    pub h: u32,
    pub d: u32,
    pub level: u32,
    pub stride: u32,
    pub layer_stride: u32,
    pub offset: u64,
}

impl Transfer3DDesc {
    /// Constructs a 2 dimensional XY box in 3 dimensional space with unit depth
    /// and zero displacement on the Z axis.
    pub const fn new_2d(x: u32, y: u32, w: u32, h: u32, offset: u64) -> Self {
        Self {
            x,
            y,
            z: 0,
            w,
            h,
            d: 1,
            level: 0,
            stride: 0,
            layer_stride: 0,
            offset,
        }
    }
}
// Invoke the macro for both targets
// rutabaga_gfx::Transfer3D
impl_transfer3d_from_desc!(Transfer3D);
// virglrenderer::Transfer3D
impl_transfer3d_from_desc!(VirglTransfer3D);

// These are neutral types that can be used by all backends
pub type Rect = virtio_gpu_rect;

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum VirtioGpuRing {
    Global,
    ContextSpecific { ctx_id: u32, ring_idx: u8 },
}

pub struct FenceDescriptor {
    pub ring: VirtioGpuRing,
    pub fence_id: u64,
    pub desc_index: u16,
    pub len: u32,
}

#[derive(Default)]
pub struct FenceState {
    pub descs: Vec<FenceDescriptor>,
    pub completed_fences: BTreeMap<VirtioGpuRing, u64>,
}

#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct Iovec {
    pub iov_base: *mut c_void,
    pub iov_len: usize,
}

// The neutral `ResourceCreate3d` struct that all adapters will convert from.
#[derive(Debug, Clone, Copy)]
pub struct ResourceCreate3d {
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
}

// Invoke the macro for both targets
impl_from_resource_create3d!(rutabaga_gfx::ResourceCreate3D);
impl_from_resource_create3d!(virglrenderer::ResourceCreate3D);

#[derive(Debug, Clone, Copy)]
pub struct ResourceCreate2d {
    pub resource_id: u32,
    pub format: u32,
    pub width: u32,
    pub height: u32,
}
