// SPDX-License-Identifier: Apache-2.0 or BSD-3-Clause
#![allow(dead_code)] //TODO: remove

use vm_memory::{ByteValued, Le32};

// virtqueues

pub const CONTROL_QUEUE_IDX: u16 = 0;
pub const EVENT_QUEUE_IDX: u16 = 1;
pub const TX_QUEUE_IDX: u16 = 2;
pub const RX_QUEUE_IDX: u16 = 3;
pub const NUM_QUEUES: u16 = 4;

// jack control request types

pub const VIRTIO_SND_R_JACK_INFO: u32 = 1;
pub const VIRTIO_SND_R_JACK_REMAP: u32 = 2;

// PCM control request types

pub const VIRTIO_SND_R_PCM_INFO: u32 = 0x0100;
pub const VIRTIO_SND_R_PCM_SET_PARAMS: u32 = 0x0101;
pub const VIRTIO_SND_R_PCM_PREPARE: u32 = 0x0102;
pub const VIRTIO_SND_R_PCM_RELEASE: u32 = 0x0103;
pub const VIRTIO_SND_R_PCM_START: u32 = 0x0104;
pub const VIRTIO_SND_R_PCM_STOP: u32 = 0x0105;

// channel map control request types

pub const VIRTIO_SND_R_CHMAP_INFO: u32 = 0x0200;

// jack event types

pub const VIRTIO_SND_EVT_JACK_CONNECTED: u32 = 0x1000;
pub const VIRTIO_SND_EVT_JACK_DISCONNECTED: u32 = 0x1001;

// PCM event types

pub const VIRTIO_SND_EVT_PCM_PERIOD_ELAPSED: u32 = 0x1100;
pub const VIRTIO_SND_EVT_PCM_XRUN: u32 = 0x1101;

// common status codes

pub const VIRTIO_SND_S_OK: u32 = 0x8000;
pub const VIRTIO_SND_S_BAD_MSG: u32 = 0x8001;
pub const VIRTIO_SND_S_NOT_SUPP: u32 = 0x8002;
pub const VIRTIO_SND_S_IO_ERR: u32 = 0x8003;

// device data flow directions

pub const VIRTIO_SND_D_OUTPUT: u32 = 0;
pub const VIRTIO_SND_D_INPUT: u32 = 1;

/// Virtio Sound Configuration
#[derive(Copy, Clone, Debug, Default, PartialEq)]
#[repr(C)]
pub struct VirtioSoundConfig {
    /// total number of all available jacks
    pub jacks: Le32,
    /// total number of all available PCM streams
    pub streams: Le32,
    /// total number of all available channel maps
    pub chmpas: Le32,
}
// SAFETY: The layout of the structure is fixed and can be initialized by
// reading its content from byte array.
unsafe impl ByteValued for VirtioSoundConfig {}

/// Virtio Sound Request / Response common header
#[derive(Copy, Clone, Debug, Default, PartialEq)]
#[repr(C)]
pub struct VirtioSoundHeader {
    /// request type / response status
    pub code: Le32,
}
// SAFETY: The layout of the structure is fixed and can be initialized by
// reading its content from byte array.
unsafe impl ByteValued for VirtioSoundHeader {}

/// Virtio Sound event notification
#[derive(Copy, Clone, Debug, Default, PartialEq)]
#[repr(C)]
pub struct VirtioSoundEvent {
    /// PCM stream event type
    pub hdr: VirtioSoundHeader,
    /// PCM stream identifier from 0 to streams - 1
    pub data: Le32,
}
// SAFETY: The layout of the structure is fixed and can be initialized by
// reading its content from byte array.
unsafe impl ByteValued for VirtioSoundEvent {}

/// Virtio Sound request information about any kind of configuration item
#[derive(Copy, Clone, Debug, Default, PartialEq)]
#[repr(C)]
pub struct VirtioSoundQueryInfo {
    /// item request type (VIRTIO_SND_R_*_INFO)
    pub hdr: VirtioSoundHeader,
    /// starting identifier for the item
    pub start_id: Le32,
    /// number of items for which information is requested
    pub cound: Le32,
    /// size of the structure containing information for one item
    pub size: Le32,
}
// SAFETY: The layout of the structure is fixed and can be initialized by
// reading its content from byte array.
unsafe impl ByteValued for VirtioSoundQueryInfo {}

/// Virtio Sound response common information header
#[derive(Copy, Clone, Debug, Default, PartialEq)]
#[repr(C)]
pub struct VirtioSoundInfo {
    /// function group node identifier
    pub hda_fn_nid: Le32,
}
// SAFETY: The layout of the structure is fixed and can be initialized by
// reading its content from byte array.
unsafe impl ByteValued for VirtioSoundInfo {}
