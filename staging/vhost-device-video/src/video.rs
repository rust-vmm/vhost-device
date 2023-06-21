// SPDX-License-Identifier: Apache-2.0 or BSD-3-Clause
#![allow(dead_code)] //TODO: remove
// Struct definitions use the kernel-style naming for consistency
#![allow(non_camel_case_types)]

use bitflags::bitflags;
use num_enum::TryFromPrimitive;
use vm_memory::{ByteValued, Le32, Le64};

use crate::{
    vhu_video::{self, VuVideoError},
    vhu_video_thread::ReadObj,
};

pub(crate) type StreamId = u32;

pub(crate) trait ToBytes {
    fn to_bytes(&self) -> Vec<u8>;
}

/// Virtio specification definitions
/// Virtio Video Command types
pub(crate) const VIRTIO_VIDEO_CMD_QUERY_CAPABILITY: u32 = 0x0100;
pub(crate) const VIRTIO_VIDEO_CMD_STREAM_CREATE: u32 = 0x0101;
pub(crate) const VIRTIO_VIDEO_CMD_STREAM_DESTROY: u32 = 0x0102;
pub(crate) const VIRTIO_VIDEO_CMD_STREAM_DRAIN: u32 = 0x0103;
pub(crate) const VIRTIO_VIDEO_CMD_RESOURCE_CREATE: u32 = 0x0104;
pub(crate) const VIRTIO_VIDEO_CMD_RESOURCE_QUEUE: u32 = 0x0105;
pub(crate) const VIRTIO_VIDEO_CMD_RESOURCE_DESTROY_ALL: u32 = 0x0106;
pub(crate) const VIRTIO_VIDEO_CMD_QUEUE_CLEAR: u32 = 0x0107;
/// GET/SET_PARAMS are being replaced with GET/SET_PARAMS_EXT
pub(crate) const VIRTIO_VIDEO_CMD_GET_PARAMS__UNUSED: u32 = 0x0108;
pub(crate) const VIRTIO_VIDEO_CMD_SET_PARAMS__UNUSED: u32 = 0x0109;
pub(crate) const VIRTIO_VIDEO_CMD_QUERY_CONTROL: u32 = 0x010A;
pub(crate) const VIRTIO_VIDEO_CMD_GET_CONTROL: u32 = 0x010B;
pub(crate) const VIRTIO_VIDEO_CMD_SET_CONTROL: u32 = 0x010C;
pub(crate) const VIRTIO_VIDEO_CMD_GET_PARAMS_EXT: u32 = 0x010D;
pub(crate) const VIRTIO_VIDEO_CMD_SET_PARAMS_EXT: u32 = 0x010E;

/// Virtio Video Response types
pub(crate) const VIRTIO_VIDEO_RESP_OK_NODATA: u32 = 0x0200;
pub(crate) const VIRTIO_VIDEO_RESP_OK_QUERY_CAPABILITY: u32 = 0x0201;
pub(crate) const VIRTIO_VIDEO_RESP_OK_RESOURCE_QUEUE: u32 = 0x0202;
pub(crate) const VIRTIO_VIDEO_RESP_OK_GET_PARAMS: u32 = 0x0203;
pub(crate) const VIRTIO_VIDEO_RESP_OK_QUERY_CONTROL: u32 = 0x0204;
pub(crate) const VIRTIO_VIDEO_RESP_OK_GET_CONTROL: u32 = 0x0205;

pub(crate) const VIRTIO_VIDEO_RESP_ERR_INVALID_OPERATION: u32 = 0x0206;
pub(crate) const VIRTIO_VIDEO_RESP_ERR_OUT_OF_MEMORY: u32 = 0x0207;
pub(crate) const VIRTIO_VIDEO_RESP_ERR_INVALID_STREAM_ID: u32 = 0x0208;
pub(crate) const VIRTIO_VIDEO_RESP_ERR_INVALID_RESOURCE_ID: u32 = 0x0209;
pub(crate) const VIRTIO_VIDEO_RESP_ERR_INVALID_PARAMETER: u32 = 0x020A;
pub(crate) const VIRTIO_VIDEO_RESP_ERR_UNSUPPORTED_CONTROL: u32 = 0x020B;

#[derive(Debug, Clone)]
pub enum CmdError {
    InvalidOperation,
    OutOfMemory,
    InvalidStreamId,
    InvalidResourceId,
    InvalidParameter,
    UnsupportedControl,
}

#[derive(Debug, Clone)]
pub enum CmdResponse {
    OkNoData,
    QueryCapability(Vec<virtio_video_format_desc>),
    ResourceQueue {
        timestamp: u64,
        flags: u32,
        size: u32,
    },
    GetParams {
        queue_type: QueueType,
        params: virtio_video_params,
    },
    QueryControl(VideoControl),
    GetControl(ControlType),
    SetControl,
    Error(CmdError),
}

impl CmdResponse {
    fn cmd_type(&self) -> Le32 {
        use CmdResponse::*;
        Le32::from(match self {
            OkNoData => VIRTIO_VIDEO_RESP_OK_NODATA,
            QueryCapability(_) => VIRTIO_VIDEO_RESP_OK_QUERY_CAPABILITY,
            ResourceQueue { .. } => VIRTIO_VIDEO_RESP_OK_RESOURCE_QUEUE,
            GetParams { .. } => VIRTIO_VIDEO_RESP_OK_GET_PARAMS,
            QueryControl(_) => VIRTIO_VIDEO_RESP_OK_QUERY_CONTROL,
            GetControl(_) => VIRTIO_VIDEO_RESP_OK_GET_CONTROL,
            SetControl => VIRTIO_VIDEO_RESP_OK_NODATA,
            Error(e) => match e {
                CmdError::InvalidOperation => VIRTIO_VIDEO_RESP_ERR_INVALID_OPERATION,
                CmdError::OutOfMemory => VIRTIO_VIDEO_RESP_ERR_OUT_OF_MEMORY,
                CmdError::InvalidStreamId => VIRTIO_VIDEO_RESP_ERR_INVALID_STREAM_ID,
                CmdError::InvalidResourceId => VIRTIO_VIDEO_RESP_ERR_INVALID_RESOURCE_ID,
                CmdError::InvalidParameter => VIRTIO_VIDEO_RESP_ERR_INVALID_PARAMETER,
                CmdError::UnsupportedControl => VIRTIO_VIDEO_RESP_ERR_UNSUPPORTED_CONTROL,
            },
        })
    }
}

impl ToBytes for CmdResponse {
    fn to_bytes(&self) -> Vec<u8> {
        use CmdResponse::*;
        let mut response_raw: Vec<u8> = Vec::new();
        match self {
            QueryCapability(descs) => {
                let mut response = virtio_video_query_capability_resp::default();
                response.hdr.type_ = self.cmd_type();
                response.append_descs(descs);
                response_raw.append(&mut response.to_bytes());
            }
            QueryControl(control_type) => {
                let mut response = virtio_video_query_control_resp::default();
                response.hdr.type_ = self.cmd_type();
                response.resp.num = control_type.get_value();
                response_raw.extend_from_slice(response.as_slice());
            }
            GetParams {
                queue_type: _,
                params,
            } => {
                let mut response = virtio_video_get_params_resp::default();
                response.hdr.type_ = self.cmd_type();
                response.params = *params;
                response_raw.extend_from_slice(response.as_slice());
            }
            GetControl(_c) => {
                let mut response = virtio_video_get_control_resp::default();
                response.hdr.type_ = self.cmd_type();
                response_raw.extend_from_slice(response.hdr.as_slice());
            }
            ResourceQueue {
                timestamp,
                flags,
                size,
            } => {
                let mut response = virtio_video_resource_queue_resp::default();
                response.hdr.type_ = self.cmd_type();
                response.timestamp = (*timestamp).into();
                response.flags = BufferFlags::from_bits_retain(*flags);
                // Only used for encoder
                response.size = (*size).into();
                response_raw.extend_from_slice(response.as_slice());
            }
            OkNoData | SetControl | Error(_) => response_raw.extend_from_slice(
                virtio_video_cmd_hdr {
                    type_: self.cmd_type(),
                    ..Default::default()
                }
                .as_slice(),
            ),
        };
        response_raw
    }
}

#[derive(Debug, Clone)]
pub enum CmdResponseType {
    Sync(CmdResponse),
    AsyncQueue {
        stream_id: u32,
        queue_type: QueueType,
        resource_id: u32,
    },
}

/// Virtio Video Formats
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, TryFromPrimitive)]
#[repr(u32)]
pub enum Format {
    /// Raw formats
    Argb8888 = 1,
    Bgra8888,
    Nv12,
    Yuv420,
    Yvu420,
    /// Coded formats
    Mpeg2 = 0x1000,
    Mpeg4,
    H264,
    Hevc,
    Vp8,
    Vp9,
    #[default]
    Fwht,
}

/// Virtio Video Controls
#[derive(Debug, Clone, Copy, PartialEq, Eq, TryFromPrimitive)]
#[repr(u32)]
pub enum ControlType {
    Bitrate = 1,
    Profile,
    Level,
    ForceKeyframe,
    BitrateMode,
    BitratePeak,
    PrependSpsPpsToIdr,
}

/// Planes layout
pub(crate) const VIRTIO_VIDEO_PLANES_LAYOUT_SINGLE_BUFFER: u32 = 1 << 0;
pub(crate) const VIRTIO_VIDEO_PLANES_LAYOUT_PER_PLANE: u16 = 1 << 1;

/// Queue type
pub(crate) const VIRTIO_VIDEO_QUEUE_TYPE_INPUT: u32 = 0x100;
pub(crate) const VIRTIO_VIDEO_QUEUE_TYPE_OUTPUT: u32 = 0x101;

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, TryFromPrimitive)]
#[repr(u32)]
pub enum QueueType {
    #[default]
    InputQueue = VIRTIO_VIDEO_QUEUE_TYPE_INPUT,
    OutputQueue = VIRTIO_VIDEO_QUEUE_TYPE_OUTPUT,
}

/// Memory type
pub(crate) const VIRTIO_VIDEO_MEM_TYPE_GUEST_PAGES: u32 = 0;
pub(crate) const VIRTIO_VIDEO_MEM_TYPE_VIRTIO_OBJECT: u32 = 1;

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, TryFromPrimitive)]
#[repr(u32)]
pub enum MemoryType {
    #[default]
    GuestPages = VIRTIO_VIDEO_MEM_TYPE_GUEST_PAGES,
    VirtioObject = VIRTIO_VIDEO_MEM_TYPE_VIRTIO_OBJECT,
}

pub(crate) const VIRTIO_VIDEO_MAX_PLANES: u8 = 8;

pub(crate) const MAX_FMT_DESCS: u8 = 64;

pub(crate) trait ToVirtio {
    fn to_virtio(&self) -> Le32;
}

pub(crate) trait InitFromValue<T>
where
    Self: Sized,
{
    fn from_value(value: T) -> Option<Self>;
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum VideoCmd {
    QueryCapability {
        queue_type: QueueType,
    },
    StreamCreate {
        stream_id: StreamId,
        in_memory_type: MemoryType,
        out_memory_type: MemoryType,
        coded_format: Format,
    },
    StreamDestroy {
        stream_id: StreamId,
    },
    StreamDrain {
        stream_id: StreamId,
    },
    ResourceCreate {
        stream_id: StreamId,
        queue_type: QueueType,
        resource_id: u32,
        planes_layout: u32,
        plane_offsets: Vec<u32>,
    },
    ResourceQueue {
        stream_id: StreamId,
        queue_type: QueueType,
        resource_id: u32,
        timestamp: u64,
        data_sizes: Vec<u32>,
    },
    ResourceDestroyAll {
        stream_id: StreamId,
        queue_type: QueueType,
    },
    QueueClear {
        stream_id: StreamId,
        queue_type: QueueType,
    },
    GetParams {
        stream_id: StreamId,
        queue_type: QueueType,
    },
    SetParams {
        stream_id: StreamId,
        queue_type: QueueType,
        params: virtio_video_params,
    },
    QueryControl {
        control: ControlType,
        format: Format,
    },
    GetControl {
        stream_id: StreamId,
        control: ControlType,
    },
}

impl VideoCmd {
    pub fn from_descriptor(
        desc_chain: &vhu_video::VideoDescriptorChain,
    ) -> vhu_video::Result<Self> {
        use self::VideoCmd::*;
        macro_rules! read_body {
            ($a: expr) => {
                desc_chain.read_body(0, $a)
            };
        }
        let header: virtio_video_cmd_hdr = read_body!(false)?;
        Ok(match header.type_.into() {
            VIRTIO_VIDEO_CMD_QUERY_CAPABILITY => {
                let body: virtio_video_query_capability = read_body!(true)?;
                QueryCapability {
                    queue_type: QueueType::try_from_primitive(<Le32 as Into<u32>>::into(
                        body.queue_type,
                    ))
                    .map_err(|_| {
                        VuVideoError::UnexpectedArgValue(stringify!(body.queue_type).to_string())
                    })?,
                }
            }
            VIRTIO_VIDEO_CMD_QUERY_CONTROL => {
                let body: virtio_video_query_control = read_body!(true)?;
                QueryControl {
                    control: ControlType::try_from_primitive(<Le32 as Into<u32>>::into(
                        body.control,
                    ))
                    .map_err(|_| {
                        VuVideoError::UnexpectedArgValue(stringify!(body.control).to_string())
                    })?,
                    format: Format::try_from_primitive(<Le32 as Into<u32>>::into(body.fmt.format))
                        .map_err(|_| {
                            VuVideoError::UnexpectedArgValue(
                                stringify!(body.fmt.format).to_string(),
                            )
                        })?,
                }
            }
            VIRTIO_VIDEO_CMD_STREAM_CREATE => {
                let body: virtio_video_stream_create = read_body!(true)?;
                StreamCreate {
                    stream_id: body.hdr.stream_id.into(),
                    in_memory_type: MemoryType::try_from_primitive(<Le32 as Into<u32>>::into(
                        body.in_mem_type,
                    ))
                    .map_err(|_| {
                        VuVideoError::UnexpectedArgValue(stringify!(body.in_mem_type).to_string())
                    })?,
                    out_memory_type: MemoryType::try_from_primitive(<Le32 as Into<u32>>::into(
                        body.out_mem_type,
                    ))
                    .map_err(|_| {
                        VuVideoError::UnexpectedArgValue(stringify!(body.out_mem_type).to_string())
                    })?,
                    coded_format: Format::try_from_primitive(<Le32 as Into<u32>>::into(
                        body.coded_format,
                    ))
                    .map_err(|_| {
                        VuVideoError::UnexpectedArgValue(stringify!(body.format).to_string())
                    })?,
                }
            }
            VIRTIO_VIDEO_CMD_STREAM_DESTROY => {
                let body: virtio_video_cmd_hdr = read_body!(true)?;
                StreamDestroy {
                    stream_id: body.stream_id.into(),
                }
            }
            VIRTIO_VIDEO_CMD_STREAM_DRAIN => {
                let body: virtio_video_cmd_hdr = read_body!(true)?;
                StreamDrain {
                    stream_id: body.stream_id.into(),
                }
            }
            VIRTIO_VIDEO_CMD_RESOURCE_CREATE => {
                let body: virtio_video_resource_create = read_body!(true)?;
                ResourceCreate {
                    stream_id: body.hdr.stream_id.into(),
                    queue_type: QueueType::try_from_primitive(<Le32 as Into<u32>>::into(
                        body.queue_type,
                    ))
                    .map_err(|_| {
                        VuVideoError::UnexpectedArgValue(stringify!(body.queue_type).to_string())
                    })?,
                    resource_id: body.resource_id.into(),
                    planes_layout: body.planes_layout.into(),
                    plane_offsets: body.plane_offsets
                        [0..<Le32 as Into<u32>>::into(body.num_planes) as usize]
                        .iter()
                        .map(|x| Into::<u32>::into(*x))
                        .collect::<Vec<u32>>(),
                }
            }
            VIRTIO_VIDEO_CMD_RESOURCE_QUEUE => {
                let body: virtio_video_resource_queue = read_body!(true)?;
                ResourceQueue {
                    stream_id: body.hdr.stream_id.into(),
                    queue_type: QueueType::try_from_primitive(<Le32 as Into<u32>>::into(
                        body.queue_type,
                    ))
                    .map_err(|_| {
                        VuVideoError::UnexpectedArgValue(stringify!(body.queue_type).to_string())
                    })?,
                    resource_id: body.resource_id.into(),
                    timestamp: body.timestamp.into(),
                    data_sizes: body.data_sizes
                        [0..<Le32 as Into<u32>>::into(body.num_data_sizes) as usize]
                        .iter()
                        .map(|x| Into::<u32>::into(*x))
                        .collect::<Vec<u32>>(),
                }
            }
            VIRTIO_VIDEO_CMD_RESOURCE_DESTROY_ALL => {
                let body: virtio_video_get_params = read_body!(true)?;
                ResourceDestroyAll {
                    stream_id: body.hdr.stream_id.into(),
                    queue_type: QueueType::try_from_primitive(<Le32 as Into<u32>>::into(
                        body.queue_type,
                    ))
                    .map_err(|_| {
                        VuVideoError::UnexpectedArgValue(stringify!(body.queue_type).to_string())
                    })?,
                }
            }
            VIRTIO_VIDEO_CMD_QUEUE_CLEAR => {
                let body: virtio_video_get_params = read_body!(true)?;
                QueueClear {
                    stream_id: body.hdr.stream_id.into(),
                    queue_type: QueueType::try_from_primitive(<Le32 as Into<u32>>::into(
                        body.queue_type,
                    ))
                    .map_err(|_| {
                        VuVideoError::UnexpectedArgValue(stringify!(body.queue_type).to_string())
                    })?,
                }
            }
            VIRTIO_VIDEO_CMD_GET_PARAMS_EXT => {
                let body: virtio_video_get_params = read_body!(true)?;
                GetParams {
                    stream_id: body.hdr.stream_id.into(),
                    queue_type: QueueType::try_from_primitive(<Le32 as Into<u32>>::into(
                        body.queue_type,
                    ))
                    .map_err(|_| {
                        VuVideoError::UnexpectedArgValue(stringify!(body.queue_type).to_string())
                    })?,
                }
            }
            VIRTIO_VIDEO_CMD_SET_PARAMS_EXT => {
                let body: virtio_video_set_params = read_body!(true)?;
                SetParams {
                    stream_id: body.hdr.stream_id.into(),
                    queue_type: QueueType::try_from_primitive(<Le32 as Into<u32>>::into(
                        body.params.queue_type,
                    ))
                    .map_err(|_| {
                        VuVideoError::UnexpectedArgValue(stringify!(body.queue_type).to_string())
                    })?,
                    params: body.params,
                }
            }
            VIRTIO_VIDEO_CMD_GET_CONTROL => {
                let body: virtio_video_get_control = read_body!(true)?;
                GetControl {
                    stream_id: body.hdr.stream_id.into(),
                    control: ControlType::try_from_primitive(<Le32 as Into<u32>>::into(
                        body.control,
                    ))
                    .map_err(|_| {
                        VuVideoError::UnexpectedArgValue(stringify!(body.control).to_string())
                    })?,
                }
            }
            _ => return Err(vhu_video::VuVideoError::InvalidCmdType(header.type_.into())),
        })
    }
}

#[repr(C)]
#[derive(Copy, Clone, Debug, Default)]
pub(crate) struct virtio_video_cmd_hdr {
    pub type_: Le32,
    pub stream_id: Le32,
}

// SAFETY: The layout of the structure is fixed and can be initialized by
// reading its content from byte array.
unsafe impl ByteValued for virtio_video_cmd_hdr {}

/// Requests
#[repr(C)]
#[derive(Copy, Clone, Debug, Default)]
pub(crate) struct virtio_video_query_capability {
    pub hdr: virtio_video_cmd_hdr,
    pub queue_type: Le32,
    pub padding: Le32,
}

// SAFETY: The layout of the structure is fixed and can be initialized by
// reading its content from byte array.
unsafe impl ByteValued for virtio_video_query_capability {}

#[repr(C)]
#[derive(Copy, Clone, Debug, Default)]
pub(crate) struct virtio_video_query_control_format {
    pub format: Le32,
    pub padding: Le32,
}

#[repr(C)]
#[derive(Copy, Clone, Debug, Default)]
pub(crate) struct virtio_video_query_control {
    pub hdr: virtio_video_cmd_hdr,
    pub control: Le32,
    pub padding: Le32,
    pub fmt: virtio_video_query_control_format,
}

// SAFETY: The layout of the structure is fixed and can be initialized by
// reading its content from byte array.
unsafe impl ByteValued for virtio_video_query_control {}

#[repr(C)]
#[derive(Copy, Clone, Debug, Default)]
pub(crate) struct virtio_video_stream_create {
    pub hdr: virtio_video_cmd_hdr,
    pub in_mem_type: Le32,
    pub out_mem_type: Le32,
    pub coded_format: Le32,
    pub padding: u32,
    pub tag: [[u8; 32]; 2],
}

// SAFETY: The layout of the structure is fixed and can be initialized by
// reading its content from byte array.
unsafe impl ByteValued for virtio_video_stream_create {}

#[repr(C)]
#[derive(Copy, Clone, Debug, Default)]
pub(crate) struct virtio_video_resource_create {
    pub hdr: virtio_video_cmd_hdr,
    pub queue_type: Le32,
    pub resource_id: Le32,
    pub planes_layout: Le32,
    pub num_planes: Le32,
    pub plane_offsets: [Le32; VIRTIO_VIDEO_MAX_PLANES as usize],
    pub num_entries: [Le32; VIRTIO_VIDEO_MAX_PLANES as usize],
}

// SAFETY: The layout of the structure is fixed and can be initialized by
// reading its content from byte array.
unsafe impl ByteValued for virtio_video_resource_create {}

#[repr(C)]
#[derive(Copy, Clone, Debug, Default)]
pub(crate) struct virtio_video_resource_queue {
    pub hdr: virtio_video_cmd_hdr,
    pub queue_type: Le32,
    pub resource_id: Le32,
    pub timestamp: Le64,
    pub num_data_sizes: Le32,
    pub data_sizes: [Le32; VIRTIO_VIDEO_MAX_PLANES as usize],
    pub padding: Le32,
}

// SAFETY: The layout of the structure is fixed and can be initialized by
// reading its content from byte array.
unsafe impl ByteValued for virtio_video_resource_queue {}

#[repr(C)]
#[derive(Copy, Clone, Debug, Default)]
pub(crate) struct virtio_video_get_params {
    pub hdr: virtio_video_cmd_hdr,
    pub queue_type: Le32,
    pub padding: Le32,
}

// SAFETY: The layout of the structure is fixed and can be initialized by
// reading its content from byte array.
unsafe impl ByteValued for virtio_video_get_params {}

#[repr(C)]
#[derive(Copy, Clone, Debug, Default)]
pub(crate) struct virtio_video_set_params {
    pub hdr: virtio_video_cmd_hdr,
    pub params: virtio_video_params,
}

// SAFETY: The layout of the structure is fixed and can be initialized by
// reading its content from byte array.
unsafe impl ByteValued for virtio_video_set_params {}

#[repr(C)]
#[derive(Copy, Clone, Debug, Default)]
pub(crate) struct virtio_video_get_control {
    pub hdr: virtio_video_cmd_hdr,
    pub control: Le32,
    pub padding: Le32,
}

// SAFETY: The layout of the structure is fixed and can be initialized by
// reading its content from byte array.
unsafe impl ByteValued for virtio_video_get_control {}

#[repr(C)]
#[derive(Copy, Clone, Debug, Default)]
pub struct virtio_video_format_range {
    pub min: Le32,
    pub max: Le32,
    pub step: Le32,
    pub padding: Le32,
}

impl From<u32> for virtio_video_format_range {
    fn from(range: u32) -> Self {
        Self {
            min: range.into(),
            max: range.into(),
            step: 0.into(),
            padding: 0.into(),
        }
    }
}

// SAFETY: The layout of the structure is fixed and can be initialized by
// reading its content from byte array.
unsafe impl ByteValued for virtio_video_format_range {}

#[repr(C)]
#[derive(Clone, Debug, Default)]
pub struct virtio_video_format_frame {
    pub width: virtio_video_format_range,
    pub length: virtio_video_format_range,
    pub num_rates: Le32,
    pub padding: Le32,
    pub frame_rates: Vec<virtio_video_format_range>,
}

impl virtio_video_format_frame {
    pub fn append_frame_rates(&mut self, frames: &mut Vec<virtio_video_format_range>) {
        self.frame_rates.append(frames);
        self.num_rates = (self.frame_rates.len() as u32).into();
    }
}

impl ToBytes for virtio_video_format_frame {
    fn to_bytes(&self) -> Vec<u8> {
        let mut ret = [
            self.width.as_slice(),
            self.length.as_slice(),
            self.num_rates.as_slice(),
            self.padding.as_slice(),
        ]
        .concat();
        self.frame_rates
            .iter()
            .for_each(|frame_rate| ret.extend_from_slice(frame_rate.as_slice()));
        ret
    }
}

#[repr(C)]
#[derive(Clone, Debug, Default)]
pub struct virtio_video_format_desc {
    mask: Le64,
    pub format: Le32,
    pub planes_layout: Le32,
    plane_align: Le32,
    num_frames: Le32,
    frames: Vec<virtio_video_format_frame>,
}

impl virtio_video_format_desc {
    pub fn append_frames(&mut self, frames: &mut Vec<virtio_video_format_frame>) {
        self.frames.append(frames);
        self.num_frames = (self.frames.len() as u32).into();
    }

    pub fn generate_mask(&mut self, num_formats: usize) {
        self.mask = (u64::MAX >> (64 - num_formats)).into();
    }
}

impl ToBytes for virtio_video_format_desc {
    fn to_bytes(&self) -> Vec<u8> {
        let mut ret = [
            self.mask.as_slice(),
            self.format.as_slice(),
            self.planes_layout.as_slice(),
            self.plane_align.as_slice(),
            self.num_frames.as_slice(),
        ]
        .concat();
        self.frames
            .iter()
            .for_each(|frames| ret.append(&mut frames.to_bytes()));
        ret
    }
}

#[repr(C)]
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct virtio_video_plane_format {
    pub plane_size: Le32,
    pub stride: Le32,
}

#[repr(C)]
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct virtio_video_crop {
    pub left: Le32,
    pub top: Le32,
    pub width: Le32,
    pub heigth: Le32,
}

#[repr(C)]
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct virtio_video_params {
    pub queue_type: Le32,
    pub format: Le32,
    pub frame_width: Le32,
    pub frame_heigth: Le32,
    pub min_buffers: Le32,
    pub max_buffers: Le32,
    pub crop: virtio_video_crop,
    pub frame_rate: Le32,
    pub num_planes: Le32,
    pub plane_formats: [virtio_video_plane_format; VIRTIO_VIDEO_MAX_PLANES as usize],
    pub resource_type: Le32,
    pub padding: Le32,
}

// SAFETY: The layout of the structure is fixed and can be initialized by
// reading its content from byte array.
unsafe impl ByteValued for virtio_video_params {}

#[repr(C)]
#[derive(Copy, Clone, Debug, Default)]
pub struct virtio_video_mem_entry {
    pub addr: Le64,
    pub length: Le32,
    pub padding: Le32,
}

#[repr(C)]
#[derive(Copy, Clone, Debug, Default)]
pub struct SingleLayoutBuffer(pub virtio_video_mem_entry);

impl SingleLayoutBuffer {
    pub fn raw_addr(&self) -> u64 {
        self.0.addr.into()
    }

    pub fn raw_len(&self) -> u32 {
        self.0.length.into()
    }
}

// SAFETY: The layout of the structure is fixed and can be initialized by
// reading its content from byte array.
unsafe impl ByteValued for SingleLayoutBuffer {}

/// Responses
#[repr(C)]
#[derive(Clone, Debug, Default)]
pub(crate) struct virtio_video_query_capability_resp {
    pub hdr: virtio_video_cmd_hdr,
    pub num_descs: Le32,
    pub padding: Le32,
    pub descs: Vec<virtio_video_format_desc>,
}

impl virtio_video_query_capability_resp {
    pub fn append_descs(&mut self, descs: &Vec<virtio_video_format_desc>) {
        for desc in descs {
            self.descs.push(desc.clone());
        }
        self.num_descs = (self.descs.len() as u32).into();
    }
}

impl ToBytes for virtio_video_query_capability_resp {
    fn to_bytes(&self) -> Vec<u8> {
        let mut ret = [
            self.hdr.as_slice(),
            self.num_descs.as_slice(),
            self.padding.as_slice(),
        ]
        .concat();
        self.descs
            .iter()
            .for_each(|desc| ret.append(&mut desc.to_bytes()));
        ret
    }
}

#[repr(C)]
#[derive(Copy, Clone, Debug, Default)]
pub struct virtio_video_query_control_resp_value {
    pub num: Le32,
    pub padding: Le32,
    pub value: Le32,
}

#[repr(C)]
#[derive(Copy, Clone, Debug, Default)]
pub(crate) struct virtio_video_query_control_resp {
    pub hdr: virtio_video_cmd_hdr,
    pub resp: virtio_video_query_control_resp_value,
}

// SAFETY: The layout of the structure is fixed and can be initialized by
// reading its content from byte array.
unsafe impl ByteValued for virtio_video_query_control_resp {}

#[repr(C)]
#[derive(Copy, Clone, Debug, Default)]
pub(crate) struct virtio_video_get_params_resp {
    pub hdr: virtio_video_cmd_hdr,
    pub params: virtio_video_params,
}

// SAFETY: The layout of the structure is fixed and can be initialized by
// reading its content from byte array.
unsafe impl ByteValued for virtio_video_get_params_resp {}

bitflags! {
    #[derive(Copy, Clone, Debug, Default)]
    pub struct BufferFlags: u32 {
        const ERR = 1 << 0;
        const EOS = 1 << 1;
        // Encoder only
        const IFRAME = 1 << 2;
        const PFRAME = 1 << 3;
        const BFRAME = 1 << 4;
    }
}

impl From<BufferFlags> for Le32 {
    fn from(val: BufferFlags) -> Self {
        Le32::from(val.bits())
    }
}

impl From<Le32> for BufferFlags {
    fn from(value: Le32) -> Self {
        Self::from_bits_retain(<Le32 as Into<u32>>::into(value))
    }
}

#[repr(C)]
#[derive(Copy, Clone, Debug, Default)]
pub(crate) struct virtio_video_resource_queue_resp {
    pub hdr: virtio_video_cmd_hdr,
    pub timestamp: Le64,
    pub flags: BufferFlags,
    pub size: Le32,
}

// SAFETY: The layout of the structure is fixed and can be initialized by
// reading its content from byte array.
unsafe impl ByteValued for virtio_video_resource_queue_resp {}

#[repr(C)]
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub enum VideoControl {
    #[default]
    Default,
    Bitrate(Le32),
    BitratePeak(Le32),
    BitrateMode(Le32),
    ForceKeyframe(Le32),
    Profile(Le32),
    Level(Le32),
    PrependSpsPpsToIdr(Le32),
}

impl VideoControl {
    pub fn new_from_type(control_type: ControlType, value: Le32) -> Self {
        match control_type {
            ControlType::Bitrate => Self::Bitrate(value),
            ControlType::BitrateMode => Self::BitrateMode(value),
            ControlType::BitratePeak => Self::BitratePeak(value),
            ControlType::Profile => Self::Profile(value),
            ControlType::Level => Self::Level(value),
            ControlType::PrependSpsPpsToIdr => Self::PrependSpsPpsToIdr(value),
            ControlType::ForceKeyframe => Self::ForceKeyframe(value),
        }
    }

    fn get_value(&self) -> Le32 {
        match self {
            Self::Default => 0.into(),
            Self::Bitrate(value)
            | Self::BitrateMode(value)
            | Self::BitratePeak(value)
            | Self::Profile(value)
            | Self::Level(value)
            | Self::PrependSpsPpsToIdr(value)
            | Self::ForceKeyframe(value) => *value,
        }
    }
}

#[repr(C)]
#[derive(Clone, Debug, Default)]
pub(crate) struct virtio_video_get_control_resp {
    pub hdr: virtio_video_cmd_hdr,
    pub control: VideoControl,
}

pub(crate) enum VirtioVideoEventType {
    Error = 0x0100,
    DecoderResolutionChanged = 0x0200,
}

impl From<VirtioVideoEventType> for Le32 {
    fn from(val: VirtioVideoEventType) -> Self {
        Le32::from(val as u32)
    }
}

#[derive(Debug)]
pub struct virtio_video_event {
    pub event_type: Le32,
    pub stream_id: Le32,
}

impl ToBytes for virtio_video_event {
    fn to_bytes(&self) -> Vec<u8> {
        [self.event_type.as_slice(), self.stream_id.as_slice()].concat()
    }
}
