// SPDX-License-Identifier: Apache-2.0 or BSD-3-Clause

mod null;

#[cfg(feature = "v4l2-decoder")]
mod v4l2_decoder;

use std::path::Path;

use self::null::NullBackend;
#[cfg(feature = "v4l2-decoder")]
use self::v4l2_decoder::V4L2Decoder;
use crate::{
    stream::{ResourcePlane, Stream},
    vhu_video::{BackendType, Result, VuVideoError},
    video::{
        virtio_video_event, virtio_video_params, BufferFlags, CmdResponseType, ControlType,
        QueueType,
    },
};

#[derive(Debug, Default)]
pub struct DqBufData {
    pub index: u32,
    pub flags: BufferFlags,
    pub size: u32,
}

pub trait VideoBackend {
    fn create_stream(
        &mut self,
        stream_id: u32,
        in_memory_type: u32,
        out_memory_type: u32,
        coded_format: u32,
    ) -> CmdResponseType;

    fn destroy_stream(&mut self, stream_id: u32) -> CmdResponseType;

    fn query_capability(&self, queue_type: QueueType) -> CmdResponseType;

    fn query_control(&self, control: ControlType) -> CmdResponseType;

    fn clear_queue(&mut self, stream_id: u32, queue_type: QueueType) -> CmdResponseType;

    fn get_params(&self, stream_id: u32, queue_type: QueueType) -> CmdResponseType;

    fn set_params(&mut self, stream_id: u32, params: virtio_video_params) -> CmdResponseType;

    fn create_resource(
        &mut self,
        stream_id: u32,
        resource_id: u32,
        planes_layout: u32,
        planes: Vec<ResourcePlane>,
        queue_type: QueueType,
    ) -> CmdResponseType;

    fn destroy_resources(&mut self, stream_id: u32, queue_type: QueueType) -> CmdResponseType;

    fn queue_resource(
        &mut self,
        stream_id: u32,
        queue_type: QueueType,
        resource_id: u32,
        timestamp: u64,
        bytes_used: Vec<u32>,
    ) -> CmdResponseType;

    fn dequeue_resource(&self, stream_id: u32, queue_type: QueueType) -> Option<DqBufData>;

    fn drain_stream(&mut self, stream_id: u32) -> CmdResponseType;

    fn dequeue_event(&self, stream_id: u32) -> Option<virtio_video_event>;

    fn stream(&self, _stream_id: &u32) -> Option<&Stream> {
        None
    }

    fn stream_mut(&mut self, _stream_id: &u32) -> Option<&mut Stream> {
        None
    }
}

pub(crate) fn alloc_video_backend(
    backend: BackendType,
    video_path: &Path,
) -> Result<Box<dyn VideoBackend + Sync + Send>> {
    macro_rules! build_backend {
        ($type:ident) => {
            Box::new($type::new(video_path).map_err(|_| VuVideoError::AccessVideoDeviceFile)?)
        };
    }
    Ok(match backend {
        BackendType::Null => build_backend!(NullBackend),
        #[cfg(feature = "v4l2-decoder")]
        BackendType::V4L2Decoder => build_backend!(V4L2Decoder),
    })
}
