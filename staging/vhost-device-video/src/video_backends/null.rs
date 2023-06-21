// SPDX-License-Identifier: Apache-2.0 or BSD-3-Clause

use std::{io, path::Path};

use log::info;

use super::{DqBufData, VideoBackend};
use crate::{
    stream::ResourcePlane,
    video::{self, CmdError::*, CmdResponseType::Sync},
};

pub struct NullBackend;

impl VideoBackend for NullBackend {
    fn create_stream(
        &mut self,
        stream_id: u32,
        _in_memory_type: u32,
        _out_memory_type: u32,
        _coded_format: u32,
    ) -> video::CmdResponseType {
        info!("null backend => Creating stream: {}", stream_id);
        Sync(video::CmdResponse::OkNoData)
    }

    fn destroy_stream(&mut self, stream_id: u32) -> video::CmdResponseType {
        info!("null backend => Destroying stream: {}", stream_id);
        Sync(video::CmdResponse::OkNoData)
    }

    fn queue_resource(
        &mut self,
        stream_id: u32,
        queue_type: video::QueueType,
        resource_id: u32,
        _timestamp: u64,
        _bytes_used: Vec<u32>,
    ) -> video::CmdResponseType {
        info!(
            "null backend => Queue resource ({:?} queue, id {}), stream {}",
            queue_type, resource_id, stream_id
        );
        Sync(video::CmdResponse::Error(InvalidOperation))
    }

    fn query_capability(&self, queue_type: video::QueueType) -> video::CmdResponseType {
        info!("null backend => Queue capability, queue {:?}", queue_type);
        Sync(video::CmdResponse::QueryCapability(Vec::new()))
    }

    fn query_control(&self, control: video::ControlType) -> video::CmdResponseType {
        info!("null backend => Query control: {:?}", control);
        Sync(video::CmdResponse::QueryControl(
            video::VideoControl::Default,
        ))
    }

    fn clear_queue(
        &mut self,
        stream_id: u32,
        queue_type: video::QueueType,
    ) -> video::CmdResponseType {
        info!(
            "null backend => Clear {:?} queue, stream {}",
            queue_type, stream_id
        );
        Sync(video::CmdResponse::OkNoData)
    }

    fn get_params(&self, stream_id: u32, queue_type: video::QueueType) -> video::CmdResponseType {
        info!(
            "null backend => Get {:?} queue params, stream {}",
            queue_type, stream_id
        );
        Sync(video::CmdResponse::Error(InvalidOperation))
    }

    fn set_params(
        &mut self,
        stream_id: u32,
        _params: video::virtio_video_params,
    ) -> video::CmdResponseType {
        info!("null backend => Set params, stream {}", stream_id);
        Sync(video::CmdResponse::OkNoData)
    }

    fn create_resource(
        &mut self,
        stream_id: u32,
        resource_id: u32,
        _planes_layout: u32,
        _planes: Vec<ResourcePlane>,
        queue_type: video::QueueType,
    ) -> video::CmdResponseType {
        info!(
            "null backend => Create resource {}, {:?} queue, stream {}",
            resource_id, queue_type, stream_id
        );
        Sync(video::CmdResponse::OkNoData)
    }

    fn destroy_resources(
        &mut self,
        stream_id: u32,
        queue_type: video::QueueType,
    ) -> video::CmdResponseType {
        info!(
            "null backend => Clear resources, {:?} queue, stream {}",
            queue_type, stream_id
        );
        Sync(video::CmdResponse::OkNoData)
    }

    fn drain_stream(&mut self, stream_id: u32) -> video::CmdResponseType {
        info!("null backend => Drain stream {}", stream_id);
        Sync(video::CmdResponse::OkNoData)
    }

    fn dequeue_event(&self, _stream_id: u32) -> Option<video::virtio_video_event> {
        None
    }

    fn dequeue_resource(
        &self,
        _stream_id: u32,
        _queue_type: video::QueueType,
    ) -> Option<DqBufData> {
        None
    }
}

impl NullBackend {
    pub fn new(video_path: &Path) -> io::Result<Self> {
        // Check if file exists
        std::fs::File::create(video_path)?;
        Ok(Self)
    }
}
