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

#[cfg(test)]
mod tests {

    use assert_matches::assert_matches;
    use rstest::*;
    use tempfile::TempDir;
    use vm_memory::Le32;

    use super::*;
    use crate::vhu_video::tests::{test_dir, VideoDeviceMock};

    #[rstest]
    fn test_backend_trait(test_dir: TempDir) {
        use video::{CmdResponse::*, CmdResponseType::*};
        // Mock video device, will not answer to requests
        let v4l2_device = VideoDeviceMock::new(&test_dir);
        let mut decoder = NullBackend::new(Path::new(&v4l2_device.path)).unwrap();
        let stream_id = 1;
        let invalid_stream_id = 2;
        let resource_id = 1;
        let queue_type = video::QueueType::OutputQueue;
        // Create stream
        assert_matches!(decoder.create_stream(stream_id, 1, 1, 1), Sync(OkNoData));
        // Null backend does not store any stream, thus it never fetches any
        assert_matches!(decoder.stream(&stream_id), None);
        assert_matches!(decoder.stream_mut(&stream_id), None);
        assert_matches!(decoder.stream(&invalid_stream_id), None);
        assert_matches!(decoder.stream_mut(&invalid_stream_id), None);
        // Check capabilities, control, params
        assert_matches!(
            decoder.query_capability(queue_type),
            Sync(QueryCapability(_))
        );
        assert_matches!(
            decoder.query_control(video::ControlType::Bitrate),
            Sync(QueryControl(_))
        );
        let params = video::virtio_video_params {
            queue_type: <u32 as Into<Le32>>::into(queue_type as u32),
            ..Default::default()
        };
        assert_matches!(decoder.set_params(stream_id, params), Sync(OkNoData));
        // Create resource, queue, and dequeue it
        assert_matches!(
            decoder.create_resource(stream_id, resource_id, 1, Vec::new(), queue_type),
            Sync(OkNoData)
        );
        assert_matches!(
            decoder.queue_resource(stream_id, queue_type, resource_id, 0, vec![0]),
            Sync(Error(video::CmdError::InvalidOperation))
        );
        assert_matches!(decoder.dequeue_resource(stream_id, queue_type), None);
        // End of stream
        assert_matches!(decoder.drain_stream(stream_id), Sync(OkNoData));
        assert_matches!(
            decoder.destroy_resources(stream_id, queue_type),
            Sync(OkNoData)
        );
    }

    #[rstest]
    fn test_backend_trait_errors(test_dir: TempDir) {
        use video::{CmdResponse::*, CmdResponseType::*};
        let stream_id = 1;
        let resource_id = 1;
        let queue_type = video::QueueType::OutputQueue;
        let params = video::virtio_video_params {
            queue_type: <u32 as Into<Le32>>::into(queue_type as u32),
            ..Default::default()
        };
        let v4l2_device = VideoDeviceMock::new(&test_dir);
        let mut decoder = NullBackend::new(Path::new(&v4l2_device.path)).unwrap();
        assert_matches!(decoder.set_params(stream_id, params), Sync(OkNoData));
        assert_matches!(
            decoder.create_resource(stream_id, resource_id, 1, Vec::new(), queue_type),
            Sync(OkNoData)
        );
        assert_matches!(
            decoder.queue_resource(stream_id, queue_type, resource_id, 0, vec![0]),
            Sync(Error(video::CmdError::InvalidOperation))
        );
        assert_matches!(decoder.dequeue_resource(stream_id, queue_type), None);
        assert_matches!(decoder.drain_stream(stream_id), Sync(OkNoData));
        assert_matches!(
            decoder.destroy_resources(stream_id, queue_type),
            Sync(OkNoData)
        );
    }
}
