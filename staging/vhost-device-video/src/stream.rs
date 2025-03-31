// SPDX-License-Identifier: Apache-2.0 or BSD-3-Clause

// Null Backend does not use all stream capabilities
#![cfg_attr(not(any(feature = "default")), allow(dead_code))]

use std::{
    collections::HashMap,
    fs::File,
    future::Future,
    os::fd::AsRawFd,
    path::Path,
    pin::Pin,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc, RwLock,
    },
    task::{Context, Poll, Waker},
};

use num_enum::TryFromPrimitive;

use crate::{
    vhu_video::{Result, VuVideoError},
    video::{BufferFlags, Format, MemoryType, QueueType},
};

#[repr(C)]
#[derive(Clone, Debug, Default)]
pub struct ResourcePlane {
    pub offset: u32,
    pub address: u64,
    pub length: u32,
}

#[repr(u32)]
#[derive(Clone, Debug, Default, TryFromPrimitive, Eq, PartialEq)]
pub enum ResourceState {
    #[default]
    Created = 1,
    Queried,
    Queued,
    Ready,
}

#[derive(Clone, Debug, Default)]
pub struct SharedResourceState {
    value: ResourceState,
    waker: Option<Waker>,
}

impl SharedResourceState {
    pub fn is_ready(&self) -> bool {
        matches!(self.value, ResourceState::Ready)
    }

    pub fn set_queried(&mut self) {
        self.set_state(ResourceState::Queried);
    }

    pub fn set_queued(&mut self) {
        self.set_state(ResourceState::Queued);
    }

    pub fn set_ready(&mut self) {
        self.set_state(ResourceState::Ready);
        if let Some(waker) = self.waker.take() {
            waker.wake();
        }
    }

    fn set_state(&mut self, state: ResourceState) {
        self.value = state;
    }
}

#[derive(Clone, Debug, Default)]
pub struct BufferData {
    pub timestamp: u64,
    pub flags: BufferFlags,
    pub size: u32,
}

impl BufferData {
    pub fn set_data(&mut self, flags: BufferFlags, size: u32) {
        self.flags = flags;
        self.size = size;
    }
}

#[repr(C)]
#[derive(Clone, Debug, Default)]
pub struct Resource {
    pub stream_id: u32,
    pub resource_id: u32,
    state: Arc<RwLock<SharedResourceState>>,
    pub index: u32,
    pub queue_type: QueueType,
    pub buffer_data: Arc<RwLock<BufferData>>,
    pub planes_layout: u32,
    pub planes: Vec<ResourcePlane>,
}

impl Future for Resource {
    type Output = BufferData;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        if self.is_ready() {
            Poll::Ready(self.buffer_data.read().unwrap().clone())
        } else {
            self.state.write().unwrap().waker = Some(cx.waker().clone());
            Poll::Pending
        }
    }
}

impl Resource {
    pub fn state(&self) -> ResourceState {
        self.state.read().unwrap().value.clone()
    }

    pub fn ready_with(&mut self, flags: BufferFlags, size: u32) {
        self.buffer_data.write().unwrap().set_data(flags, size);
        self.set_ready();
    }

    pub fn set_ready(&mut self) {
        self.state.write().unwrap().set_ready();
    }

    pub fn is_ready(&self) -> bool {
        self.state.read().unwrap().is_ready()
    }

    pub fn set_queried(&mut self) {
        self.state.write().unwrap().set_queried();
    }

    pub fn set_queued(&mut self) {
        self.state.write().unwrap().set_queued();
    }
}

#[repr(u32)]
#[derive(Clone, Debug, Default, TryFromPrimitive, Eq, PartialEq)]
pub enum StreamState {
    #[default]
    Stopped = 1,
    Subscribed,
    Streaming,
    Draining,
    Destroying,
    Destroyed,
}

#[derive(Clone, Debug)]
pub struct AtomicStreamState {
    state: Arc<AtomicUsize>,
}

impl AtomicStreamState {
    pub fn new(state: StreamState) -> Self {
        Self {
            state: Arc::new(AtomicUsize::new(state as usize)),
        }
    }

    pub fn state(&self) -> StreamState {
        StreamState::try_from_primitive(self.state.load(Ordering::SeqCst) as u32)
            .expect("Unexpected Stream state")
    }

    pub fn set_state(&mut self, state: StreamState) {
        self.state.store(state as usize, Ordering::SeqCst)
    }
}

#[derive(Default, Debug, Clone)]
pub struct ResourcesMap {
    pub map: HashMap<u32, Resource>,
    pub streaming: bool,
}

impl ResourcesMap {
    fn find_mut_by_index(&mut self, v4l2_index: u32) -> Option<&mut Resource> {
        self.map
            .iter_mut()
            .find_map(|(_k, v)| if v.index == v4l2_index { Some(v) } else { None })
    }

    fn resources(&self) -> Vec<&Resource> {
        self.map.values().collect()
    }

    fn resources_mut(&mut self) -> Vec<&mut Resource> {
        self.map.values_mut().collect()
    }
}

#[repr(C)]
#[derive(Debug, Clone)]
pub struct Stream {
    pub stream_id: u32,
    pub file: Arc<File>,
    state: AtomicStreamState,
    pub in_memory_type: MemoryType,
    pub out_memory_type: MemoryType,
    pub coded_format: Format,
    pub inputq_resources: ResourcesMap,
    pub outputq_resources: ResourcesMap,
}

impl AsRawFd for Stream {
    fn as_raw_fd(&self) -> i32 {
        self.file.as_raw_fd()
    }
}

impl Stream {
    pub(crate) fn new(
        stream_id: u32,
        device_path: &Path,
        in_memory_type: u32,
        out_memory_type: u32,
        coded_format: u32,
    ) -> Result<Self> {
        Ok(Self {
            stream_id,
            file: Arc::new(File::create(device_path).unwrap()),
            state: AtomicStreamState::new(StreamState::default()),
            in_memory_type: MemoryType::try_from_primitive(in_memory_type)
                .map_err(|_| VuVideoError::VideoStreamCreate)?,
            out_memory_type: MemoryType::try_from_primitive(out_memory_type)
                .map_err(|_| VuVideoError::VideoStreamCreate)?,
            coded_format: Format::try_from_primitive(coded_format)
                .map_err(|_| VuVideoError::VideoStreamCreate)?,
            inputq_resources: Default::default(),
            outputq_resources: Default::default(),
        })
    }

    pub fn memory(&self, queue_type: QueueType) -> MemoryType {
        match queue_type {
            QueueType::InputQueue => self.in_memory_type,
            QueueType::OutputQueue => self.out_memory_type,
        }
    }

    pub fn find_resource(&self, resource_id: u32, queue_type: QueueType) -> Option<&Resource> {
        match queue_type {
            QueueType::InputQueue => self.inputq_resources.map.get(&resource_id),
            QueueType::OutputQueue => self.outputq_resources.map.get(&resource_id),
        }
    }

    pub fn find_resource_mut_by_index(
        &mut self,
        v4l2_index: u32,
        queue_type: QueueType,
    ) -> Option<&mut Resource> {
        match queue_type {
            QueueType::InputQueue => self.inputq_resources.find_mut_by_index(v4l2_index),
            QueueType::OutputQueue => self.outputq_resources.find_mut_by_index(v4l2_index),
        }
    }

    pub fn find_resource_mut(
        &mut self,
        resource_id: u32,
        queue_type: QueueType,
    ) -> Option<&mut Resource> {
        match queue_type {
            QueueType::InputQueue => self.inputq_resources.map.get_mut(&resource_id),
            QueueType::OutputQueue => self.outputq_resources.map.get_mut(&resource_id),
        }
    }

    pub fn is_queue_streaming(&self, queue_type: QueueType) -> bool {
        match queue_type {
            QueueType::InputQueue => self.inputq_resources.streaming,
            QueueType::OutputQueue => self.outputq_resources.streaming,
        }
    }

    pub fn set_queue_streaming(&mut self, queue_type: QueueType) {
        match queue_type {
            QueueType::InputQueue => self.inputq_resources.streaming = true,
            QueueType::OutputQueue => self.outputq_resources.streaming = true,
        }
    }

    pub fn set_state(&mut self, state: StreamState) {
        self.state.set_state(state);
    }

    pub fn state(&self) -> StreamState {
        self.state.state()
    }

    pub fn all_created(&self, queue_type: QueueType) -> bool {
        self.all_resources_state(queue_type, ResourceState::Created)
    }

    fn all_resources_state(&self, queue_type: QueueType, state: ResourceState) -> bool {
        match queue_type {
            QueueType::InputQueue => self
                .inputq_resources
                .resources()
                .into_iter()
                .all(|x| x.state() == state),
            QueueType::OutputQueue => self
                .outputq_resources
                .resources()
                .into_iter()
                .all(|x| x.state() == state),
        }
    }

    pub fn resources_mut(&mut self, queue_type: QueueType) -> Vec<&mut Resource> {
        match queue_type {
            QueueType::InputQueue => self.inputq_resources.resources_mut(),
            QueueType::OutputQueue => self.outputq_resources.resources_mut(),
        }
    }

    pub fn queued_resources_mut(&mut self, queue_type: QueueType) -> Vec<&mut Resource> {
        self.resources_mut(queue_type)
            .into_iter()
            .filter(|x| (*x).state() == ResourceState::Queued)
            .collect()
    }

    /// Inserts a new resource into the specific queue map.
    /// If the map did not have this resource ID present, None is returned.
    /// If the map did have this resource ID present, the value is updated, and
    /// the old value is returned. The ID is not updated.
    pub fn add_resource(
        &mut self,
        resource_id: u32,
        planes_layout: u32,
        planes: Vec<ResourcePlane>,
        queue_type: QueueType,
    ) -> Option<Resource> {
        let mut resource = Resource {
            stream_id: self.stream_id,
            resource_id,
            queue_type,
            planes_layout,
            ..Default::default()
        };
        resource.planes = planes;
        match queue_type {
            QueueType::InputQueue => {
                resource.index = self.inputq_resources.map.len() as u32;
                self.inputq_resources.map.insert(resource_id, resource)
            }
            QueueType::OutputQueue => {
                resource.index = self.outputq_resources.map.len() as u32;
                self.outputq_resources.map.insert(resource_id, resource)
            }
        }
    }

    pub fn empty_resources(&mut self, queue_type: QueueType) {
        match queue_type {
            QueueType::InputQueue => self.inputq_resources.map.clear(),
            QueueType::OutputQueue => self.outputq_resources.map.clear(),
        }
    }
}

#[cfg(test)]
mod tests {
    use assert_matches::assert_matches;
    use rstest::*;
    use tempfile::TempDir;

    use super::*;
    use crate::vhu_video::tests::{test_dir, VideoDeviceMock};

    const TEST_PLANES: [ResourcePlane; 1] = [ResourcePlane {
        offset: 0,
        address: 0x100,
        length: 1024,
    }];
    const INVALID_MEM_TYPE: u32 = (MemoryType::VirtioObject as u32) + 1;
    const INVALID_FORMAT: u32 = (Format::Fwht as u32) + 1;

    #[rstest]
    fn test_video_stream(test_dir: TempDir) {
        let stream_id: u32 = 1;
        let v4l2_device = VideoDeviceMock::new(&test_dir);
        let resource_id: u32 = 1;
        let mut stream = Stream::new(
            stream_id,
            Path::new(&v4l2_device.path),
            MemoryType::GuestPages as u32,
            MemoryType::VirtioObject as u32,
            Format::Fwht as u32,
        )
        .expect("Failed to create stream");
        assert_matches!(stream.memory(QueueType::InputQueue), MemoryType::GuestPages);
        assert_matches!(
            stream.memory(QueueType::OutputQueue),
            MemoryType::VirtioObject
        );

        // Add resource
        let planes_layout = 0;
        let res = stream.add_resource(
            resource_id,
            planes_layout,
            Vec::from(TEST_PLANES),
            QueueType::InputQueue,
        );
        assert!(res.is_none());
        // Resource is retrievable
        {
            let res = stream.find_resource_mut(resource_id, QueueType::InputQueue);
            assert!(res.is_some());
            let res = res.unwrap();
            assert_eq!(res.planes_layout, planes_layout);
            assert_eq!(res.queue_type, QueueType::InputQueue);
            assert_eq!(res.state(), ResourceState::Created);
            // Query resource
            res.set_queried();
        }
        assert!(stream.all_resources_state(QueueType::InputQueue, ResourceState::Queried));
        {
            let res = stream
                .find_resource_mut(resource_id, QueueType::InputQueue)
                .unwrap();
            // Queue resource
            res.set_queued();
        }
        // Start streaming
        assert!(!stream.is_queue_streaming(QueueType::InputQueue));
        stream.set_queue_streaming(QueueType::InputQueue);
        assert!(stream.is_queue_streaming(QueueType::InputQueue));
        assert!(stream.all_resources_state(QueueType::InputQueue, ResourceState::Queued));
        // Resource can be found by index
        assert!(stream
            .find_resource_mut_by_index(0, QueueType::InputQueue)
            .is_some());
        {
            let res = stream
                .find_resource_mut(resource_id, QueueType::InputQueue)
                .unwrap();
            // Ready up resource
            res.set_ready();
        }
        assert!(stream.all_resources_state(QueueType::InputQueue, ResourceState::Ready));
        // Clean resources
        stream.empty_resources(QueueType::InputQueue);
        assert!(stream.resources_mut(QueueType::InputQueue).is_empty());
    }

    #[rstest]
    #[case::invalid_in_mem(
        INVALID_MEM_TYPE, MemoryType::GuestPages as u32, Format::Fwht as u32)]
    #[case::invalid_out_mem(
        MemoryType::VirtioObject as u32, INVALID_MEM_TYPE, Format::Nv12 as u32)]
    #[case::invalid_format(
        MemoryType::VirtioObject as u32, MemoryType::VirtioObject as u32, INVALID_FORMAT)]
    fn test_video_stream_failures(
        test_dir: TempDir,
        #[case] in_mem: u32,
        #[case] out_mem: u32,
        #[case] format: u32,
    ) {
        let stream_id: u32 = 1;
        let v4l2_device = VideoDeviceMock::new(&test_dir);
        assert_matches!(
            Stream::new(
                stream_id,
                Path::new(&v4l2_device.path),
                in_mem,
                out_mem,
                format
            )
            .unwrap_err(),
            VuVideoError::VideoStreamCreate
        );
    }
}
