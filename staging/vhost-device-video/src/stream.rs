// SPDX-License-Identifier: Apache-2.0 or BSD-3-Clause

// Null Backend does not use all stream capabilities
#![cfg_attr(not(any(feature)), allow(dead_code))]

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
            return Poll::Ready(self.buffer_data.read().unwrap().clone());
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
        if let Some(waker) = self.waker().take() {
            waker.wake();
        }
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

    pub fn waker(&self) -> Option<Waker> {
        self.state.read().unwrap().waker.clone()
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
