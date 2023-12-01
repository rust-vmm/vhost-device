// SPDX-License-Identifier: Apache-2.0 or BSD-3-Clause

use std::{
    fs::File,
    mem::size_of,
    ops::Deref,
    os::unix::io::{AsRawFd, FromRawFd},
    sync::{Arc, RwLock},
};

use futures_executor::{ThreadPool, ThreadPoolBuilder};
use log::{debug, warn};
use vhost_user_backend::{VringEpollHandler, VringRwLock, VringT};
use virtio_queue::{Descriptor, QueueOwnedT};
use vm_memory::{
    ByteValued, Bytes, GuestAddress, GuestAddressSpace, GuestMemory, GuestMemoryAtomic,
    GuestMemoryMmap,
};
use vmm_sys_util::epoll::EventSet;

use crate::{
    stream,
    vhu_video::{self, Result, VideoDescriptorChain, VuVideoBackend, VuVideoError},
    video::{self, ToBytes},
    video_backends::VideoBackend,
};

type ArcVhostBknd = Arc<RwLock<VuVideoBackend>>;

const MAX_BUFFERS: usize = 32;

#[derive(Copy, Clone, Debug)]
pub struct TriggeredEvent {
    pub have_read: bool,
    pub have_write: bool,
    pub have_event: bool,
    pub data: u64,
}

pub enum EventType {
    None = 0,
    Read,
    Write,
    ReadWrite,
    Event,
    EventRead,
    All,
}

impl From<EventType> for epoll::Events {
    fn from(et: EventType) -> epoll::Events {
        match et {
            EventType::None => epoll::Events::EPOLLERR,
            EventType::Read => epoll::Events::EPOLLIN,
            EventType::Write => epoll::Events::EPOLLOUT,
            EventType::ReadWrite => epoll::Events::EPOLLIN | epoll::Events::EPOLLOUT,
            EventType::Event => epoll::Events::EPOLLPRI,
            EventType::EventRead => epoll::Events::EPOLLPRI | epoll::Events::EPOLLIN,
            EventType::All => {
                epoll::Events::EPOLLPRI | epoll::Events::EPOLLIN | epoll::Events::EPOLLOUT
            }
        }
    }
}

#[derive(Copy, Clone, Debug)]
pub struct PollerEvent {
    pub event: epoll::Event,
}

impl PollerEvent {
    pub fn new(et: EventType, token: u64) -> Self {
        Self {
            event: epoll::Event::new(epoll::Events::from(et), token),
        }
    }
}

impl Default for PollerEvent {
    fn default() -> Self {
        Self::new(EventType::None, 0)
    }
}

struct VideoPoller {
    /// epoll fd to which new host connections are added.
    epoll_file: File,
}

impl VideoPoller {
    fn new() -> Result<Self> {
        let poll_fd = epoll::create(true).map_err(VuVideoError::EpollFdCreate)?;
        Ok(Self {
            // SAFETY: Safe as the fd is guaranteed to be valid here.
            epoll_file: unsafe { File::from_raw_fd(poll_fd) },
        })
    }

    pub fn add(&self, fd: i32, event: PollerEvent) -> Result<()> {
        self.epoll_ctl(epoll::ControlOptions::EPOLL_CTL_ADD, fd, &event)
            .map_err(VuVideoError::EpollAdd)?;

        Ok(())
    }

    #[allow(dead_code)]
    pub fn modify(&self, fd: i32, event: PollerEvent) -> Result<()> {
        self.epoll_ctl(epoll::ControlOptions::EPOLL_CTL_MOD, fd, &event)
            .map_err(VuVideoError::EpollModify)?;

        Ok(())
    }

    pub fn remove(&self, fd: i32) -> Result<()> {
        self.epoll_ctl(epoll::ControlOptions::EPOLL_CTL_DEL, fd, None)
            .map_err(VuVideoError::EpollRemove)?;

        Ok(())
    }

    pub fn wait(&self, events: &mut [PollerEvent], timeout: i32) -> Result<Vec<TriggeredEvent>> {
        let mut events: Vec<epoll::Event> = events.iter_mut().map(|e| e.event).collect();
        match epoll::wait(self.epoll_file.as_raw_fd(), timeout, events.as_mut_slice()) {
            Ok(count) => {
                let events = events[0..count]
                    .iter()
                    .map(|epoll_event| TriggeredEvent {
                        have_read: epoll_event.events & epoll::Events::EPOLLIN.bits() != 0,
                        have_write: epoll_event.events & epoll::Events::EPOLLOUT.bits() != 0,
                        have_event: epoll_event.events & epoll::Events::EPOLLPRI.bits() != 0,
                        data: epoll_event.data,
                    })
                    .collect();
                Ok(events)
            }
            Err(e) => Err(VuVideoError::EpollWait(e)),
        }
    }

    fn epoll_ctl<'a, T>(
        &self,
        op: epoll::ControlOptions,
        fd: i32,
        event: T,
    ) -> std::result::Result<(), std::io::Error>
    where
        T: Into<Option<&'a PollerEvent>>,
    {
        let event: Option<&PollerEvent> = event.into();
        let ptr = match event.map(|x| x.event as epoll::Event) {
            Some(ev) => ev,
            None => epoll::Event::new(epoll::Events::empty(), 0),
        };
        epoll::ctl(self.epoll_file.as_raw_fd(), op, fd, ptr)
    }
}

pub(crate) trait ReadObj<T: ByteValued> {
    fn read_body(&self, index: usize, equal: bool) -> Result<T>;
}

impl<T: ByteValued> ReadObj<T> for VideoDescriptorChain {
    fn read_body(&self, index: usize, equal: bool) -> Result<T> {
        let descriptors: Vec<_> = self.clone().collect();
        let descriptor = descriptors[index];
        let request_size: usize = size_of::<T>();
        let to_read = descriptor.len() as usize;
        if equal {
            if to_read != request_size {
                return Err(VuVideoError::UnexpectedDescriptorSize(
                    request_size,
                    to_read,
                ));
            }
        } else if to_read < request_size {
            return Err(VuVideoError::UnexpectedMinimumDescriptorSize(
                request_size,
                to_read,
            ));
        }
        self.memory()
            .read_obj::<T>(descriptor.addr())
            .map_err(|_| VuVideoError::DescriptorReadFailed)
    }
}

pub(crate) struct VhostUserVideoThread {
    /// Guest memory map.
    pub mem: Option<GuestMemoryAtomic<GuestMemoryMmap>>,
    /// VIRTIO_RING_F_EVENT_IDX.
    pub event_idx: bool,
    poller: VideoPoller,
    vring_worker: Option<Arc<VringEpollHandler<ArcVhostBknd>>>,
    backend: Arc<RwLock<Box<dyn VideoBackend + Sync + Send>>>,
    /// Thread pool to handle async commands.
    pool: ThreadPool,
}

fn write_descriptor_data<T: ToBytes>(
    resp: T,
    desc_response: &Descriptor,
    desc_chain: &VideoDescriptorChain,
    vring: &VringRwLock,
) {
    if desc_chain
        .memory()
        .write_slice(resp.to_bytes().as_slice(), desc_response.addr())
        .is_err()
    {
        warn!("Descriptor write failed");
    }

    if vring
        .add_used(desc_chain.head_index(), desc_response.len())
        .is_err()
    {
        warn!("Couldn't return used descriptors to the ring");
    }
}

impl VhostUserVideoThread {
    pub fn new(backend: Arc<RwLock<Box<dyn VideoBackend + Sync + Send>>>) -> Result<Self> {
        Ok(Self {
            mem: None,
            event_idx: false,
            poller: VideoPoller::new()?,
            backend,
            vring_worker: None,
            pool: ThreadPoolBuilder::new()
                .pool_size(MAX_BUFFERS)
                .create()
                .map_err(VuVideoError::CreateThreadPool)?,
        })
    }

    pub fn set_vring_workers(&mut self, vring_worker: Arc<VringEpollHandler<ArcVhostBknd>>) {
        self.vring_worker = Some(vring_worker);
        self.vring_worker
            .as_ref()
            .unwrap()
            .register_listener(
                self.poller.epoll_file.as_raw_fd(),
                EventSet::IN,
                u64::from(vhu_video::VIDEO_EVENT),
            )
            .unwrap();
    }

    pub fn process_requests(
        &mut self,
        requests: Vec<VideoDescriptorChain>,
        vring: &VringRwLock,
    ) -> Result<bool> {
        use video::VideoCmd::*;
        if requests.is_empty() {
            return Ok(true);
        }
        for desc_chain in requests {
            let descriptors: Vec<_> = desc_chain.clone().collect();
            debug!("Video request with n descriptors: {}", descriptors.len());
            let mut desc_len: usize = 2;
            let response: video::CmdResponseType =
                match video::VideoCmd::from_descriptor(&desc_chain) {
                    Err(e) => {
                        warn!("Reading command failed: {}", e);
                        video::CmdResponseType::Sync(video::CmdResponse::Error(
                            video::CmdError::InvalidOperation,
                        ))
                    }
                    Ok(cmd) => {
                        debug!("Received command: {:?}", cmd);
                        match cmd {
                            QueryCapability { queue_type } => {
                                self.backend.read().unwrap().query_capability(queue_type)
                            }
                            QueryControl { control, format: _ } => {
                                self.backend.read().unwrap().query_control(control)
                            }
                            StreamCreate {
                                stream_id,
                                in_memory_type,
                                out_memory_type,
                                coded_format,
                            } => self.backend.write().unwrap().create_stream(
                                stream_id,
                                in_memory_type as u32,
                                out_memory_type as u32,
                                coded_format as u32,
                            ),
                            StreamDestroy { stream_id } => {
                                self.backend.write().unwrap().destroy_stream(stream_id)
                            }
                            StreamDrain { stream_id } => {
                                self.backend.write().unwrap().drain_stream(stream_id)
                            }
                            ResourceCreate {
                                stream_id,
                                queue_type,
                                resource_id,
                                planes_layout,
                                plane_offsets,
                            } => {
                                desc_len = 3;
                                let planes = self.collect_planes(&desc_chain, plane_offsets)?;
                                self.backend.write().unwrap().create_resource(
                                    stream_id,
                                    resource_id,
                                    planes_layout,
                                    planes,
                                    queue_type,
                                )
                            }
                            ResourceQueue {
                                stream_id,
                                queue_type,
                                resource_id,
                                timestamp,
                                data_sizes,
                            } => {
                                let mut backend = self.backend.write().unwrap();
                                if let Some(stream) = backend.stream_mut(&stream_id) {
                                    self.set_stream_poller(stream, stream_id as u64);
                                }
                                backend.queue_resource(
                                    stream_id,
                                    queue_type,
                                    resource_id,
                                    timestamp,
                                    data_sizes,
                                )
                            }
                            ResourceDestroyAll {
                                stream_id,
                                queue_type,
                            } => self
                                .backend
                                .write()
                                .unwrap()
                                .destroy_resources(stream_id, queue_type),
                            QueueClear {
                                stream_id,
                                queue_type,
                            } => self
                                .backend
                                .write()
                                .unwrap()
                                .clear_queue(stream_id, queue_type),
                            GetParams {
                                stream_id,
                                queue_type,
                            } => self
                                .backend
                                .write()
                                .unwrap()
                                .get_params(stream_id, queue_type),
                            SetParams {
                                stream_id,
                                queue_type: _,
                                params,
                            } => self.backend.write().unwrap().set_params(stream_id, params),
                            GetControl {
                                stream_id: _,
                                control: _,
                            } => {
                                debug!("GET_CONTROL support is not fully handled yet");
                                video::CmdResponseType::Sync(video::CmdResponse::Error(
                                    video::CmdError::UnsupportedControl,
                                ))
                            }
                        }
                    }
                };
            debug!("Response: {:?}", response);
            if descriptors.len() != desc_len {
                return Err(VuVideoError::UnexpectedDescriptorCount(descriptors.len()));
            }
            let desc_response = &descriptors[desc_len - 1];
            if !desc_response.is_write_only() {
                return Err(VuVideoError::UnexpectedReadableDescriptor(desc_len - 1));
            }
            match response {
                video::CmdResponseType::Sync(resp) => {
                    write_descriptor_data(resp, desc_response, &desc_chain, vring);
                }

                video::CmdResponseType::AsyncQueue {
                    stream_id,
                    queue_type,
                    resource_id,
                } => {
                    let backend = self.backend.read().unwrap();
                    let stream = backend.stream(&stream_id).unwrap();
                    let resource = match stream.find_resource(resource_id, queue_type) {
                        Some(res) => res.clone(),
                        None => return Err(VuVideoError::InvalidResourceId(resource_id)),
                    };
                    let vring = vring.clone();
                    let desc_response = *desc_response;
                    self.pool.spawn_ok(async move {
                        let buf_data = resource.await;
                        debug!(
                            "Dequeued resource {} ({:?}) for stream {}",
                            resource_id, queue_type, stream_id
                        );
                        let resp = video::CmdResponse::ResourceQueue {
                            timestamp: buf_data.timestamp,
                            flags: buf_data.flags.bits(),
                            size: buf_data.size,
                        };
                        write_descriptor_data(resp, &desc_response, &desc_chain, &vring);
                        if let Err(e) = vring
                            .signal_used_queue()
                            .map_err(|_| VuVideoError::SendNotificationFailed)
                        {
                            warn!("{}", e);
                        }
                    });
                    // Avoid signaling the used queue for delayed responses
                    return Ok(false);
                }
            }
        }

        Ok(true)
    }

    fn collect_planes(
        &self,
        desc_chain: &VideoDescriptorChain,
        plane_offsets: Vec<u32>,
    ) -> Result<Vec<stream::ResourcePlane>> {
        let mem: video::SingleLayoutBuffer = desc_chain.read_body(1, true)?;
        // Assumes mplanar with a single plane
        let virt_addr = self
            .atomic_mem()?
            .memory()
            .deref()
            .get_host_address(GuestAddress(mem.raw_addr()))
            .expect("Could not get the host address");
        let plane_addrs = vec![virt_addr as u64];
        let plane_lengths = vec![mem.raw_len()];
        Ok(plane_offsets
            .into_iter()
            .zip(plane_addrs)
            .zip(plane_lengths)
            .map(|((offset, address), length)| stream::ResourcePlane {
                offset,
                address,
                length,
            })
            .collect())
    }

    fn set_stream_poller(&self, stream: &stream::Stream, data: u64) {
        if stream.state() != stream::StreamState::Streaming
            && stream.state() != stream::StreamState::Draining
        {
            if let Err(e) = self
                .poller
                .add(stream.as_raw_fd(), PollerEvent::new(EventType::All, data))
            {
                warn!("Add poller events to stream ID {} failed: {}", data, e);
            }
        }
    }

    fn atomic_mem(&self) -> Result<&GuestMemoryAtomic<GuestMemoryMmap>> {
        match &self.mem {
            Some(m) => Ok(m),
            None => Err(VuVideoError::NoMemoryConfigured),
        }
    }

    /// Process the requests in the vring and dispatch replies
    pub fn process_command_queue(&mut self, vring: &VringRwLock) -> Result<()> {
        let requests: Vec<_> = vring
            .get_mut()
            .get_queue_mut()
            .iter(self.atomic_mem()?.memory())
            .map_err(|_| VuVideoError::DescriptorNotFound)?
            .collect();

        if self.process_requests(requests, vring)? {
            // Send notification once all the requests are processed
            vring
                .signal_used_queue()
                .map_err(|_| VuVideoError::SendNotificationFailed)?;
        }

        Ok(())
    }

    fn process_event(&self, stream_id: u32, eventq: &VringRwLock) -> Result<()> {
        if let Some(event) = self.backend.read().unwrap().dequeue_event(stream_id) {
            let desc_chain = eventq
                .get_mut()
                .get_queue_mut()
                .iter(self.atomic_mem()?.memory())
                .map_err(|_| VuVideoError::DescriptorNotFound)?
                .collect::<Vec<_>>()
                .pop();
            let desc_chain = match desc_chain {
                Some(desc_chain) => desc_chain,
                None => {
                    warn!("No available buffer found in the event queue.");
                    return Err(VuVideoError::DescriptorNotFound);
                }
            };
            let descriptors: Vec<_> = desc_chain.clone().collect();
            if descriptors.len() > 1 {
                return Err(VuVideoError::UnexpectedDescriptorCount(descriptors.len()));
            }
            write_descriptor_data(event, &descriptors[0], &desc_chain, eventq);
            eventq
                .signal_used_queue()
                .map_err(|_| VuVideoError::SendNotificationFailed)?;
        }

        Ok(())
    }

    fn send_dqbuf(&mut self, stream_id: u32, queue_type: video::QueueType) -> Result<()> {
        let dqbuf_data = match self
            .backend
            .read()
            .unwrap()
            .dequeue_resource(stream_id, queue_type)
        {
            Some(buf_data) => buf_data,
            None => return Ok(()),
        };
        let mut backend = self.backend.write().unwrap();
        let stream = backend.stream_mut(&stream_id).unwrap();
        if dqbuf_data.flags.contains(video::BufferFlags::EOS)
            && stream.state() == stream::StreamState::Draining
        {
            stream.set_state(stream::StreamState::Stopped);
            if let Err(e) = self.poller.remove(stream.as_raw_fd()) {
                warn!("{}", e);
            }
        }
        let resource = stream
            .find_resource_mut_by_index(dqbuf_data.index, queue_type)
            .unwrap();
        resource.ready_with(dqbuf_data.flags, dqbuf_data.size);

        Ok(())
    }

    pub fn process_video_event(&mut self, eventq: &VringRwLock) -> Result<()> {
        let mut epoll_events = vec![PollerEvent::default(); 1024];
        let events = self.poller.wait(epoll_events.as_mut_slice(), 0).unwrap();
        for event in events {
            let stream_id = event.data as u32;
            if event.have_event {
                self.process_event(stream_id, eventq)?;
            }
            if event.have_read {
                // TODO: Assumes decoder
                self.send_dqbuf(stream_id, video::QueueType::OutputQueue)?;
            }
            if event.have_write {
                // TODO: Assumes decoder
                self.send_dqbuf(stream_id, video::QueueType::InputQueue)?;
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use assert_matches::assert_matches;
    use rstest::*;
    use tempfile::TempDir;
    use virtio_bindings::virtio_ring::{VRING_DESC_F_NEXT, VRING_DESC_F_WRITE};
    use virtio_queue::{mock::MockSplitQueue, Queue};
    use vm_memory::{Address, GuestAddress};
    use vmm_sys_util::eventfd::EventFd;

    use super::*;
    use crate::{
        vhu_video::{
            tests::{test_dir, VideoDeviceMock},
            BackendType,
        },
        video::*,
        video_backends::alloc_video_backend,
    };

    #[fixture]
    fn dummy_fd() -> EventFd {
        EventFd::new(0).expect("Could not create an EventFd.")
    }

    fn build_cmd_desc_chain(request: &[u8]) -> VideoDescriptorChain {
        let mem = &GuestMemoryMmap::<()>::from_ranges(&[(GuestAddress(0), 0x1000)]).unwrap();
        let vq = MockSplitQueue::new(mem, 16);
        let mut next_addr = vq.desc_table().total_size() + 0x100;
        let mut index = 0;
        let request_size: u32 = request.len() as u32;

        // Descriptor for the video request
        let desc_request =
            Descriptor::new(next_addr, request_size, VRING_DESC_F_NEXT as u16, index + 1);
        mem.write_slice(request, desc_request.addr()).unwrap();
        vq.desc_table().store(index, desc_request).unwrap();
        next_addr += u64::from(desc_request.len());
        index += 1;
        // Descriptor for the video response
        let desc_response = Descriptor::new(next_addr, 0x100, VRING_DESC_F_WRITE as u16, 0);
        vq.desc_table().store(index, desc_response).unwrap();

        // Put the descriptor index 0 in the first available ring position.
        mem.write_obj(0u16, vq.avail_addr().unchecked_add(4))
            .unwrap();
        // Set `avail_idx` to 1.
        mem.write_obj(1u16, vq.avail_addr().unchecked_add(2))
            .unwrap();
        // Create descriptor chain
        vq.create_queue::<Queue>()
            .unwrap()
            .iter(GuestMemoryAtomic::new(mem.clone()).memory())
            .unwrap()
            .next()
            .unwrap()
    }

    #[rstest]
    fn test_video_poller(dummy_fd: EventFd) {
        let poller = VideoPoller::new().unwrap();
        assert!(poller
            .add(dummy_fd.as_raw_fd(), PollerEvent::new(EventType::Write, 1))
            .is_ok());
        assert!(poller
            .modify(dummy_fd.as_raw_fd(), PollerEvent::new(EventType::Read, 1))
            .is_ok());

        // Poller captures a read event.
        dummy_fd.write(1).unwrap();
        let mut epoll_events = vec![PollerEvent::default(); 1];
        let events = poller.wait(epoll_events.as_mut_slice(), 0);
        assert!(events.is_ok());
        let events = events.unwrap();
        assert_eq!(events.len(), 1);
        assert!(events[0].have_read);

        assert!(poller.remove(dummy_fd.as_raw_fd()).is_ok());
        // Poller captures no event, since there is no listener.
        dummy_fd.write(1).unwrap();
        let events = poller.wait(epoll_events.as_mut_slice(), 0);
        assert!(events.is_ok());
        let events = events.unwrap();
        assert_eq!(events.len(), 0);
    }

    #[test]
    fn test_video_poller_failures() {
        let poller = VideoPoller::new().unwrap();
        let invalid_fd: i32 = -1;
        let mut epoll_events: Vec<PollerEvent> = Vec::new();
        assert_matches!(
            poller
                .add(invalid_fd, PollerEvent::new(EventType::Write, 1))
                .unwrap_err(),
            VuVideoError::EpollAdd(_)
        );
        assert_matches!(
            poller
                .modify(invalid_fd, PollerEvent::new(EventType::Read, 1))
                .unwrap_err(),
            VuVideoError::EpollModify(_)
        );
        assert_matches!(
            poller.remove(invalid_fd).unwrap_err(),
            VuVideoError::EpollRemove(_)
        );
        assert_matches!(
            poller.wait(epoll_events.as_mut_slice(), 1).unwrap_err(),
            VuVideoError::EpollWait(_)
        );
    }

    #[rstest]
    #[case::get_params(virtio_video_get_params {
        hdr: virtio_video_cmd_hdr {
            type_: VIRTIO_VIDEO_CMD_GET_PARAMS_EXT.into(),
            stream_id: 1.into()
        },
        queue_type: VIRTIO_VIDEO_QUEUE_TYPE_INPUT.into(),
        ..Default::default()
    })]
    #[case::resource_destroy_all(virtio_video_get_params {
        hdr: virtio_video_cmd_hdr {
            type_: VIRTIO_VIDEO_CMD_RESOURCE_DESTROY_ALL.into(),
            stream_id: 1.into()
        },
        queue_type: VIRTIO_VIDEO_QUEUE_TYPE_INPUT.into(),
        ..Default::default()
    })]
    #[case::queue_clear(virtio_video_get_params {
        hdr: virtio_video_cmd_hdr {
            type_: VIRTIO_VIDEO_CMD_QUEUE_CLEAR.into(),
            stream_id: 1.into()
        },
        queue_type: VIRTIO_VIDEO_QUEUE_TYPE_INPUT.into(),
        ..Default::default()
    })]
    #[case::query_capability(virtio_video_query_capability {
        hdr: virtio_video_cmd_hdr {
            type_: VIRTIO_VIDEO_CMD_QUERY_CAPABILITY.into(),
            stream_id: 1.into()
        },
        queue_type: VIRTIO_VIDEO_QUEUE_TYPE_INPUT.into(),
        ..Default::default()
    })]
    #[case::set_params(virtio_video_set_params {
        hdr: virtio_video_cmd_hdr {
            type_: VIRTIO_VIDEO_CMD_SET_PARAMS_EXT.into(),
            stream_id: 1.into()
        },
        params: virtio_video_params {
            queue_type: VIRTIO_VIDEO_QUEUE_TYPE_INPUT.into(),
            ..Default::default()
        }
    })]
    #[case::query_control(virtio_video_query_control {
        hdr: virtio_video_cmd_hdr {
            type_: VIRTIO_VIDEO_CMD_QUERY_CONTROL.into(),
            stream_id: 1.into()
        },
        control: (ControlType::Bitrate as u32).into(),
        padding: 0.into(),
        fmt: virtio_video_query_control_format {
            format: (Format::H264 as u32).into(),
            padding: 0.into(),
        },
    })]
    #[case::stream_create(virtio_video_stream_create {
        hdr: virtio_video_cmd_hdr {
            type_: VIRTIO_VIDEO_CMD_STREAM_CREATE.into(),
            stream_id: 1.into()
        },
        coded_format: (Format::H264 as u32).into(),
        ..Default::default()
    })]
    #[case::get_control(virtio_video_get_control {
        hdr: virtio_video_cmd_hdr {
            type_: VIRTIO_VIDEO_CMD_GET_CONTROL.into(),
            stream_id: 1.into()
        },
        control: (ControlType::ForceKeyframe as u32).into(),
        ..Default::default()
    })]
    #[case::stream_destroy(virtio_video_cmd_hdr {
        type_: VIRTIO_VIDEO_CMD_STREAM_DESTROY.into(),
        stream_id: 2.into()
    })]
    #[case::stream_drain(virtio_video_cmd_hdr {
        type_: VIRTIO_VIDEO_CMD_STREAM_DRAIN.into(),
        stream_id: 1.into()
    })]
    #[case::resource_queue(virtio_video_resource_queue {
        hdr: virtio_video_cmd_hdr {
            type_: VIRTIO_VIDEO_CMD_RESOURCE_QUEUE.into(),
            stream_id: 1.into()
        },
        queue_type: VIRTIO_VIDEO_QUEUE_TYPE_INPUT.into(),
        resource_id: 1.into(),
        ..Default::default()
    })]
    fn test_video_thread<T: ByteValued>(test_dir: TempDir, dummy_fd: EventFd, #[case] request: T) {
        let v4l2_device = VideoDeviceMock::new(&test_dir);
        let backend = Arc::new(RwLock::new(
            alloc_video_backend(BackendType::Null, Path::new(&v4l2_device.path)).unwrap(),
        ));
        let thread = VhostUserVideoThread::new(backend);
        assert!(thread.is_ok());
        let mut thread = thread.unwrap();

        let mem = GuestMemoryAtomic::new(
            GuestMemoryMmap::<()>::from_ranges(&[(GuestAddress(0), 0x10000)]).unwrap(),
        );
        thread.mem = Some(mem.clone());

        assert!(thread
            .poller
            .add(dummy_fd.as_raw_fd(), PollerEvent::new(EventType::Read, 1))
            .is_ok());

        let vring = VringRwLock::new(mem, 0x1000).unwrap();
        vring.set_queue_info(0x100, 0x200, 0x300).unwrap();
        let desc_chains = vec![build_cmd_desc_chain(request.as_slice())];
        let result = thread.process_requests(desc_chains.clone(), &vring);
        assert!(result.is_ok());
        assert!(result.unwrap());

        dummy_fd.write(1).unwrap();
        assert!(thread.process_video_event(&vring).is_ok());
    }

    #[rstest]
    fn test_video_thread_mem_fail(test_dir: TempDir) {
        assert!(alloc_video_backend(BackendType::Null, test_dir.path()).is_err());
        let v4l2_device = VideoDeviceMock::new(&test_dir);
        let backend = Arc::new(RwLock::new(
            alloc_video_backend(BackendType::Null, Path::new(&v4l2_device.path)).unwrap(),
        ));
        let thread = VhostUserVideoThread::new(backend);
        assert!(thread.is_ok());
        let mut thread = thread.unwrap();

        let mem = GuestMemoryAtomic::new(
            GuestMemoryMmap::<()>::from_ranges(&[(GuestAddress(0), 0x10000)]).unwrap(),
        );

        let vring = VringRwLock::new(mem, 0x1000).unwrap();

        // Memory is not configured, so processing command queue should fail
        assert_matches!(
            thread.process_command_queue(&vring).unwrap_err(),
            VuVideoError::NoMemoryConfigured
        );
    }
}
