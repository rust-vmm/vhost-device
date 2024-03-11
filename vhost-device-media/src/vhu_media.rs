// Copyright 2026 Red Hat Inc
//
// SPDX-License-Identifier: Apache-2.0 or BSD-3-Clause

use std::{
    convert,
    io::{self, Result as IoResult},
    path::Path,
    sync::{Arc, Mutex},
};

use clap::ValueEnum;
use log::{debug, warn};
use thiserror::Error as ThisError;
use vhost::vhost_user::{
    message::VhostUserShMemConfig, Backend, VhostUserProtocolFeatures, VhostUserVirtioFeatures,
};
use vhost_user_backend::{VhostUserBackend, VringEpollHandler, VringRwLock, VringT};
use virtio_bindings::{
    virtio_config::{VIRTIO_F_NOTIFY_ON_EMPTY, VIRTIO_F_VERSION_1},
    virtio_ring::{VIRTIO_RING_F_EVENT_IDX, VIRTIO_RING_F_INDIRECT_DESC},
};
use virtio_media::{protocol::VirtioMediaDeviceConfig, VirtioMediaDevice};
use vm_memory::{mmap::GuestMemoryMmap, GuestMemoryAtomic, GuestMemoryLoadGuard};
use vmm_sys_util::{
    epoll::EventSet,
    event::{new_event_consumer_and_notifier, EventConsumer, EventFlag, EventNotifier},
};
use zerocopy::IntoBytes;

use crate::{
    descriptor_chain,
    vhu_adapters::{EventQueue, VuBackend, VuMemoryMapper},
    vhu_media_thread::VhostUserMediaThread,
};

pub(crate) type MediaResult<T> = std::result::Result<T, VuMediaError>;
pub(crate) type Writer =
    descriptor_chain::DescriptorChainWriter<GuestMemoryLoadGuard<GuestMemoryMmap>>;
pub(crate) type Reader =
    descriptor_chain::DescriptorChainReader<GuestMemoryLoadGuard<GuestMemoryMmap>>;

#[derive(ValueEnum, Debug, Clone, Eq, PartialEq)]
pub enum BackendType {
    Null,
    #[cfg(feature = "simple-capture")]
    SimpleCapture,
    #[cfg(feature = "v4l2-proxy")]
    V4l2Proxy,
    #[cfg(feature = "ffmpeg")]
    FfmpegDecoder,
}

const QUEUE_SIZE: usize = 1024;
pub const NUM_QUEUES: usize = 2;
const COMMAND_Q: u16 = 0;
pub const EVENT_Q: u16 = 1;
pub const SHMEM_SIZE: u64 = 1 << 32;

#[derive(Debug, ThisError)]
/// Errors related to vhost-device-media daemon.
pub enum VuMediaError {
    #[error("Descriptor not found")]
    DescriptorNotFound,
    #[error("Failed to create a used descriptor")]
    AddUsedDescriptorFailed,
    #[error("Notification send failed")]
    SendNotificationFailed,
    #[error("Can't create eventFd")]
    EventFdError,
    #[error("Memory allocator failed")]
    MemoryAllocatorFailed,
    #[error("Failed to handle event")]
    HandleEventNotEpollIn,
    #[error("No memory configured")]
    NoMemoryConfigured,
    #[error("Received event for non-registered session: {0}")]
    MissingSession(u32),
    #[error("Media Device Runner not initialised")]
    MissingRunner,
    #[error("No vhost-user request channel available")]
    NoRequestChannel,
    #[error("Error while processing events for session {0}: {1}")]
    ProcessSessionEvent(u32, i32),
}

impl convert::From<VuMediaError> for io::Error {
    fn from(e: VuMediaError) -> Self {
        io::Error::other(e)
    }
}

pub(crate) struct VuMediaBackend<
    D: VirtioMediaDevice<Reader, Writer> + Send + Sync,
    F: Fn(EventQueue, VuMemoryMapper, VuBackend) -> MediaResult<D> + Send + Sync,
> where
    D::Session: Send + Sync,
{
    config: VirtioMediaDeviceConfig,
    threads: Vec<Mutex<VhostUserMediaThread<D, F>>>,
    exit_consumer: EventConsumer,
    exit_notifier: EventNotifier,
    create_device: F,
}

impl<D, F> VuMediaBackend<D, F>
where
    D: VirtioMediaDevice<Reader, Writer> + Send + Sync,
    D::Session: Send + Sync,
    F: Fn(EventQueue, VuMemoryMapper, VuBackend) -> MediaResult<D> + Send + Sync,
{
    /// Create a new virtio video device for /dev/video<num>.
    pub fn new(
        _video_path: &Path,
        config: VirtioMediaDeviceConfig,
        create_device: F,
    ) -> MediaResult<Self> {
        let (exit_consumer, exit_notifier) = new_event_consumer_and_notifier(EventFlag::NONBLOCK)
            .map_err(|_| VuMediaError::EventFdError)?;
        Ok(Self {
            config,
            threads: vec![Mutex::new(VhostUserMediaThread::new()?)],
            exit_consumer,
            exit_notifier,
            create_device,
        })
    }

    pub fn set_thread_workers(&self, vring_workers: &mut Vec<Arc<VringEpollHandler<Arc<Self>>>>) {
        for thread in self.threads.iter() {
            thread
                .lock()
                .unwrap()
                .set_vring_workers(vring_workers.remove(0));
        }
    }
}

/// VhostUserBackend trait methods
impl<D, F> VhostUserBackend for VuMediaBackend<D, F>
where
    D: VirtioMediaDevice<Reader, Writer> + Send + Sync,
    D::Session: Send + Sync,
    F: Fn(EventQueue, VuMemoryMapper, VuBackend) -> MediaResult<D> + Send + Sync,
{
    type Vring = VringRwLock;
    type Bitmap = ();

    fn num_queues(&self) -> usize {
        NUM_QUEUES
    }

    fn max_queue_size(&self) -> usize {
        debug!("Max queue size called");
        QUEUE_SIZE
    }

    fn features(&self) -> u64 {
        debug!("Features called");
        1 << VIRTIO_F_VERSION_1
            | 1 << VIRTIO_F_NOTIFY_ON_EMPTY
            | 1 << VIRTIO_RING_F_INDIRECT_DESC
            | 1 << VIRTIO_RING_F_EVENT_IDX
            | VhostUserVirtioFeatures::PROTOCOL_FEATURES.bits()
    }

    fn protocol_features(&self) -> VhostUserProtocolFeatures {
        debug!("Protocol features called");
        VhostUserProtocolFeatures::MQ
            | VhostUserProtocolFeatures::CONFIG
            | VhostUserProtocolFeatures::BACKEND_REQ
            | VhostUserProtocolFeatures::BACKEND_SEND_FD
            | VhostUserProtocolFeatures::REPLY_ACK
            | VhostUserProtocolFeatures::SHMEM
    }

    fn set_event_idx(&self, enabled: bool) {
        for thread in self.threads.iter() {
            thread.lock().unwrap().event_idx = enabled;
        }
    }

    fn update_memory(&self, mem: GuestMemoryAtomic<GuestMemoryMmap>) -> IoResult<()> {
        debug!("Memory updated");
        for thread in self.threads.iter() {
            thread.lock().unwrap().mem = Some(mem.clone());
        }
        Ok(())
    }

    fn handle_event(
        &self,
        device_event: u16,
        evset: EventSet,
        vrings: &[VringRwLock],
        thread_id: usize,
    ) -> IoResult<()> {
        if evset != EventSet::IN {
            warn!("Non-input event");
            return Err(VuMediaError::HandleEventNotEpollIn.into());
        }
        let mut thread = self.threads[thread_id].lock().unwrap();
        let commandq = &vrings[COMMAND_Q as usize];
        let eventq = &vrings[EVENT_Q as usize];
        let evt_idx = thread.event_idx;
        if thread.need_media_worker() {
            let atomic_mem = thread.atomic_mem().map_err(io::Error::other)?.clone();
            let vu_req = thread
                .vu_req
                .as_ref()
                .ok_or_else(|| io::Error::other(VuMediaError::NoRequestChannel))?
                .clone();
            let device = (self.create_device)(
                EventQueue {
                    mem: atomic_mem.clone(),
                    queue: eventq.clone(),
                },
                VuMemoryMapper::new(atomic_mem),
                VuBackend::new(vu_req).map_err(|_| VuMediaError::MemoryAllocatorFailed)?,
            )
            .map_err(io::Error::other)?;
            thread.set_media_worker(device);
        }

        match device_event {
            COMMAND_Q => {
                if evt_idx {
                    // vm-virtio's Queue implementation only checks avail_index
                    // once, so to properly support EVENT_IDX we need to keep
                    // calling process_queue() until it stops finding new
                    // requests on the queue.
                    loop {
                        commandq.disable_notification().map_err(io::Error::other)?;
                        thread.process_command_queue(commandq)?;
                        if !commandq.enable_notification().map_err(io::Error::other)? {
                            break;
                        }
                    }
                } else {
                    // Without EVENT_IDX, a single call is enough.
                    thread.process_command_queue(commandq)?;
                }
            }

            EVENT_Q => {
                // We do not handle incoming events.
                warn!("Unexpected event notification received");
            }

            session_id => {
                let session_id = session_id as usize - (NUM_QUEUES + 1);
                thread.process_media_events(session_id as u32)?;
            }
        }
        Ok(())
    }

    fn get_config(&self, _offset: u32, _size: u32) -> Vec<u8> {
        let offset = _offset as usize;
        let size = _size as usize;

        let buf = self.config.as_bytes();

        if offset + size > buf.len() {
            return Vec::new();
        }

        buf[offset..offset + size].to_vec()
    }

    fn exit_event(&self, _thread_index: usize) -> Option<(EventConsumer, EventNotifier)> {
        let consumer = self.exit_consumer.try_clone().ok()?;
        let notifier = self.exit_notifier.try_clone().ok()?;
        Some((consumer, notifier))
    }

    fn set_backend_req_fd(&self, vu_req: Backend) {
        debug!("Setting req fd");
        for thread in self.threads.iter() {
            thread.lock().unwrap().vu_req = Some(vu_req.clone());
        }
    }

    fn get_shmem_config(&self) -> IoResult<VhostUserShMemConfig> {
        Ok(VhostUserShMemConfig::new(1, &[SHMEM_SIZE]))
    }
}
