// Copyright 2026 Red Hat Inc
//
// SPDX-License-Identifier: Apache-2.0 or BSD-3-Clause

use std::{
    os::{fd::BorrowedFd, unix::io::AsRawFd},
    sync::Arc,
};

use vhost::vhost_user::Backend;
use vhost_user_backend::{VringEpollHandler, VringRwLock, VringT};
use virtio_media::{poll::SessionPoller, VirtioMediaDevice, VirtioMediaDeviceRunner};
use virtio_queue::QueueOwnedT;
use vm_memory::{GuestAddressSpace, GuestMemoryAtomic, GuestMemoryMmap};
use vmm_sys_util::epoll::EventSet;

use crate::{
    media_backends::{EventQueue, VuBackend, VuMemoryMapper},
    vhu_media::{MediaResult, Reader, VuMediaBackend, VuMediaError, Writer, NUM_QUEUES},
};

struct MediaSession<
    D: VirtioMediaDevice<Reader, Writer> + Send + Sync,
    F: Fn(EventQueue, VuMemoryMapper, VuBackend) -> MediaResult<D> + Send + Sync,
> where
    D::Session: Send + Sync,
{
    epoll_handler: Arc<VringEpollHandler<Arc<VuMediaBackend<D, F>>>>,
}

impl<D, F> MediaSession<D, F>
where
    D: VirtioMediaDevice<Reader, Writer> + Send + Sync,
    D::Session: Send + Sync,
    F: Fn(EventQueue, VuMemoryMapper, VuBackend) -> MediaResult<D> + Send + Sync,
{
    pub fn new(epoll_handler: Arc<VringEpollHandler<Arc<VuMediaBackend<D, F>>>>) -> Self {
        Self { epoll_handler }
    }
}

impl<D, F> SessionPoller for MediaSession<D, F>
where
    D: VirtioMediaDevice<Reader, Writer> + Send + Sync,
    D::Session: Send + Sync,
    F: Fn(EventQueue, VuMemoryMapper, VuBackend) -> MediaResult<D> + Send + Sync,
{
    fn add_session(&self, session: BorrowedFd, session_id: u32) -> Result<(), i32> {
        self.epoll_handler
            .register_listener(
                session.as_raw_fd(),
                EventSet::IN,
                // Event range [0...num_queues] is reserved for queues and exit event.
                // So registered session start at NUM_QUEUES + 1.
                u64::from((NUM_QUEUES + 1) as u32 + session_id),
            )
            .map_err(|e| e.kind() as i32)
    }

    fn remove_session(&self, session: BorrowedFd) {
        let _ =
            self.epoll_handler
                .as_ref()
                .unregister_listener(session.as_raw_fd(), EventSet::IN, 0);
    }
}

impl<D, F> Clone for MediaSession<D, F>
where
    D: VirtioMediaDevice<Reader, Writer> + Send + Sync,
    D::Session: Send + Sync,
    F: Fn(EventQueue, VuMemoryMapper, VuBackend) -> MediaResult<D> + Send + Sync,
{
    fn clone(&self) -> Self {
        Self {
            epoll_handler: Arc::clone(&self.epoll_handler),
        }
    }
}

pub(crate) struct VhostUserMediaThread<
    D: VirtioMediaDevice<Reader, Writer> + Send + Sync,
    F: Fn(EventQueue, VuMemoryMapper, VuBackend) -> MediaResult<D> + Send + Sync,
> where
    D::Session: Send + Sync,
{
    /// Guest memory map.
    pub mem: Option<GuestMemoryAtomic<GuestMemoryMmap>>,
    /// VIRTIO_RING_F_EVENT_IDX.
    pub event_idx: bool,
    epoll_handler: Option<MediaSession<D, F>>,
    pub vu_req: Option<Backend>,
    worker: Option<VirtioMediaDeviceRunner<Reader, Writer, D, MediaSession<D, F>>>,
}

impl<D, F> VhostUserMediaThread<D, F>
where
    D: VirtioMediaDevice<Reader, Writer> + Send + Sync,
    D::Session: Send + Sync,
    F: Fn(EventQueue, VuMemoryMapper, VuBackend) -> MediaResult<D> + Send + Sync,
{
    pub fn new() -> MediaResult<Self> {
        Ok(Self {
            mem: None,
            event_idx: false,
            epoll_handler: None,
            vu_req: None,
            worker: None,
        })
    }

    pub fn set_vring_workers(
        &mut self,
        epoll_handler: Arc<VringEpollHandler<Arc<VuMediaBackend<D, F>>>>,
    ) {
        self.epoll_handler = Some(MediaSession::new(epoll_handler));
    }

    pub fn need_media_worker(&self) -> bool {
        self.worker.is_none()
    }

    pub fn set_media_worker(&mut self, device: D) {
        let worker = self.epoll_handler.as_ref().unwrap();
        self.worker = Some(VirtioMediaDeviceRunner::new(device, worker.clone()));
    }

    pub fn process_media_events(&mut self, session_id: u32) -> MediaResult<()> {
        if let Some(runner) = self.worker.as_mut() {
            let session = runner
                .sessions
                .get_mut(&session_id)
                .ok_or(VuMediaError::MissingSession(session_id))?;
            if let Err(e) = runner.device.process_events(session) {
                if let Some(session) = runner.sessions.remove(&session_id) {
                    runner.device.close_session(session);
                }
                return Err(VuMediaError::ProcessSessionEvent(session_id, e));
            }

            return Ok(());
        }

        Err(VuMediaError::MissingRunner)
    }

    pub fn atomic_mem(&self) -> MediaResult<&GuestMemoryAtomic<GuestMemoryMmap>> {
        match &self.mem {
            Some(m) => Ok(m),
            None => Err(VuMediaError::NoMemoryConfigured),
        }
    }

    pub fn process_command_queue(&mut self, vring: &VringRwLock) -> MediaResult<()> {
        let chains: Vec<_> = vring
            .get_mut()
            .get_queue_mut()
            .iter(self.atomic_mem()?.memory())
            .map_err(|_| VuMediaError::DescriptorNotFound)?
            .collect();

        for dc in chains {
            let mut writer = Writer::new(dc.clone());
            let mut reader = Reader::new(dc.clone());

            if let Some(runner) = &mut self.worker {
                runner.handle_command(&mut reader, &mut writer);
            }

            vring
                .add_used(dc.head_index(), writer.max_written())
                .map_err(|_| VuMediaError::AddUsedDescriptorFailed)?;
        }

        vring
            .signal_used_queue()
            .map_err(|_| VuMediaError::SendNotificationFailed)?;

        Ok(())
    }
}
