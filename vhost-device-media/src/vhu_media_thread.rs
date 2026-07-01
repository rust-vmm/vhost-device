// Copyright 2026 Red Hat Inc
//
// SPDX-License-Identifier: Apache-2.0 or BSD-3-Clause

use std::{
    collections::HashMap,
    os::{
        fd::BorrowedFd,
        unix::io::{AsRawFd, RawFd},
    },
    sync::{Arc, Mutex},
};

use vhost::vhost_user::Backend;
use vhost_user_backend::{VringEpollHandler, VringRwLock, VringT};
use virtio_media::{
    poll::SessionPoller, VirtioMediaDevice, VirtioMediaDeviceRunner, VirtioMediaDeviceSession,
};
use virtio_queue::QueueOwnedT;
use vm_memory::{GuestAddressSpace, GuestMemoryAtomic, GuestMemoryMmap};
use vmm_sys_util::epoll::EventSet;

use crate::{
    vhu_adapters::{EventQueue, VuBackend, VuMemoryMapper},
    vhu_media::{MediaResult, Reader, VuMediaBackend, VuMediaError, Writer, NUM_QUEUES},
};

struct MediaSession<
    D: VirtioMediaDevice<Reader, Writer> + Send + Sync,
    F: Fn(EventQueue, VuMemoryMapper, VuBackend) -> MediaResult<D> + Send + Sync,
> where
    D::Session: Send + Sync,
{
    epoll_handler: Arc<VringEpollHandler<Arc<VuMediaBackend<D, F>>>>,
    /// Maps raw fd → epoll user data so that remove_session can supply
    /// the same token that was used at registration time.
    session_data: Mutex<HashMap<RawFd, u64>>,
}

impl<D, F> MediaSession<D, F>
where
    D: VirtioMediaDevice<Reader, Writer> + Send + Sync,
    D::Session: Send + Sync,
    F: Fn(EventQueue, VuMemoryMapper, VuBackend) -> MediaResult<D> + Send + Sync,
{
    pub fn new(epoll_handler: Arc<VringEpollHandler<Arc<VuMediaBackend<D, F>>>>) -> Self {
        Self {
            epoll_handler,
            session_data: Mutex::new(HashMap::new()),
        }
    }
}

impl<D, F> SessionPoller for MediaSession<D, F>
where
    D: VirtioMediaDevice<Reader, Writer> + Send + Sync,
    D::Session: Send + Sync,
    F: Fn(EventQueue, VuMemoryMapper, VuBackend) -> MediaResult<D> + Send + Sync,
{
    fn add_session(&self, session: BorrowedFd, session_id: u32) -> Result<(), i32> {
        // Event range [0...num_queues] is reserved for queues and exit event.
        // Session events start at NUM_QUEUES + 1.
        let data = u64::from((NUM_QUEUES + 1) as u32 + session_id);
        self.epoll_handler
            .register_listener(session.as_raw_fd(), EventSet::IN, data)
            .map_err(|e| e.raw_os_error().unwrap_or(libc::EIO))?;
        // Insert only after successful registration; avoids stale map entries
        // if registration fails.
        self.session_data
            .lock()
            .unwrap()
            .insert(session.as_raw_fd(), data);
        Ok(())
    }

    fn remove_session(&self, session: BorrowedFd) {
        let data = self
            .session_data
            .lock()
            .unwrap()
            .remove(&session.as_raw_fd())
            .unwrap_or(0);
        let _ = self
            .epoll_handler
            .unregister_listener(session.as_raw_fd(), EventSet::IN, data);
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
            session_data: Mutex::new(HashMap::new()),
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
                    // Unregister the epoll listener before close_session so the
                    // fd is still valid and session_data is cleaned up correctly.
                    if let (Some(epoll), Some(fd)) =
                        (self.epoll_handler.as_ref(), session.poll_fd())
                    {
                        epoll.remove_session(fd);
                    }
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

#[cfg(test)]
mod tests {
    use std::{os::fd::AsRawFd, sync::Arc};

    use assert_matches::assert_matches;
    use rstest::*;
    use vhost_user_backend::VhostUserDaemon;
    use virtio_media::{poll::SessionPoller, protocol::V4l2Ioctl, VirtioMediaDevice};
    use vm_memory::GuestAddress;
    use vmm_sys_util::eventfd::EventFd;

    use super::*;
    use crate::vhu_media::test_utils::{
        create_test_config, make_dummy_device, DummyDevice, DummyFn, DummySession,
    };

    /// A device whose `process_events` always fails, exercising the error path
    /// of `process_media_events` (the `ProcessSessionEvent` return).
    struct FailingDevice;

    impl VirtioMediaDevice<Reader, Writer> for FailingDevice {
        type Session = DummySession;

        fn new_session(&mut self, _id: u32) -> Result<Self::Session, i32> {
            Ok(DummySession {})
        }

        fn close_session(&mut self, _session: Self::Session) {}

        fn do_ioctl(
            &mut self,
            _session: &mut Self::Session,
            _ioctl: V4l2Ioctl,
            _reader: &mut Reader,
            _writer: &mut Writer,
        ) -> std::io::Result<()> {
            Ok(())
        }

        fn do_mmap(
            &mut self,
            _session: &mut Self::Session,
            _len: u32,
            _prot: u32,
        ) -> Result<(u64, u64), i32> {
            Ok((0, 0))
        }

        fn do_munmap(&mut self, _offset: u64) -> Result<(), i32> {
            Ok(())
        }

        fn process_events(&mut self, _session: &mut Self::Session) -> Result<(), i32> {
            Err(-1)
        }
    }

    type FailingFn = fn(EventQueue, VuMemoryMapper, VuBackend) -> MediaResult<FailingDevice>;

    fn make_failing_device(
        _: EventQueue,
        _: VuMemoryMapper,
        _: VuBackend,
    ) -> MediaResult<FailingDevice> {
        Ok(FailingDevice)
    }

    fn setup_test_memory() -> GuestMemoryAtomic<GuestMemoryMmap> {
        GuestMemoryAtomic::new(
            GuestMemoryMmap::<()>::from_ranges(&[(GuestAddress(0), 0x10000)]).unwrap(),
        )
    }

    fn setup_test_vring(mem: &GuestMemoryAtomic<GuestMemoryMmap>) -> VringRwLock {
        let vring = VringRwLock::new(mem.clone(), 0x1000).unwrap();
        vring.set_queue_info(0x100, 0x200, 0x300).unwrap();
        vring.set_queue_ready(true);
        vring
    }

    #[allow(clippy::type_complexity)]
    fn setup_test_backend_and_daemon() -> (
        Arc<crate::vhu_media::VuMediaBackend<DummyDevice, DummyFn>>,
        VhostUserDaemon<Arc<crate::vhu_media::VuMediaBackend<DummyDevice, DummyFn>>>,
    ) {
        let config = create_test_config();
        let backend = Arc::new(
            crate::vhu_media::VuMediaBackend::new(config, make_dummy_device as DummyFn).unwrap(),
        );
        let daemon = VhostUserDaemon::new(
            "vhost-device-media-test".to_owned(),
            backend.clone(),
            GuestMemoryAtomic::new(GuestMemoryMmap::new()),
        )
        .unwrap();
        (backend, daemon)
    }

    #[fixture]
    fn dummy_eventfd() -> EventFd {
        EventFd::new(0).expect("Could not create an EventFd")
    }

    #[rstest]
    #[case::no_memory(VuMediaError::NoMemoryConfigured)]
    #[case::missing_runner(VuMediaError::MissingRunner)]
    fn test_error_handling(#[case] expected_error: VuMediaError) {
        let mut thread = VhostUserMediaThread::<DummyDevice, DummyFn>::new().unwrap();

        match expected_error {
            VuMediaError::NoMemoryConfigured => {
                // Test atomic_mem before initialization
                assert_matches!(thread.atomic_mem(), Err(VuMediaError::NoMemoryConfigured));
            }
            VuMediaError::MissingRunner => {
                // Test process_media_events before worker is set
                assert_matches!(
                    thread.process_media_events(0),
                    Err(VuMediaError::MissingRunner)
                );
            }
            _ => unreachable!(),
        }
    }

    #[test]
    fn test_queue_processing() {
        let mem = setup_test_memory();
        let vring = setup_test_vring(&mem);

        let mut thread = VhostUserMediaThread::<DummyDevice, DummyFn>::new().unwrap();
        thread.mem = Some(mem);

        // We can't easily check the used length here without more mocking,
        // but we can at least verify that the method runs without panicking.
        thread.process_command_queue(&vring).unwrap();
    }

    #[test]
    fn test_set_workers_and_missing_session_path() {
        let (_backend, daemon) = setup_test_backend_and_daemon();
        let mut handlers = daemon.get_epoll_handlers();

        let mut thread = VhostUserMediaThread::<DummyDevice, DummyFn>::new().unwrap();
        assert!(thread.need_media_worker());
        thread.set_vring_workers(handlers.remove(0));
        thread.set_media_worker(DummyDevice {});
        assert!(!thread.need_media_worker());

        assert_matches!(
            thread.process_media_events(42),
            Err(VuMediaError::MissingSession(42))
        );
    }

    #[rstest]
    #[case::session_0(0)]
    #[case::session_7(7)]
    #[case::session_42(42)]
    #[case::session_100(100)]
    fn test_media_session_add_remove_session(dummy_eventfd: EventFd, #[case] session_id: u32) {
        let (_backend, daemon) = setup_test_backend_and_daemon();
        let mut handlers = daemon.get_epoll_handlers();
        let session_poller = MediaSession::new(handlers.remove(0));

        // SAFETY: `borrowed` does not outlive `dummy_eventfd` in this test.
        let borrowed = unsafe { BorrowedFd::borrow_raw(dummy_eventfd.as_raw_fd()) };
        assert_matches!(session_poller.add_session(borrowed, session_id), Ok(()));
        session_poller.remove_session(borrowed);
    }

    #[rstest]
    #[case::session_0(0)]
    #[case::session_1(1)]
    #[case::session_99(99)]
    fn test_process_media_events_missing_session(#[case] session_id: u32) {
        let (_backend, daemon) = setup_test_backend_and_daemon();
        let mut handlers = daemon.get_epoll_handlers();

        let mut thread = VhostUserMediaThread::<DummyDevice, DummyFn>::new().unwrap();
        thread.set_vring_workers(handlers.remove(0));
        thread.set_media_worker(DummyDevice {});

        assert_matches!(
            thread.process_media_events(session_id),
            Err(VuMediaError::MissingSession(id)) if id == session_id
        );
    }

    /// Exercises the `process_events` error branch of `process_media_events`:
    /// the session is closed and `ProcessSessionEvent` is returned.
    #[test]
    fn test_process_media_events_process_events_error() {
        let config = create_test_config();
        let backend =
            Arc::new(VuMediaBackend::new(config, make_failing_device as FailingFn).unwrap());
        let daemon = VhostUserDaemon::new(
            "vhost-device-media-test".to_owned(),
            backend.clone(),
            GuestMemoryAtomic::new(GuestMemoryMmap::new()),
        )
        .unwrap();
        let mut handlers = daemon.get_epoll_handlers();

        let mut thread = VhostUserMediaThread::<FailingDevice, FailingFn>::new().unwrap();
        thread.set_vring_workers(handlers.remove(0));
        thread.set_media_worker(FailingDevice);

        // Insert a session directly, bypassing fd-based epoll registration.
        thread
            .worker
            .as_mut()
            .unwrap()
            .sessions
            .insert(42, DummySession {});

        assert_matches!(
            thread.process_media_events(42),
            Err(VuMediaError::ProcessSessionEvent(42, -1))
        );
    }
}
