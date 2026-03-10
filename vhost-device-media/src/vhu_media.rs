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
use log::{debug, info, warn};
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
    media_backends::{EventQueue, VuBackend, VuMemoryMapper},
    vhu_media_thread::VhostUserMediaThread,
    virtio,
};

pub(crate) type MediaResult<T> = std::result::Result<T, VuMediaError>;
pub(crate) type Writer = virtio::DescriptorChainWriter<GuestMemoryLoadGuard<GuestMemoryMmap>>;
pub(crate) type Reader = virtio::DescriptorChainReader<GuestMemoryLoadGuard<GuestMemoryMmap>>;

#[derive(ValueEnum, Debug, Clone, Eq, PartialEq)]
pub enum BackendType {
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
    #[error("Error while processing events for session {0}: {1}")]
    ProcessSessionEvent(u32, i32),
}

impl convert::From<VuMediaError> for io::Error {
    fn from(e: VuMediaError) -> Self {
        io::Error::new(io::ErrorKind::Other, e)
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
        info!("Memory updated - guest probably booting");
        for thread in self.threads.iter() {
            match thread.try_lock() {
                Err(_) => warn!("Thread locked, memory update failed"),
                Ok(mut t) => t.mem = Some(mem.clone()),
            }
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
            let device = (self.create_device)(
                EventQueue {
                    mem: thread.mem.as_ref().unwrap().clone(),
                    queue: eventq.clone(),
                },
                VuMemoryMapper::new(thread.atomic_mem().unwrap().clone()),
                VuBackend::new(thread.vu_req.as_ref().unwrap().clone())
                    .map_err(|_| VuMediaError::MemoryAllocatorFailed)?,
            )
            .unwrap();
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
                        commandq.disable_notification().unwrap();
                        thread.process_command_queue(commandq)?;
                        if !commandq.enable_notification().unwrap() {
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

// Shared test utilities for use across test modules
#[cfg(test)]
pub(crate) mod test_utils {
    use std::os::fd::BorrowedFd;

    use virtio_media::{protocol::V4l2Ioctl, VirtioMediaDevice, VirtioMediaDeviceSession};

    use super::*;

    pub struct DummySession {}

    impl VirtioMediaDeviceSession for DummySession {
        fn poll_fd(&self) -> Option<BorrowedFd<'_>> {
            None
        }
    }

    pub struct DummyDevice {}

    impl VirtioMediaDevice<Reader, Writer> for DummyDevice {
        type Session = DummySession;

        fn new_session(&mut self, _id: u32) -> std::result::Result<Self::Session, i32> {
            Ok(DummySession {})
        }

        fn close_session(&mut self, _session: Self::Session) {}

        fn do_ioctl(
            &mut self,
            _session: &mut Self::Session,
            _ioctl: V4l2Ioctl,
            _reader: &mut Reader,
            _writer: &mut Writer,
        ) -> std::result::Result<(), std::io::Error> {
            Ok(())
        }

        fn do_mmap(
            &mut self,
            _session: &mut Self::Session,
            _len: u32,
            _prot: u32,
        ) -> std::result::Result<(u64, u64), i32> {
            Ok((0, 0))
        }

        fn do_munmap(&mut self, _offset: u64) -> std::result::Result<(), i32> {
            Ok(())
        }
    }

    pub type DummyFn = fn(EventQueue, VuMemoryMapper, VuBackend) -> MediaResult<DummyDevice>;

    pub fn make_dummy_device(
        _: EventQueue,
        _: VuMemoryMapper,
        _: VuBackend,
    ) -> MediaResult<DummyDevice> {
        Ok(DummyDevice {})
    }

    pub fn create_test_config() -> VirtioMediaDeviceConfig {
        VirtioMediaDeviceConfig {
            device_caps: 0,
            device_type: 0,
            card: [0; 32],
        }
    }
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use rstest::*;
    use vhost_user_backend::VringT;
    use vm_memory::GuestAddress;

    use super::{
        test_utils::{create_test_config, make_dummy_device, DummyDevice},
        *,
    };

    fn create_test_backend() -> VuMediaBackend<
        DummyDevice,
        fn(EventQueue, VuMemoryMapper, VuBackend) -> MediaResult<DummyDevice>,
    > {
        let config = create_test_config();
        VuMediaBackend::new(
            Path::new("/dev/null"),
            config,
            make_dummy_device
                as fn(EventQueue, VuMemoryMapper, VuBackend) -> MediaResult<DummyDevice>,
        )
        .unwrap()
    }

    fn setup_test_memory() -> GuestMemoryAtomic<GuestMemoryMmap> {
        GuestMemoryAtomic::new(
            GuestMemoryMmap::<()>::from_ranges(&[(GuestAddress(0), 0x10000)]).unwrap(),
        )
    }

    #[allow(dead_code)] // Useful helper for future tests
    fn setup_test_vring(mem: &GuestMemoryAtomic<GuestMemoryMmap>, queue_size: u16) -> VringRwLock {
        let vring = VringRwLock::new(mem.clone(), queue_size).unwrap();
        vring.set_queue_info(0x100, 0x200, 0x300).unwrap();
        vring.set_queue_ready(true);
        vring
    }

    fn setup_test_vrings(mem: &GuestMemoryAtomic<GuestMemoryMmap>) -> [VringRwLock; 2] {
        let vring0 = VringRwLock::new(mem.clone(), 0x1000).unwrap();
        vring0.set_queue_info(0x100, 0x200, 0x300).unwrap();
        vring0.set_queue_ready(true);

        let vring1 = VringRwLock::new(mem.clone(), 0x2000).unwrap();
        vring1.set_queue_info(0x1100, 0x1200, 0x1300).unwrap();
        vring1.set_queue_ready(true);

        [vring0, vring1]
    }

    #[test]
    fn test_backend_creation_and_features() {
        let backend = create_test_backend();

        assert_eq!(backend.num_queues(), NUM_QUEUES);
        assert_eq!(backend.max_queue_size(), QUEUE_SIZE);
        assert_ne!(backend.features(), 0);
        assert!(!backend.protocol_features().is_empty());
    }

    #[rstest]
    #[case(0x12345678u32, 0, 8, 0x12345678u64)]
    #[case(0x00000000u32, 0, 8, 0x00000000u64)]
    #[case(0xFFFFFFFFu32, 0, 8, 0xFFFFFFFFu64)]
    fn test_get_config(
        #[case] device_caps: u32,
        #[case] offset: u32,
        #[case] size: u32,
        #[case] expected: u64,
    ) {
        let mut config = create_test_config();
        config.device_caps = device_caps;
        let backend =
            VuMediaBackend::new(Path::new("/dev/null"), config, make_dummy_device).unwrap();

        let config_bytes = backend.get_config(offset, size);
        assert_eq!(config_bytes.len(), size as usize);
        let mut bytes_array = [0u8; 8];
        bytes_array[..config_bytes.len()].copy_from_slice(&config_bytes);
        let val = u64::from_le_bytes(bytes_array);
        assert_eq!(val, expected);
    }

    #[test]
    fn test_get_config_partial_read() {
        let mut config = create_test_config();
        config.device_caps = 0xDEADBEEF;
        let backend =
            VuMediaBackend::new(Path::new("/dev/null"), config, make_dummy_device).unwrap();

        // Test reading 4 bytes
        let config_bytes = backend.get_config(0, 4);
        assert_eq!(config_bytes.len(), 4);
        let val = u32::from_le_bytes(config_bytes.try_into().unwrap());
        assert_eq!(val, 0xDEADBEEF);
    }

    #[test]
    fn test_get_config_out_of_bounds() {
        let mut config = create_test_config();
        config.device_caps = 0x12345678;
        let backend =
            VuMediaBackend::new(Path::new("/dev/null"), config, make_dummy_device).unwrap();

        // Test reading out of bounds
        let config_bytes = backend.get_config(1024, 8);
        assert_eq!(config_bytes.len(), 0);
    }

    #[test]
    fn test_exit_event() {
        let backend = create_test_backend();

        let exit_event = backend.exit_event(0);
        assert!(exit_event.is_some());
        let (consumer, notifier) = exit_event.unwrap();
        notifier.notify().unwrap();
        assert!(consumer.try_clone().is_ok());
    }

    #[test]
    fn test_handle_event() {
        let backend = create_test_backend();
        let mem = setup_test_memory();
        let vrings = setup_test_vrings(&mem);

        backend.update_memory(mem).unwrap();

        // Test a non-IN event
        assert!(backend
            .handle_event(COMMAND_Q, EventSet::OUT, &vrings, 0)
            .is_err());

        // TODO: We intentionally do not test the IN-path here because it
        // requires a fully initialized backend request fd and worker
        // setup.
    }
}
