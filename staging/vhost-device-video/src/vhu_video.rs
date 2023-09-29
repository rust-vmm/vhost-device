// SPDX-License-Identifier: Apache-2.0 or BSD-3-Clause

use std::{
    convert,
    io::{self, Result as IoResult},
    path::Path,
    sync::{Arc, Mutex, RwLock},
};

use clap::ValueEnum;
use log::{debug, warn};
use thiserror::Error as ThisError;
use vhost::vhost_user::message::{VhostUserProtocolFeatures, VhostUserVirtioFeatures};
use vhost_user_backend::{VhostUserBackendMut, VringRwLock, VringT};
use virtio_bindings::bindings::{
    virtio_config::{VIRTIO_F_NOTIFY_ON_EMPTY, VIRTIO_F_VERSION_1},
    virtio_ring::{VIRTIO_RING_F_EVENT_IDX, VIRTIO_RING_F_INDIRECT_DESC},
};
use virtio_queue::DescriptorChain;
use vm_memory::{ByteValued, GuestMemoryAtomic, GuestMemoryLoadGuard, GuestMemoryMmap, Le32};
use vmm_sys_util::{
    epoll::EventSet,
    eventfd::{EventFd, EFD_NONBLOCK},
};

use crate::{vhu_video_thread::VhostUserVideoThread, video_backends};

/// Virtio Video Feature bits
const VIRTIO_VIDEO_F_RESOURCE_GUEST_PAGES: u16 = 0;
/// Unsupported
/// const VIRTIO_VIDEO_F_RESOURCE_NON_CONTIG: u16 = 1;
/// const VIRTIO_VIDEO_F_RESOURCE_VIRTIO_OBJECT: u16 = 2;

const COMMAND_Q: u16 = 0;
const EVENT_Q: u16 = 1;
const NUM_QUEUES: usize = 2;
const QUEUE_SIZE: usize = 1024;
/// Notification coming from the backend.
/// Event range [0...num_queues] is reserved for queues and exit event.
/// So NUM_QUEUES + 1 is used.
pub(crate) const VIDEO_EVENT: u16 = (NUM_QUEUES + 1) as u16;

pub(crate) const VIRTIO_V4L2_CARD_NAME_LEN: usize = 32;
const MAX_CAPS_LEN: u32 = 4096;
const MAX_RESP_LEN: u32 = MAX_CAPS_LEN;

pub(crate) type Result<T> = std::result::Result<T, VuVideoError>;
pub(crate) type VideoDescriptorChain = DescriptorChain<GuestMemoryLoadGuard<GuestMemoryMmap<()>>>;

#[derive(Debug, ThisError)]
/// Errors related to vhost-device-rng daemon.
pub(crate) enum VuVideoError {
    #[error("Descriptor not found")]
    DescriptorNotFound,
    #[error("Descriptor read failed")]
    DescriptorReadFailed,
    #[error("Notification send failed")]
    SendNotificationFailed,
    #[error("Can't create eventFd")]
    EventFdError,
    #[error("Video device file doesn't exists or can't be accessed")]
    AccessVideoDeviceFile,
    #[error("Failed to create stream")]
    VideoStreamCreate,
    #[error("Failed to handle event")]
    HandleEventNotEpollIn,
    #[error("Unknown device event")]
    HandleUnknownEvent,
    #[error("Invalid command type {0}")]
    InvalidCmdType(u32),
    #[error("Invalid Resource ID {0}")]
    InvalidResourceId(u32),
    #[error("Too many descriptors: {0}")]
    UnexpectedDescriptorCount(usize),
    #[error("Invalid descriptor size, expected at least: {0}, found: {1}")]
    UnexpectedMinimumDescriptorSize(usize, usize),
    #[error("Invalid descriptor size, expected: {0}, found: {1}")]
    UnexpectedDescriptorSize(usize, usize),
    #[error("Received unexpected readable descriptor at index {0}")]
    UnexpectedReadableDescriptor(usize),
    #[error("Invalid value for argument: {0}")]
    UnexpectedArgValue(String),
    #[error("Failed to create an epoll fd: {0}")]
    EpollFdCreate(std::io::Error),
    #[error("Failed to add to epoll: {0}")]
    EpollAdd(#[from] std::io::Error),
    #[error("Failed to modify evset associated with epoll: {0}")]
    EpollModify(std::io::Error),
    #[error("Failed to consume new epoll event: {0}")]
    EpollWait(std::io::Error),
    #[error("Failed to de-register fd from epoll: {0}")]
    EpollRemove(std::io::Error),
    #[error("No memory configured")]
    NoMemoryConfigured,
    #[error("Unable to create thread pool: {0}")]
    CreateThreadPool(std::io::Error),
}

impl convert::From<VuVideoError> for io::Error {
    fn from(e: VuVideoError) -> Self {
        io::Error::new(io::ErrorKind::Other, e)
    }
}

#[derive(ValueEnum, Debug, Default, Clone, Eq, PartialEq)]
pub(crate) enum BackendType {
    #[default]
    Null,
    #[cfg(feature = "v4l2-decoder")]
    V4L2Decoder,
}

/// Virtio Video Configuration
#[derive(Copy, Clone, Debug, Default, Eq, PartialEq)]
#[repr(C)]
pub(crate) struct VirtioVideoConfig {
    version: Le32,
    max_caps_length: Le32,
    max_resp_length: Le32,
    device_name: [u8; VIRTIO_V4L2_CARD_NAME_LEN],
}

// SAFETY: The layout of the structure is fixed and can be initialized by
// reading its content from byte array.
unsafe impl ByteValued for VirtioVideoConfig {}

pub(crate) struct VuVideoBackend {
    config: VirtioVideoConfig,
    pub threads: Vec<Mutex<VhostUserVideoThread>>,
    pub exit_event: EventFd,
}

impl VuVideoBackend {
    /// Create a new virtio video device for /dev/video<num>.
    pub fn new(video_path: &Path, video_backend: BackendType) -> Result<Self> {
        let backend = Arc::new(RwLock::new(video_backends::alloc_video_backend(
            video_backend,
            video_path,
        )?));
        Ok(Self {
            config: VirtioVideoConfig {
                version: 0.into(),
                max_caps_length: MAX_CAPS_LEN.into(),
                max_resp_length: MAX_RESP_LEN.into(),
                device_name: [0; 32],
            },
            threads: vec![Mutex::new(VhostUserVideoThread::new(backend.clone())?)],
            exit_event: EventFd::new(EFD_NONBLOCK).map_err(|_| VuVideoError::EventFdError)?,
        })
    }
}

/// VhostUserBackend trait methods
impl VhostUserBackendMut for VuVideoBackend {
    type Vring = VringRwLock;
    type Bitmap = ();

    fn num_queues(&self) -> usize {
        NUM_QUEUES
    }

    fn max_queue_size(&self) -> usize {
        QUEUE_SIZE
    }

    fn features(&self) -> u64 {
        debug!("Get features");
        1 << VIRTIO_F_VERSION_1
            | 1 << VIRTIO_F_NOTIFY_ON_EMPTY
            | 1 << VIRTIO_RING_F_INDIRECT_DESC
            | 1 << VIRTIO_RING_F_EVENT_IDX
            | 1 << VIRTIO_VIDEO_F_RESOURCE_GUEST_PAGES
            | VhostUserVirtioFeatures::PROTOCOL_FEATURES.bits()
    }

    fn protocol_features(&self) -> VhostUserProtocolFeatures {
        debug!("Get protocol features");
        VhostUserProtocolFeatures::MQ | VhostUserProtocolFeatures::CONFIG
    }

    fn set_event_idx(&mut self, enabled: bool) {
        for thread in self.threads.iter() {
            thread.lock().unwrap().event_idx = enabled;
        }
    }

    fn update_memory(&mut self, mem: GuestMemoryAtomic<GuestMemoryMmap>) -> IoResult<()> {
        for thread in self.threads.iter() {
            thread.lock().unwrap().mem = Some(mem.clone());
        }
        Ok(())
    }

    fn handle_event(
        &mut self,
        device_event: u16,
        evset: EventSet,
        vrings: &[VringRwLock],
        thread_id: usize,
    ) -> IoResult<()> {
        if evset != EventSet::IN {
            return Err(VuVideoError::HandleEventNotEpollIn.into());
        }

        let mut thread = self.threads[thread_id].lock().unwrap();
        let commandq = &vrings[COMMAND_Q as usize];
        let eventq = &vrings[EVENT_Q as usize];
        let evt_idx = thread.event_idx;

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
                // This queue is used by the device to asynchronously send
                // event notifications to the driver. Thus, we do not handle
                // incoming events.
                warn!("Unexpected event notification received");
            }

            VIDEO_EVENT => {
                thread.process_video_event(eventq)?;
            }

            _ => {
                warn!("unhandled device_event: {}", device_event);
                return Err(VuVideoError::HandleUnknownEvent.into());
            }
        }
        Ok(())
    }

    fn get_config(&self, _offset: u32, _size: u32) -> Vec<u8> {
        let offset = _offset as usize;
        let size = _size as usize;

        let buf = self.config.as_slice();

        if offset + size > buf.len() {
            return Vec::new();
        }

        buf[offset..offset + size].to_vec()
    }

    fn exit_event(&self, _thread_index: usize) -> Option<EventFd> {
        self.exit_event.try_clone().ok()
    }
}

#[cfg(test)]
pub mod tests {
    use std::{fs::File, path::PathBuf};

    use rstest::*;
    use tempfile::{tempdir, TempDir};
    use vm_memory::GuestAddress;

    use super::*;

    pub struct VideoDeviceMock {
        pub path: PathBuf,
        _dev: File,
    }

    impl VideoDeviceMock {
        pub fn new(test_dir: &TempDir) -> Self {
            let v4l2_device = test_dir.path().join("video.dev");
            Self {
                path: v4l2_device.to_owned(),
                _dev: File::create(v4l2_device.as_path())
                    .expect("Could not create a test device file."),
            }
        }
    }

    impl Drop for VideoDeviceMock {
        fn drop(&mut self) {
            std::fs::remove_file(&self.path).expect("Failed to clean up test device file.");
        }
    }

    fn setup_backend_memory(backend: &mut VuVideoBackend) -> [VringRwLock; 2] {
        let mem = GuestMemoryAtomic::new(
            GuestMemoryMmap::<()>::from_ranges(&[(GuestAddress(0), 0x10000)]).unwrap(),
        );
        let vrings = [
            VringRwLock::new(mem.clone(), 0x1000).unwrap(),
            VringRwLock::new(mem.clone(), 0x2000).unwrap(),
        ];
        vrings[0].set_queue_info(0x100, 0x200, 0x300).unwrap();
        vrings[0].set_queue_ready(true);
        vrings[1].set_queue_info(0x1100, 0x1200, 0x1300).unwrap();
        vrings[1].set_queue_ready(true);

        assert!(backend.update_memory(mem).is_ok());

        vrings
    }

    /// Creates a new test dir. There is no need to clean it after, since Drop
    /// is implemented for TempDir.
    #[fixture]
    pub fn test_dir() -> TempDir {
        tempdir().expect("Could not create a temp test directory.")
    }

    #[rstest]
    fn test_video_backend(test_dir: TempDir) {
        let v4l2_device = VideoDeviceMock::new(&test_dir);
        let backend = VuVideoBackend::new(Path::new(&v4l2_device.path), BackendType::Null);

        assert!(backend.is_ok());
        let mut backend = backend.unwrap();

        assert_eq!(backend.num_queues(), NUM_QUEUES);
        assert_eq!(backend.max_queue_size(), QUEUE_SIZE);
        assert_ne!(backend.features(), 0);
        assert!(!backend.protocol_features().is_empty());
        backend.set_event_idx(false);

        let vrings = setup_backend_memory(&mut backend);

        let config = backend.get_config(0, 4);
        assert_eq!(config.len(), 4);
        let version = u32::from_le_bytes(config.try_into().unwrap());
        assert_eq!(version, 0);

        let exit = backend.exit_event(0);
        assert!(exit.is_some());
        exit.unwrap().write(1).unwrap();
        for queue in COMMAND_Q..VIDEO_EVENT {
            // Skip exit event
            if queue == NUM_QUEUES as u16 {
                continue;
            }
            let ret = backend.handle_event(queue, EventSet::IN, &vrings, 0);
            assert!(ret.is_ok());
        }
    }

    #[rstest]
    fn test_video_backend_failures(test_dir: TempDir) {
        let v4l2_device = VideoDeviceMock::new(&test_dir);
        let mut backend = VuVideoBackend::new(Path::new(&v4l2_device.path), BackendType::Null)
            .expect("Could not create backend");
        let vrings = setup_backend_memory(&mut backend);

        // reading out of the config space, expecting empty config
        let config = backend.get_config(44, 1);
        assert_eq!(config.len(), 0);

        assert_eq!(
            backend
                .handle_event(COMMAND_Q, EventSet::OUT, &vrings, 0)
                .unwrap_err()
                .to_string(),
            VuVideoError::HandleEventNotEpollIn.to_string()
        );
        assert_eq!(
            backend
                .handle_event(VIDEO_EVENT + 1, EventSet::IN, &vrings, 0)
                .unwrap_err()
                .to_string(),
            VuVideoError::HandleUnknownEvent.to_string()
        );
    }
}
