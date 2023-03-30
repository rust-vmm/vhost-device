// SPDX-License-Identifier: Apache-2.0 or BSD-3-Clause

use std::{
    io::{self, Result as IoResult},
    u16, u32, u64, u8,
};
use thiserror::Error as ThisError;
use vhost::vhost_user::message::{VhostUserProtocolFeatures, VhostUserVirtioFeatures};
use vhost_user_backend::{VhostUserBackendMut, VringRwLock};
use virtio_bindings::bindings::{
    virtio_config::VIRTIO_F_NOTIFY_ON_EMPTY, virtio_config::VIRTIO_F_VERSION_1,
    virtio_ring::VIRTIO_RING_F_EVENT_IDX, virtio_ring::VIRTIO_RING_F_INDIRECT_DESC,
};
use vm_memory::{ByteValued, GuestMemoryAtomic, GuestMemoryMmap, Le32};
use vmm_sys_util::{
    epoll::EventSet,
    eventfd::{EventFd, EFD_NONBLOCK},
};

const CONTROL_Q: u16 = 0;
const EVENT_Q: u16 = 1;
const TX_Q: u16 = 2;
const RX_Q: u16 = 3;

pub(crate) type Result<T> = std::result::Result<T, Error>;

/// Custom error types
#[derive(Debug, ThisError)]
pub(crate) enum Error {
    #[error("Failed to handle event other than EPOLLIN event")]
    HandleEventNotEpollIn,
    #[error("Failed to handle unknown event")]
    HandleUnknownEvent,
    #[error("Failed to create a new EventFd")]
    EventFdCreate(std::io::Error),
}

impl std::convert::From<Error> for std::io::Error {
    fn from(e: Error) -> Self {
        std::io::Error::new(io::ErrorKind::Other, e)
    }
}

#[derive(Debug, Clone)]
/// This structure is the public API through which an external program
/// is allowed to configure the backend.
pub(crate) struct SoundConfig {
    socket: String,
}

impl SoundConfig {
    /// Create a new instance of the SoundConfig struct, containing the
    /// parameters to be fed into the sound-backend server.
    pub fn new(socket: String) -> Self {
        Self { socket }
    }

    /// Return the path of the unix domain socket which is listening to
    /// requests from the guest.
    pub fn get_socket_path(&self) -> String {
        String::from(&self.socket)
    }
}

/// Virtio Sound Configuration
#[derive(Copy, Clone, Debug, Default, PartialEq)]
#[repr(C)]
struct VirtioSoundConfig {
    /// total number of all available jacks
    jacks: Le32,
    /// total number of all available PCM streams
    streams: Le32,
    /// total number of all available channel maps
    chmpas: Le32,
}
// SAFETY: The layout of the structure is fixed and can be initialized by
// reading its content from byte array.
unsafe impl ByteValued for VirtioSoundConfig {}

/// Virtio Sound Request / Response common header
#[derive(Copy, Clone, Debug, Default, PartialEq)]
#[repr(C)]
struct VirtioSoundHeader {
    /// request type / response status
    code: Le32,
}
// SAFETY: The layout of the structure is fixed and can be initialized by
// reading its content from byte array.
unsafe impl ByteValued for VirtioSoundHeader {}

pub(crate) struct VhostUserSoundBackend {
    config: VirtioSoundConfig,
    queues_per_thread: Vec<u64>,
    event_idx: bool,
    pub(crate) exit_event: EventFd,
    mem: Option<GuestMemoryAtomic<GuestMemoryMmap>>,
}

impl VhostUserSoundBackend {
    pub fn new(_config: SoundConfig) -> Result<Self> {
        let queues_per_thread = vec![0b1111];

        Ok(Self {
            config: VirtioSoundConfig {
                jacks: 0.into(),
                streams: 1.into(),
                chmpas: 0.into(),
            },
            queues_per_thread,
            event_idx: false,
            exit_event: EventFd::new(EFD_NONBLOCK).map_err(Error::EventFdCreate)?,
            mem: None,
        })
    }
}

impl VhostUserBackendMut<VringRwLock, ()> for VhostUserSoundBackend {
    fn num_queues(&self) -> usize {
        4
    }

    fn max_queue_size(&self) -> usize {
        256
    }

    fn features(&self) -> u64 {
        1 << VIRTIO_F_VERSION_1
            | 1 << VIRTIO_F_NOTIFY_ON_EMPTY
            | 1 << VIRTIO_RING_F_INDIRECT_DESC
            | 1 << VIRTIO_RING_F_EVENT_IDX
            | VhostUserVirtioFeatures::PROTOCOL_FEATURES.bits()
    }

    fn protocol_features(&self) -> VhostUserProtocolFeatures {
        VhostUserProtocolFeatures::CONFIG
    }

    fn set_event_idx(&mut self, enabled: bool) {
        self.event_idx = enabled;
    }

    fn update_memory(&mut self, mem: GuestMemoryAtomic<GuestMemoryMmap>) -> IoResult<()> {
        self.mem = Some(mem);
        Ok(())
    }

    fn handle_event(
        &mut self,
        device_event: u16,
        evset: EventSet,
        _vrings: &[VringRwLock],
        _thread_id: usize,
    ) -> IoResult<bool> {
        if evset != EventSet::IN {
            return Err(Error::HandleEventNotEpollIn.into());
        }

        match device_event {
            CONTROL_Q => {}
            EVENT_Q => {}
            TX_Q => {}
            RX_Q => {}
            _ => {
                return Err(Error::HandleUnknownEvent.into());
            }
        }

        Ok(false)
    }

    fn get_config(&self, offset: u32, size: u32) -> Vec<u8> {
        let offset = offset as usize;
        let size = size as usize;

        let buf = self.config.as_slice();

        if offset + size > buf.len() {
            return Vec::new();
        }

        buf[offset..offset + size].to_vec()
    }

    fn queues_per_thread(&self) -> Vec<u64> {
        self.queues_per_thread.clone()
    }

    fn exit_event(&self, _thread_index: usize) -> Option<EventFd> {
        self.exit_event.try_clone().ok()
    }
}
