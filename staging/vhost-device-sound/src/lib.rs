// Manos Pitsidianakis <manos.pitsidianakis@linaro.org>
// SPDX-License-Identifier: Apache-2.0 or BSD-3-Clause

pub mod audio_backends;
pub mod device;
pub mod stream;
pub mod virtio_sound;

use std::{
    convert::TryFrom,
    io::{Error as IoError, ErrorKind},
    sync::Arc,
};

use clap::ValueEnum;
use log::{info, warn};
pub use stream::Stream;
use thiserror::Error as ThisError;
use vhost::{vhost_user, vhost_user::Listener};
use vhost_user_backend::{VhostUserDaemon, VringRwLock, VringT};
use virtio_sound::*;
use vm_memory::{
    ByteValued, Bytes, GuestMemoryAtomic, GuestMemoryLoadGuard, GuestMemoryMmap, Le32,
};

use crate::device::VhostUserSoundBackend;

pub const SUPPORTED_FORMATS: u64 = 1 << VIRTIO_SND_PCM_FMT_U8
    | 1 << VIRTIO_SND_PCM_FMT_S16
    | 1 << VIRTIO_SND_PCM_FMT_S24
    | 1 << VIRTIO_SND_PCM_FMT_S32;

pub const SUPPORTED_RATES: u64 = 1 << VIRTIO_SND_PCM_RATE_8000
    | 1 << VIRTIO_SND_PCM_RATE_11025
    | 1 << VIRTIO_SND_PCM_RATE_16000
    | 1 << VIRTIO_SND_PCM_RATE_22050
    | 1 << VIRTIO_SND_PCM_RATE_32000
    | 1 << VIRTIO_SND_PCM_RATE_44100
    | 1 << VIRTIO_SND_PCM_RATE_48000;

use virtio_queue::DescriptorChain;
pub type SoundDescriptorChain = DescriptorChain<GuestMemoryLoadGuard<GuestMemoryMmap<()>>>;
pub type Result<T> = std::result::Result<T, Error>;

/// Custom error types
#[derive(Debug, ThisError)]
pub enum Error {
    #[error("Notification send failed")]
    SendNotificationFailed,
    #[error("Descriptor not found")]
    DescriptorNotFound,
    #[error("Descriptor read failed")]
    DescriptorReadFailed,
    #[error("Descriptor write failed")]
    DescriptorWriteFailed,
    #[error("Failed to handle event other than EPOLLIN event")]
    HandleEventNotEpollIn,
    #[error("Failed to handle unknown event")]
    HandleUnknownEvent,
    #[error("Invalid control message code {0}")]
    InvalidControlMessage(u32),
    #[error("Failed to create a new EventFd")]
    EventFdCreate(IoError),
    #[error("Request missing data buffer")]
    SoundReqMissingData,
    #[error("Audio backend not supported")]
    AudioBackendNotSupported,
    #[error("No memory configured")]
    NoMemoryConfigured,
    #[error("Invalid virtio_snd_hdr size, expected: {0}, found: {1}")]
    UnexpectedSoundHeaderSize(usize, u32),
    #[error("Received unexpected write only descriptor at index {0}")]
    UnexpectedWriteOnlyDescriptor(usize),
    #[error("Received unexpected readable descriptor at index {0}")]
    UnexpectedReadableDescriptor(usize),
    #[error("Invalid descriptor count {0}")]
    UnexpectedDescriptorCount(usize),
    #[error("Invalid descriptor size, expected: {0}, found: {1}")]
    UnexpectedDescriptorSize(usize, u32),
    #[error("Protocol or device error: {0}")]
    Stream(stream::Error),
    #[error("Stream with id {0} not found")]
    StreamWithIdNotFound(u32),
    #[error("Channel number not supported: {0}")]
    ChannelNotSupported(u8),
}

impl From<Error> for IoError {
    fn from(e: Error) -> Self {
        Self::new(ErrorKind::Other, e)
    }
}

impl From<stream::Error> for Error {
    fn from(val: stream::Error) -> Self {
        Self::Stream(val)
    }
}

#[derive(ValueEnum, Clone, Copy, Default, Debug, Eq, PartialEq)]
pub enum BackendType {
    #[default]
    Null,
    #[cfg(feature = "pw-backend")]
    Pipewire,
    #[cfg(feature = "alsa-backend")]
    Alsa,
}

#[derive(Debug, PartialEq)]
pub struct InvalidControlMessage(u32);

impl std::fmt::Display for InvalidControlMessage {
    fn fmt(&self, fmt: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(fmt, "Invalid control message code {}", self.0)
    }
}

impl From<InvalidControlMessage> for crate::Error {
    fn from(val: InvalidControlMessage) -> Self {
        Self::InvalidControlMessage(val.0)
    }
}

impl std::error::Error for InvalidControlMessage {}

#[derive(Copy, Debug, Clone, Eq, PartialEq)]
#[repr(u32)]
pub enum ControlMessageKind {
    JackInfo = 1,
    JackRemap = 2,
    PcmInfo = 0x0100,
    PcmSetParams = 0x0101,
    PcmPrepare = 0x0102,
    PcmRelease = 0x0103,
    PcmStart = 0x0104,
    PcmStop = 0x0105,
    ChmapInfo = 0x0200,
}

impl TryFrom<Le32> for ControlMessageKind {
    type Error = InvalidControlMessage;

    fn try_from(val: Le32) -> std::result::Result<Self, Self::Error> {
        Ok(match u32::from(val) {
            VIRTIO_SND_R_JACK_INFO => Self::JackInfo,
            VIRTIO_SND_R_JACK_REMAP => Self::JackRemap,
            VIRTIO_SND_R_PCM_INFO => Self::PcmInfo,
            VIRTIO_SND_R_PCM_SET_PARAMS => Self::PcmSetParams,
            VIRTIO_SND_R_PCM_PREPARE => Self::PcmPrepare,
            VIRTIO_SND_R_PCM_RELEASE => Self::PcmRelease,
            VIRTIO_SND_R_PCM_START => Self::PcmStart,
            VIRTIO_SND_R_PCM_STOP => Self::PcmStop,
            VIRTIO_SND_R_CHMAP_INFO => Self::ChmapInfo,
            other => return Err(InvalidControlMessage(other)),
        })
    }
}

pub struct ControlMessage {
    pub kind: ControlMessageKind,
    pub code: u32,
    pub desc_chain: SoundDescriptorChain,
    pub descriptor: virtio_queue::Descriptor,
    pub vring: VringRwLock,
}

impl std::fmt::Debug for ControlMessage {
    fn fmt(&self, fmt: &mut std::fmt::Formatter) -> std::fmt::Result {
        fmt.debug_struct(stringify!(ControlMessage))
            .field("kind", &self.kind)
            .field("code", &self.code)
            .finish()
    }
}

impl Drop for ControlMessage {
    fn drop(&mut self) {
        log::trace!(
            "dropping ControlMessage {:?} reply = {}",
            self.kind,
            match self.code {
                virtio_sound::VIRTIO_SND_S_OK => "VIRTIO_SND_S_OK",
                virtio_sound::VIRTIO_SND_S_BAD_MSG => "VIRTIO_SND_S_BAD_MSG",
                virtio_sound::VIRTIO_SND_S_NOT_SUPP => "VIRTIO_SND_S_NOT_SUPP",
                virtio_sound::VIRTIO_SND_S_IO_ERR => "VIRTIO_SND_S_IO_ERR",
                _ => "other",
            }
        );
        let resp = VirtioSoundHeader {
            code: self.code.into(),
        };

        if let Err(err) = self
            .desc_chain
            .memory()
            .write_obj(resp, self.descriptor.addr())
        {
            log::error!("Error::DescriptorWriteFailed: {}", err);
            return;
        }
        if self
            .vring
            .add_used(self.desc_chain.head_index(), resp.as_slice().len() as u32)
            .is_err()
        {
            log::error!("Couldn't add used");
        }
        if self.vring.signal_used_queue().is_err() {
            log::error!("Couldn't signal used queue");
        }
    }
}

#[derive(Debug, Clone)]
/// This structure is the public API through which an external program
/// is allowed to configure the backend.
pub struct SoundConfig {
    /// vhost-user Unix domain socket
    socket: String,
    /// use multiple threads to hanlde the virtqueues
    multi_thread: bool,
    /// audio backend variant
    audio_backend: BackendType,
}

impl SoundConfig {
    /// Create a new instance of the SoundConfig struct, containing the
    /// parameters to be fed into the sound-backend server.
    pub fn new(socket: String, multi_thread: bool, audio_backend: BackendType) -> Self {
        Self {
            socket,
            multi_thread,
            audio_backend,
        }
    }

    /// Return the path of the unix domain socket which is listening to
    /// requests from the guest.
    pub fn get_socket_path(&self) -> String {
        String::from(&self.socket)
    }

    pub fn get_audio_backend(&self) -> BackendType {
        self.audio_backend
    }
}

pub struct IOMessage {
    status: std::sync::atomic::AtomicU32,
    pub latency_bytes: std::sync::atomic::AtomicU32,
    desc_chain: SoundDescriptorChain,
    descriptor: virtio_queue::Descriptor,
    vring: VringRwLock,
}

impl Drop for IOMessage {
    fn drop(&mut self) {
        log::trace!("dropping IOMessage");
        let resp = VirtioSoundPcmStatus {
            status: self.status.load(std::sync::atomic::Ordering::SeqCst).into(),
            latency_bytes: self
                .latency_bytes
                .load(std::sync::atomic::Ordering::SeqCst)
                .into(),
        };

        if let Err(err) = self
            .desc_chain
            .memory()
            .write_obj(resp, self.descriptor.addr())
        {
            log::error!("Error::DescriptorWriteFailed: {}", err);
            return;
        }
        if self
            .vring
            .add_used(self.desc_chain.head_index(), resp.as_slice().len() as u32)
            .is_err()
        {
            log::error!("Couldn't add used");
        }
        if self.vring.signal_used_queue().is_err() {
            log::error!("Couldn't signal used queue");
        }
    }
}

/// This is the public API through which an external program starts the
/// vhost-device-sound backend server.
pub fn start_backend_server(config: SoundConfig) {
    log::trace!("Using config {:?}", &config);
    let listener = Listener::new(config.get_socket_path(), true).unwrap();
    let backend = Arc::new(VhostUserSoundBackend::new(config).unwrap());

    let mut daemon = VhostUserDaemon::new(
        String::from("vhost-device-sound"),
        backend.clone(),
        GuestMemoryAtomic::new(GuestMemoryMmap::new()),
    )
    .unwrap();

    log::trace!("Starting daemon");
    daemon.start(listener).unwrap();

    match daemon.wait() {
        Ok(()) => {
            info!("Stopping cleanly");
        }
        Err(vhost_user_backend::Error::HandleRequest(vhost_user::Error::PartialMessage)) => {
            info!(
                "vhost-user connection closed with partial message. If the VM is shutting down, \
                 this is expected behavior; otherwise, it might be a bug."
            );
        }
        Err(e) => {
            warn!("Error running daemon: {:?}", e);
        }
    }

    // No matter the result, we need to shut down the worker thread.
    backend.send_exit_event();
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use vm_memory::{GuestMemoryAtomic, GuestMemoryMmap};

    use super::*;
    use crate::ControlMessageKind;

    #[test]
    fn test_sound_server() {
        const SOCKET_PATH: &str = "vsound.socket";

        let config = SoundConfig::new(SOCKET_PATH.to_string(), false, BackendType::Null);

        let backend = Arc::new(VhostUserSoundBackend::new(config.clone()).unwrap());
        let daemon = VhostUserDaemon::new(
            String::from("vhost-device-sound"),
            backend.clone(),
            GuestMemoryAtomic::new(GuestMemoryMmap::new()),
        )
        .unwrap();

        let vring_workers = daemon.get_epoll_handlers();

        // VhostUserSoundBackend support a single thread that handles the TX and RX
        // queues
        assert_eq!(backend.threads.len(), 1);

        assert_eq!(vring_workers.len(), backend.threads.len());
    }

    #[test]
    fn test_control_message_kind_try_from() {
        assert_eq!(
            ControlMessageKind::try_from(<u32 as Into<Le32>>::into(VIRTIO_SND_R_JACK_INFO)),
            Ok(ControlMessageKind::JackInfo)
        );
        assert_eq!(
            ControlMessageKind::try_from(<u32 as Into<Le32>>::into(VIRTIO_SND_R_PCM_INFO)),
            Ok(ControlMessageKind::PcmInfo)
        );
        assert_eq!(
            ControlMessageKind::try_from(<u32 as Into<Le32>>::into(VIRTIO_SND_R_CHMAP_INFO)),
            Ok(ControlMessageKind::ChmapInfo)
        );
        assert_eq!(
            ControlMessageKind::try_from(<u32 as Into<Le32>>::into(VIRTIO_SND_R_PCM_SET_PARAMS)),
            Ok(ControlMessageKind::PcmSetParams)
        );
    }

    #[test]
    fn test_control_message_kind_try_from_invalid() {
        // Test an invalid value that should result in an InvalidControlMessage error
        let invalid_value: u32 = 0x1101;
        assert_eq!(
            ControlMessageKind::try_from(<u32 as Into<Le32>>::into(invalid_value)),
            Err(InvalidControlMessage(invalid_value))
        );
    }
}
