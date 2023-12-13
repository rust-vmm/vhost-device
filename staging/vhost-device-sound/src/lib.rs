// Manos Pitsidianakis <manos.pitsidianakis@linaro.org>
// SPDX-License-Identifier: Apache-2.0 or BSD-3-Clause
//
#![deny(
    /* groups */
    clippy::correctness,
    clippy::suspicious,
    clippy::complexity,
    clippy::perf,
    clippy::style,
    clippy::nursery,
    //* restriction */
    clippy::dbg_macro,
    clippy::rc_buffer,
    clippy::as_underscore,
    clippy::assertions_on_result_states,
    //* pedantic */
    clippy::cast_lossless,
    clippy::cast_possible_wrap,
    clippy::ptr_as_ptr,
    clippy::bool_to_int_with_if,
    clippy::borrow_as_ptr,
    clippy::case_sensitive_file_extension_comparisons,
    clippy::cast_lossless,
    clippy::cast_ptr_alignment,
    clippy::naive_bytecount
)]
#![allow(
    clippy::significant_drop_in_scrutinee,
    clippy::significant_drop_tightening
)]

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
pub use stream::Stream;
use thiserror::Error as ThisError;
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

/// Stream direction.
///
/// Equivalent to `VIRTIO_SND_D_OUTPUT` and `VIRTIO_SND_D_INPUT`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum Direction {
    /// [`VIRTIO_SND_D_OUTPUT`](crate::virtio_sound::VIRTIO_SND_D_OUTPUT)
    Output = VIRTIO_SND_D_OUTPUT,
    /// [`VIRTIO_SND_D_INPUT`](crate::virtio_sound::VIRTIO_SND_D_INPUT)
    Input = VIRTIO_SND_D_INPUT,
}

impl TryFrom<u8> for Direction {
    type Error = Error;

    fn try_from(val: u8) -> std::result::Result<Self, Self::Error> {
        Ok(match val {
            virtio_sound::VIRTIO_SND_D_OUTPUT => Self::Output,
            virtio_sound::VIRTIO_SND_D_INPUT => Self::Input,
            other => return Err(Error::InvalidMessageValue(stringify!(Direction), other)),
        })
    }
}

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
    #[error("Failed to handle unknown event with id {0}")]
    HandleUnknownEvent(u16),
    #[error("Invalid control message code {0}")]
    InvalidControlMessage(u32),
    #[error("Invalid value in {0}: {1}")]
    InvalidMessageValue(&'static str, u8),
    #[error("Failed to create a new EventFd")]
    EventFdCreate(IoError),
    #[error("Request missing data buffer")]
    SoundReqMissingData,
    #[error("Audio backend not supported")]
    AudioBackendNotSupported,
    #[error("Audio backend unexpected error: {0}")]
    UnexpectedAudioBackendError(String),
    #[error("Audio backend configuration not supported")]
    UnexpectedAudioBackendConfiguration,
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

#[derive(Debug, PartialEq, Eq)]
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
    pub const fn new(socket: String, multi_thread: bool, audio_backend: BackendType) -> Self {
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

    pub const fn get_audio_backend(&self) -> BackendType {
        self.audio_backend
    }
}

pub struct IOMessage {
    status: std::sync::atomic::AtomicU32,
    pub used_len: std::sync::atomic::AtomicU32,
    pub latency_bytes: std::sync::atomic::AtomicU32,
    desc_chain: SoundDescriptorChain,
    response_descriptor: virtio_queue::Descriptor,
    vring: VringRwLock,
}

impl Drop for IOMessage {
    fn drop(&mut self) {
        let resp = VirtioSoundPcmStatus {
            status: self.status.load(std::sync::atomic::Ordering::SeqCst).into(),
            latency_bytes: self
                .latency_bytes
                .load(std::sync::atomic::Ordering::SeqCst)
                .into(),
        };
        let used_len: u32 = self.used_len.load(std::sync::atomic::Ordering::SeqCst);
        log::trace!("dropping IOMessage {:?}", resp);

        if let Err(err) = self
            .desc_chain
            .memory()
            .write_obj(resp, self.response_descriptor.addr())
        {
            log::error!("Error::DescriptorWriteFailed: {}", err);
            return;
        }
        if let Err(err) = self.vring.add_used(
            self.desc_chain.head_index(),
            resp.as_slice().len() as u32 + used_len,
        ) {
            log::error!("Couldn't add used bytes count to vring: {}", err);
        }
        if let Err(err) = self.vring.signal_used_queue() {
            log::error!("Couldn't signal used queue: {}", err);
        }
    }
}

/// This is the public API through which an external program starts the
/// vhost-device-sound backend server.
pub fn start_backend_server(config: SoundConfig) {
    log::trace!("Using config {:?}.", &config);
    let socket = config.get_socket_path();
    let backend = Arc::new(VhostUserSoundBackend::new(config).unwrap());

    let mut daemon = VhostUserDaemon::new(
        String::from("vhost-device-sound"),
        backend,
        GuestMemoryAtomic::new(GuestMemoryMmap::new()),
    )
    .unwrap();

    log::trace!("Starting daemon.");
    daemon.serve(socket).unwrap();
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

        let backend = Arc::new(VhostUserSoundBackend::new(config).unwrap());
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

    #[test]
    fn test_try_from_valid_output() {
        let val = virtio_sound::VIRTIO_SND_D_OUTPUT;
        assert_eq!(Direction::try_from(val).unwrap(), Direction::Output);

        let val = virtio_sound::VIRTIO_SND_D_INPUT;
        assert_eq!(Direction::try_from(val).unwrap(), Direction::Input);

        let val = 42;
        Direction::try_from(val).unwrap_err();
    }

    #[test]
    fn test_display() {
        let error = InvalidControlMessage(42);
        let formatted_error = format!("{}", error);
        assert_eq!(formatted_error, "Invalid control message code 42");
    }

    #[test]
    fn test_into_error() {
        let error = InvalidControlMessage(42);
        let _error: Error = error.into();

        // Test from stream Error
        let stream_error = stream::Error::DescriptorReadFailed;
        let _error: Error = stream_error.into();
    }
}
