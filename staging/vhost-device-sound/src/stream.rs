// Manos Pitsidianakis <manos.pitsidianakis@linaro.org>
// SPDX-License-Identifier: Apache-2.0 or BSD-3-Clause

use std::{collections::VecDeque, sync::Arc};

use thiserror::Error as ThisError;
use vm_memory::{Address, Bytes, Le32, Le64};

use crate::{virtio_sound::*, IOMessage, SUPPORTED_FORMATS, SUPPORTED_RATES};

/// Stream errors.
#[derive(Debug, ThisError)]
pub enum Error {
    #[error("Guest driver request an invalid stream state transition from {0} to {1}.")]
    InvalidStateTransition(PCMState, PCMState),
    #[error("Guest requested an invalid stream id: {0}")]
    InvalidStreamId(u32),
    #[error("Descriptor read failed")]
    DescriptorReadFailed,
}

type Result<T> = std::result::Result<T, Error>;

/// PCM stream state machine.
///
/// ## 5.14.6.6.1 PCM Command Lifecycle
///
/// A PCM stream has the following command lifecycle:
///
/// - `SET PARAMETERS`
///
///   The driver negotiates the stream parameters (format, transport, etc) with
/// the device.
///
///   Possible valid transitions: `SET PARAMETERS`, `PREPARE`.
///
/// - `PREPARE`
///
///   The device prepares the stream (allocates resources, etc).
///
///   Possible valid transitions: `SET PARAMETERS`, `PREPARE`, `START`,
/// `RELEASE`.   Output only: the driver transfers data for pre-buffing.
///
/// - `START`
///
///   The device starts the stream (unmute, putting into running state, etc).
///
///   Possible valid transitions: `STOP`.
///   The driver transfers data to/from the stream.
///
/// - `STOP`
///
///   The device stops the stream (mute, putting into non-running state, etc).
///
///   Possible valid transitions: `START`, `RELEASE`.
///
/// - `RELEASE`
///
///   The device releases the stream (frees resources, etc).
///
///   Possible valid transitions: `SET PARAMETERS`, `PREPARE`.
///
/// ```text
/// +---------------+ +---------+ +---------+ +-------+ +-------+
/// | SetParameters | | Prepare | | Release | | Start | | Stop  |
/// +---------------+ +---------+ +---------+ +-------+ +-------+
///         |              |           |          |         |
///         |-             |           |          |         |
///         ||             |           |          |         |
///         |<             |           |          |         |
///         |              |           |          |         |
///         |------------->|           |          |         |
///         |              |           |          |         |
///         |<-------------|           |          |         |
///         |              |           |          |         |
///         |              |-          |          |         |
///         |              ||          |          |         |
///         |              |<          |          |         |
///         |              |           |          |         |
///         |              |--------------------->|         |
///         |              |           |          |         |
///         |              |---------->|          |         |
///         |              |           |          |         |
///         |              |           |          |-------->|
///         |              |           |          |         |
///         |              |           |          |<--------|
///         |              |           |          |         |
///         |              |           |<-------------------|
///         |              |           |          |         |
///         |<-------------------------|          |         |
///         |              |           |          |         |
///         |              |<----------|          |         |
/// ```
#[derive(Debug, Default, Copy, Clone)]
pub enum PCMState {
    #[default]
    #[doc(alias = "VIRTIO_SND_R_PCM_SET_PARAMS")]
    SetParameters,
    #[doc(alias = "VIRTIO_SND_R_PCM_PREPARE")]
    Prepare,
    #[doc(alias = "VIRTIO_SND_R_PCM_RELEASE")]
    Release,
    #[doc(alias = "VIRTIO_SND_R_PCM_START")]
    Start,
    #[doc(alias = "VIRTIO_SND_R_PCM_STOP")]
    Stop,
}

macro_rules! set_new_state {
    ($new_state_fn:ident, $new_state:expr, $($valid_source_states:tt)*) => {
        pub fn $new_state_fn(&mut self) -> Result<()> {
            if !matches!(self, $($valid_source_states)*) {
                return Err(Error::InvalidStateTransition(*self, $new_state));
            }
            *self = $new_state;
            Ok(())
        }
    };
}

impl PCMState {
    pub fn new() -> Self {
        Self::default()
    }

    set_new_state!(
        set_parameters,
        Self::SetParameters,
        Self::SetParameters | Self::Prepare | Self::Release
    );

    set_new_state!(
        prepare,
        Self::Prepare,
        Self::SetParameters | Self::Prepare | Self::Release
    );

    set_new_state!(start, Self::Start, Self::Prepare | Self::Stop);

    set_new_state!(stop, Self::Stop, Self::Start);

    set_new_state!(release, Self::Release, Self::Prepare | Self::Stop);
}

impl std::fmt::Display for PCMState {
    fn fmt(&self, fmt: &mut std::fmt::Formatter) -> std::fmt::Result {
        use PCMState::*;
        match *self {
            SetParameters => {
                write!(fmt, "VIRTIO_SND_R_PCM_SET_PARAMS")
            }
            Prepare => {
                write!(fmt, "VIRTIO_SND_R_PCM_PREPARE")
            }
            Release => {
                write!(fmt, "VIRTIO_SND_R_PCM_RELEASE")
            }
            Start => {
                write!(fmt, "VIRTIO_SND_R_PCM_START")
            }
            Stop => {
                write!(fmt, "VIRTIO_SND_R_PCM_STOP")
            }
        }
    }
}

/// Internal state of a PCM stream of the VIRTIO Sound device.
#[derive(Debug)]
pub struct Stream {
    pub id: usize,
    pub params: PcmParams,
    pub formats: Le64,
    pub rates: Le64,
    pub direction: u8,
    pub channels_min: u8,
    pub channels_max: u8,
    pub state: PCMState,
    pub buffers: VecDeque<Buffer>,
}

impl Default for Stream {
    fn default() -> Self {
        Self {
            id: 0,
            direction: VIRTIO_SND_D_OUTPUT,
            formats: SUPPORTED_FORMATS.into(),
            rates: SUPPORTED_RATES.into(),
            params: PcmParams::default(),
            channels_min: 1,
            channels_max: 6,
            state: Default::default(),
            buffers: VecDeque::new(),
        }
    }
}

impl Stream {
    #[inline]
    pub fn supports_format(&self, format: u8) -> bool {
        let formats: u64 = self.formats.into();
        (formats & (1_u64 << format)) != 0
    }

    #[inline]
    pub fn supports_rate(&self, rate: u8) -> bool {
        let rates: u64 = self.rates.into();
        (rates & (1_u64 << rate)) != 0
    }
}

/// Stream params
#[derive(Debug)]
pub struct PcmParams {
    /// size of hardware buffer in bytes
    pub buffer_bytes: Le32,
    /// size of hardware period in bytes
    pub period_bytes: Le32,
    pub features: Le32,
    pub channels: u8,
    pub format: u8,
    pub rate: u8,
}

impl Default for PcmParams {
    fn default() -> Self {
        Self {
            buffer_bytes: 8192.into(),
            period_bytes: 4096.into(),
            features: 0.into(),
            channels: 1,
            format: VIRTIO_SND_PCM_FMT_S16,
            rate: VIRTIO_SND_PCM_RATE_44100,
        }
    }
}

pub struct Buffer {
    // TODO: to make private and add len usize
    pub data_descriptor: virtio_queue::Descriptor,
    pub pos: usize,
    pub message: Arc<IOMessage>,
}

impl std::fmt::Debug for Buffer {
    fn fmt(&self, fmt: &mut std::fmt::Formatter) -> std::fmt::Result {
        fmt.debug_struct(stringify!(Buffer))
            .field("pos", &self.pos)
            .field("message", &Arc::as_ptr(&self.message))
            .finish()
    }
}

impl Buffer {
    pub fn new(data_descriptor: virtio_queue::Descriptor, message: Arc<IOMessage>) -> Self {
        Self {
            pos: 0,
            data_descriptor,
            message,
        }
    }

    pub fn consume(&self, buf: &mut [u8]) -> Result<u32> {
        let addr = self.data_descriptor.addr();
        let offset = self.pos as u64;
        let len = self
            .message
            .desc_chain
            .memory()
            .read(
                buf,
                addr.checked_add(offset)
                    .expect("invalid guest memory address"),
            )
            .map_err(|_| Error::DescriptorReadFailed)?;
        Ok(len as u32)
    }
}

impl Drop for Buffer {
    fn drop(&mut self) {
        log::trace!("dropping buffer {:?}", self);
    }
}
