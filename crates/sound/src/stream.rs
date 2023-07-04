// Manos Pitsidianakis <manos.pitsidianakis@linaro.org>
// SPDX-License-Identifier: Apache-2.0 or BSD-3-Clause

use thiserror::Error as ThisError;
use vm_memory::{Le32, Le64};

use crate::{virtio_sound::*, SUPPORTED_FORMATS, SUPPORTED_RATES};

/// Stream errors.
#[derive(Debug, ThisError)]
pub enum Error {
    #[error("Guest driver request an invalid stream state transition from {0} to {1}.")]
    InvalidStateTransition(PCMState, PCMState),
    #[error("Guest requested an invalid stream id: {0}")]
    InvalidStreamId(u32),
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
        Self::SetParameters
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
    pub features: Le32,
    /// size of hardware buffer in bytes
    pub buffer_bytes: Le32,
    /// size of hardware period in bytes
    pub period_bytes: Le32,
    pub channels: u8,
    pub format: u8,
    pub rate: u8,
}

impl Default for PcmParams {
    fn default() -> Self {
        Self {
            features: 0.into(),
            buffer_bytes: 8192.into(),
            period_bytes: 4096.into(),
            channels: 1,
            format: VIRTIO_SND_PCM_FMT_S16,
            rate: VIRTIO_SND_PCM_RATE_44100,
        }
    }
}

impl PcmParams {
    pub fn sample_bytes(&self) -> usize {
        match self.format {
            crate::virtio_sound::VIRTIO_SND_PCM_FMT_IMA_ADPCM
            | crate::virtio_sound::VIRTIO_SND_PCM_FMT_MU_LAW
            | crate::virtio_sound::VIRTIO_SND_PCM_FMT_A_LAW
            | crate::virtio_sound::VIRTIO_SND_PCM_FMT_S8
            | crate::virtio_sound::VIRTIO_SND_PCM_FMT_U8 => 1,
            crate::virtio_sound::VIRTIO_SND_PCM_FMT_S16 => 2,
            crate::virtio_sound::VIRTIO_SND_PCM_FMT_U16 => 2,
            crate::virtio_sound::VIRTIO_SND_PCM_FMT_S18_3
            | crate::virtio_sound::VIRTIO_SND_PCM_FMT_U18_3
            | crate::virtio_sound::VIRTIO_SND_PCM_FMT_S20_3
            | crate::virtio_sound::VIRTIO_SND_PCM_FMT_U20_3
            | crate::virtio_sound::VIRTIO_SND_PCM_FMT_S24_3
            | crate::virtio_sound::VIRTIO_SND_PCM_FMT_U24_3 => 3,
            crate::virtio_sound::VIRTIO_SND_PCM_FMT_S20 => 3,
            crate::virtio_sound::VIRTIO_SND_PCM_FMT_U20 => 3,
            crate::virtio_sound::VIRTIO_SND_PCM_FMT_S24
            | crate::virtio_sound::VIRTIO_SND_PCM_FMT_U24
            | crate::virtio_sound::VIRTIO_SND_PCM_FMT_S32
            | crate::virtio_sound::VIRTIO_SND_PCM_FMT_U32 => 4,
            crate::virtio_sound::VIRTIO_SND_PCM_FMT_FLOAT => 4,
            crate::virtio_sound::VIRTIO_SND_PCM_FMT_FLOAT64 => 8,
            crate::virtio_sound::VIRTIO_SND_PCM_FMT_DSD_U8
            | crate::virtio_sound::VIRTIO_SND_PCM_FMT_DSD_U16
            | crate::virtio_sound::VIRTIO_SND_PCM_FMT_DSD_U32
            | crate::virtio_sound::VIRTIO_SND_PCM_FMT_IEC958_SUBFRAME => {
                todo!()
            }
            _ => unreachable!(),
        }
    }

    pub fn frame(&self) -> usize {
        self.sample_bytes() * self.channels as usize
    }
}
