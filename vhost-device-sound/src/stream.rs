// Manos Pitsidianakis <manos.pitsidianakis@linaro.org>
// SPDX-License-Identifier: Apache-2.0 or BSD-3-Clause

use std::{
    collections::VecDeque,
    convert::TryFrom,
    io::{Read, Write},
    mem::size_of,
    sync::Arc,
};

use thiserror::Error as ThisError;
use vm_memory::{Le32, Le64};

use crate::{virtio_sound::*, Direction, IOMessage, SUPPORTED_FORMATS, SUPPORTED_RATES};

/// Stream errors.
#[derive(Debug, ThisError, PartialEq, Eq)]
pub enum Error {
    #[error("Guest driver request {0} in an invalid stream state {1}")]
    InvalidState(&'static str, PCMState),
    #[error("Guest driver request an invalid stream state transition from {0} to {1}.")]
    InvalidStateTransition(PCMState, PCMState),
    #[error("Guest requested an invalid stream id: {0}")]
    InvalidStreamId(u32),
    #[error("Descriptor read failed")]
    DescriptorReadFailed,
    #[error("Descriptor write failed")]
    DescriptorWriteFailed,
    #[error("Could not disconnect stream")]
    CouldNotDisconnectStream,
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
///   the device.
///
///   Possible valid transitions: `SET PARAMETERS`, `PREPARE`.
///
/// - `PREPARE`
///
///   The device prepares the stream (allocates resources, etc).
///
///   Possible valid transitions: `SET PARAMETERS`, `PREPARE`, `START`,
///   `RELEASE`. Output only: the driver transfers data for pre-buffing.
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
#[derive(Debug, Default, Copy, Clone, PartialEq, Eq)]
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
        match *self {
            Self::SetParameters => {
                write!(fmt, "VIRTIO_SND_R_PCM_SET_PARAMS")
            }
            Self::Prepare => {
                write!(fmt, "VIRTIO_SND_R_PCM_PREPARE")
            }
            Self::Release => {
                write!(fmt, "VIRTIO_SND_R_PCM_RELEASE")
            }
            Self::Start => {
                write!(fmt, "VIRTIO_SND_R_PCM_START")
            }
            Self::Stop => {
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
    pub direction: Direction,
    pub channels_min: u8,
    pub channels_max: u8,
    pub state: PCMState,
    pub requests: VecDeque<Request>,
}

impl Default for Stream {
    fn default() -> Self {
        Self {
            id: 0,
            direction: Direction::Output,
            formats: SUPPORTED_FORMATS.into(),
            rates: SUPPORTED_RATES.into(),
            params: PcmParams::default(),
            channels_min: 1,
            channels_max: 6,
            state: Default::default(),
            requests: VecDeque::new(),
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

pub struct Request {
    pub pos: usize,
    len: usize,
    pub message: Arc<IOMessage>,
    direction: Direction,
}

impl std::fmt::Debug for Request {
    fn fmt(&self, fmt: &mut std::fmt::Formatter) -> std::fmt::Result {
        fmt.debug_struct(stringify!(Request))
            .field("pos", &self.pos)
            .field("len", &self.len)
            .field("direction", &self.direction)
            .field("message", &Arc::as_ptr(&self.message))
            .finish()
    }
}

impl Request {
    pub fn new(len: usize, message: Arc<IOMessage>, direction: Direction) -> Self {
        Self {
            pos: 0,
            len,
            message,
            direction,
        }
    }

    pub fn read_output(&self, buf: &mut [u8]) -> Result<u32> {
        let mem = self.message.desc_chain.memory();

        let mut reader = self
            .message
            .desc_chain
            .clone()
            .reader(mem)
            .map_err(|_| Error::DescriptorReadFailed)?;

        let mut reader_content = reader
            .split_at(size_of::<VirtioSoundPcmXfer>() + self.pos)
            .map_err(|_| Error::DescriptorReadFailed)?;

        let bytes_read = reader_content
            .read(buf)
            .map_err(|_| Error::DescriptorReadFailed)?;

        Ok(bytes_read as u32)
    }

    pub fn write_input(&mut self, buf: &[u8]) -> Result<u32> {
        let mem = self.message.desc_chain.memory();

        let mut writer = self
            .message
            .desc_chain
            .clone()
            .writer(mem)
            .map_err(|_| Error::DescriptorReadFailed)?;

        let mut _status = writer
            .split_at(self.len)
            .map_err(|_| Error::DescriptorReadFailed)?;

        let mut write_content = writer
            .split_at(self.pos)
            .map_err(|_| Error::DescriptorReadFailed)?;

        let bytes_written = write_content
            .write(buf)
            .map_err(|_| Error::DescriptorWriteFailed)?;

        self.pos += bytes_written;

        Ok(bytes_written as u32)
    }

    #[inline]
    /// Returns the length of the sound data [`virtio_queue::Descriptor`].
    pub const fn len(&self) -> usize {
        self.len
    }

    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }
}

impl Drop for Request {
    fn drop(&mut self) {
        // Since used_len is 32 bits, but self.len() may be bigger
        // than that, the spec is unclear about how to handle this
        // case, so when converting from usize to u32, saturate
        // when conversion overflows
        let payload_len = match u32::try_from(self.len()) {
            Ok(len) => len,
            Err(len) => {
                log::warn!("used_len {} overflows u32", len);
                u32::MAX
            }
        };

        match self.direction {
            Direction::Input => {
                let used_len = std::cmp::min(self.pos as u32, payload_len);
                self.message
                    .used_len
                    .fetch_add(used_len, std::sync::atomic::Ordering::SeqCst);
                self.message
                    .latency_bytes
                    .fetch_add(used_len, std::sync::atomic::Ordering::SeqCst);
            }
            Direction::Output => {
                self.message
                    .latency_bytes
                    .fetch_add(payload_len, std::sync::atomic::Ordering::SeqCst);
            }
        }
        log::trace!("dropping {:?} request {:?}", self.direction, self);
    }
}

#[cfg(test)]
mod tests {
    use std::fmt::Write;

    use vhost_user_backend::{VringRwLock, VringT};
    use virtio_bindings::bindings::virtio_ring::{VRING_DESC_F_NEXT, VRING_DESC_F_WRITE};
    use virtio_queue::{mock::MockSplitQueue, Descriptor, Queue, QueueOwnedT};
    use vm_memory::{
        Address, ByteValued, Bytes, GuestAddress, GuestAddressSpace, GuestMemoryAtomic,
        GuestMemoryMmap,
    };

    use super::*;
    use crate::SoundDescriptorChain;

    // Prepares a single chain of descriptors for request queue
    fn prepare_desc_chain<R: ByteValued>(
        start_addr: GuestAddress,
        hdr: R,
        payload_len: u32,
        response_len: u32,
    ) -> SoundDescriptorChain {
        let mem = &GuestMemoryMmap::<()>::from_ranges(&[(start_addr, 0x1000)]).unwrap();
        let vq = MockSplitQueue::new(mem, 16);
        let mut next_addr = vq.desc_table().total_size() + 0x100;
        let mut index = 0;

        let desc_out = Descriptor::new(
            next_addr,
            (std::mem::size_of::<R>() as u32)
                .checked_add(payload_len)
                .unwrap(),
            VRING_DESC_F_NEXT as u16,
            index + 1,
        );

        mem.write_obj::<R>(hdr, desc_out.addr()).unwrap();
        vq.desc_table().store(index, desc_out).unwrap();
        next_addr += u64::from(desc_out.len());
        index += 1;

        // In response descriptor
        let desc_in = Descriptor::new(next_addr, response_len, VRING_DESC_F_WRITE as u16, 0);
        vq.desc_table().store(index, desc_in).unwrap();

        // Put the descriptor index 0 in the first available ring position.
        mem.write_obj(0u16, vq.avail_addr().unchecked_add(4))
            .unwrap();

        // Set `avail_idx` to 1.
        mem.write_obj(1u16, vq.avail_addr().unchecked_add(2))
            .unwrap();

        // Create descriptor chain from pre-filled memory
        vq.create_queue::<Queue>()
            .unwrap()
            .iter(GuestMemoryAtomic::new(mem.clone()).memory())
            .unwrap()
            .next()
            .unwrap()
    }

    fn iomsg(payload_len: u32, response_len: u32) -> IOMessage {
        let hdr = VirtioSoundPcmHeader::default();
        let memr = GuestMemoryAtomic::new(
            GuestMemoryMmap::<()>::from_ranges(&[(GuestAddress(0), 0x10000)]).unwrap(),
        );
        let vring = VringRwLock::new(memr, 0x1000).unwrap();
        IOMessage {
            status: VIRTIO_SND_S_OK.into(),
            latency_bytes: 0.into(),
            used_len: 0.into(),
            desc_chain: prepare_desc_chain::<VirtioSoundPcmHeader>(
                GuestAddress(0),
                hdr,
                payload_len,
                response_len,
            ),
            vring,
        }
    }

    #[test]
    fn test_display_fmt() {
        assert_eq!(&PCMState::Stop.to_string(), "VIRTIO_SND_R_PCM_STOP");
    }

    #[test]
    fn test_logging() {
        let msg = iomsg(0, size_of::<VirtioSoundPcmStatus>() as u32);
        let message = Arc::new(msg);
        let direction = Direction::Input;
        let request = Request::new(0, message, direction);
        assert_eq!(format!("{direction:?}"), "Input");
        assert_eq!(
            format!("{request:?}"),
            format!(
                "Request {{ pos: 0, len: 0, direction: Input, message: {:?} }}",
                &Arc::as_ptr(&request.message)
            )
        );
    }

    #[test]
    fn test_pcm_state_transitions() {
        let mut state = PCMState::new();
        assert_eq!(state, PCMState::SetParameters);

        state.set_parameters().unwrap();
        assert_eq!(state, PCMState::SetParameters);

        state.prepare().unwrap();
        assert_eq!(state, PCMState::Prepare);

        state.release().unwrap();
        assert_eq!(state, PCMState::Release);
    }

    #[test]
    fn test_invalid_state_transition() {
        let mut state = PCMState::new();
        assert_eq!(state, PCMState::SetParameters);

        // Attempt to transition from set_params state to Release state
        let result = state.release();
        assert_eq!(
            result,
            Err(Error::InvalidStateTransition(
                PCMState::SetParameters,
                PCMState::Release
            ))
        );

        let result = state.start();
        assert_eq!(
            result,
            Err(Error::InvalidStateTransition(
                PCMState::SetParameters,
                PCMState::Start
            ))
        );

        let result = state.stop();
        assert_eq!(
            result,
            Err(Error::InvalidStateTransition(
                PCMState::SetParameters,
                PCMState::Stop
            ))
        );

        state.prepare().unwrap();
        let result = state.stop();
        assert_eq!(
            result,
            Err(Error::InvalidStateTransition(
                PCMState::Prepare,
                PCMState::Stop
            ))
        );

        state.start().unwrap();
        let result = state.set_parameters();
        assert_eq!(
            result,
            Err(Error::InvalidStateTransition(
                PCMState::Start,
                PCMState::SetParameters
            ))
        );

        let result = state.release();
        assert_eq!(
            result,
            Err(Error::InvalidStateTransition(
                PCMState::Start,
                PCMState::Release
            ))
        );

        let result = state.prepare();
        assert_eq!(
            result,
            Err(Error::InvalidStateTransition(
                PCMState::Start,
                PCMState::Prepare
            ))
        );

        state.stop().unwrap();
        let result = state.set_parameters();
        assert_eq!(
            result,
            Err(Error::InvalidStateTransition(
                PCMState::Stop,
                PCMState::SetParameters
            ))
        );

        let result = state.prepare();
        assert_eq!(
            result,
            Err(Error::InvalidStateTransition(
                PCMState::Stop,
                PCMState::Prepare
            ))
        );
    }

    #[test]
    fn test_stream_supports_format() {
        let stream = Stream::default();
        assert!(stream.supports_format(VIRTIO_SND_PCM_FMT_S16));
        assert!(stream.supports_rate(VIRTIO_SND_PCM_RATE_44100));
    }

    #[test]
    fn test_pcm_params_default() {
        let params = PcmParams::default();
        assert_eq!(params.buffer_bytes, 8192);
        assert_eq!(params.period_bytes, 4096);
        assert_eq!(params.features, 0);
        assert_eq!(params.channels, 1);
        assert_eq!(params.format, VIRTIO_SND_PCM_FMT_S16);
        assert_eq!(params.rate, VIRTIO_SND_PCM_RATE_44100);
    }

    #[test]
    fn test_request_read_output() {
        let mut buf = vec![0; 5];
        let msg = iomsg(buf.len() as u32, size_of::<VirtioSoundPcmStatus>() as u32);
        let message = Arc::new(msg);
        let request = Request::new(buf.len(), message, Direction::Output);

        let len = request.read_output(&mut buf).unwrap();
        assert_eq!(len, buf.len() as u32);
    }

    #[test]
    fn test_request_write_input() {
        let buf = vec![0; 5];
        let msg = iomsg(
            0,
            size_of::<VirtioSoundPcmStatus>() as u32 + buf.len() as u32,
        );
        let message = Arc::new(msg);
        let mut request = Request::new(buf.len(), message, Direction::Input);

        request.write_input(&buf).unwrap();
    }

    #[test]
    fn test_request_fn() {
        let msg = iomsg(0, size_of::<VirtioSoundPcmStatus>() as u32);
        let message = Arc::new(msg);
        let direction = Direction::Input;
        let request = Request::new(0, message, direction);

        assert_eq!(request.len() as usize, request.pos);
        assert_eq!(request.len(), 0);
        assert_eq!(request.direction, Direction::Input);

        // Test debug format representation for Request
        let mut debug_output = String::new();

        // Format the Debug representation into the String.
        write!(&mut debug_output, "{:?}", request).unwrap();

        let expected_debug = format!(
            "Request {{ pos: {}, len: {}, direction: {:?}, message: {:?} }}",
            request.len,
            request.pos,
            request.direction,
            Arc::as_ptr(&request.message)
        );

        assert_eq!(debug_output, expected_debug);
    }
}
