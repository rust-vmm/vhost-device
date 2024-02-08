/// Alsa backend
//
// Manos Pitsidianakis <manos.pitsidianakis@linaro.org>
// SPDX-License-Identifier: Apache-2.0 or BSD-3-Clause
use std::{
    convert::{TryFrom, TryInto},
    sync::mpsc::{channel, Receiver, Sender},
    sync::{Arc, Mutex, RwLock},
    thread,
    thread::sleep,
    time::Duration,
};

use alsa::{
    pcm::{Access, Format, HwParams, State, PCM},
    PollDescriptors, ValueOr,
};

use super::AudioBackend;
use crate::{
    stream::{PCMState, Stream},
    virtio_sound::{self, VirtioSndPcmSetParams},
    Direction, Error, Result as CrateResult,
};

impl From<Direction> for alsa::Direction {
    fn from(val: Direction) -> Self {
        match val {
            Direction::Output => Self::Playback,
            Direction::Input => Self::Capture,
        }
    }
}

type AResult<T> = std::result::Result<T, alsa::Error>;

#[derive(Clone)]
pub struct AlsaBackend {
    senders: Vec<Sender<bool>>,
    streams: Arc<RwLock<Vec<Stream>>>,
    pcms: Vec<Arc<Mutex<PCM>>>,
}

impl std::fmt::Debug for AlsaBackend {
    fn fmt(&self, fmt: &mut std::fmt::Formatter) -> std::fmt::Result {
        fmt.debug_struct(stringify!(AlsaBackend))
            .field("senders_no", &self.senders.len())
            .field("pcm_no", &self.pcms.len())
            .finish_non_exhaustive()
    }
}

fn update_pcm(
    pcm_: &Arc<Mutex<PCM>>,
    stream_id: usize,
    streams: &RwLock<Vec<Stream>>,
) -> AResult<()> {
    *pcm_.lock().unwrap() = {
        let streams = streams.read().unwrap();
        let s = &streams[stream_id];
        let pcm = PCM::new("default", s.direction.into(), false)?;

        {
            let rate = match s.params.rate {
                virtio_sound::VIRTIO_SND_PCM_RATE_5512 => 5512,
                virtio_sound::VIRTIO_SND_PCM_RATE_8000 => 8000,
                virtio_sound::VIRTIO_SND_PCM_RATE_11025 => 11025,
                virtio_sound::VIRTIO_SND_PCM_RATE_16000 => 16000,
                virtio_sound::VIRTIO_SND_PCM_RATE_22050 => 22050,
                virtio_sound::VIRTIO_SND_PCM_RATE_32000 => 32000,
                virtio_sound::VIRTIO_SND_PCM_RATE_44100 => 44100,
                virtio_sound::VIRTIO_SND_PCM_RATE_48000 => 48000,
                virtio_sound::VIRTIO_SND_PCM_RATE_64000 => 64000,
                virtio_sound::VIRTIO_SND_PCM_RATE_88200 => 88200,
                virtio_sound::VIRTIO_SND_PCM_RATE_96000 => 96000,
                virtio_sound::VIRTIO_SND_PCM_RATE_176400 => 176400,
                virtio_sound::VIRTIO_SND_PCM_RATE_192000 => 192000,
                virtio_sound::VIRTIO_SND_PCM_RATE_384000 => 384000,
                // We check if a rate value is supported in PCM_SET_PARAMS so it should never have
                // an unknown value.
                _ => unreachable!(),
            };
            let hwp = HwParams::any(&pcm)?;
            hwp.set_channels(s.params.channels.into())?;
            hwp.set_rate(rate, ValueOr::Nearest)?;
            hwp.set_rate_resample(false)?;
            hwp.set_format(match s.params.format {
                virtio_sound::VIRTIO_SND_PCM_FMT_IMA_ADPCM => Format::ImaAdPCM,
                virtio_sound::VIRTIO_SND_PCM_FMT_MU_LAW => Format::MuLaw,
                virtio_sound::VIRTIO_SND_PCM_FMT_A_LAW => Format::ALaw,
                virtio_sound::VIRTIO_SND_PCM_FMT_S8 => Format::S8,
                virtio_sound::VIRTIO_SND_PCM_FMT_U8 => Format::U8,
                virtio_sound::VIRTIO_SND_PCM_FMT_S16 => Format::s16(),
                virtio_sound::VIRTIO_SND_PCM_FMT_U16 => Format::r#u16(),
                virtio_sound::VIRTIO_SND_PCM_FMT_S18_3 => Format::S183LE,
                virtio_sound::VIRTIO_SND_PCM_FMT_U18_3 => Format::U183LE,
                virtio_sound::VIRTIO_SND_PCM_FMT_S20_3 => Format::S203LE,
                virtio_sound::VIRTIO_SND_PCM_FMT_U20_3 => Format::U203LE,
                virtio_sound::VIRTIO_SND_PCM_FMT_S24_3 => Format::S24LE,
                virtio_sound::VIRTIO_SND_PCM_FMT_U24_3 => Format::U24LE,
                virtio_sound::VIRTIO_SND_PCM_FMT_S20 => Format::s20_3(),
                virtio_sound::VIRTIO_SND_PCM_FMT_U20 => Format::u20_3(),
                virtio_sound::VIRTIO_SND_PCM_FMT_S24 => Format::s24(),
                virtio_sound::VIRTIO_SND_PCM_FMT_U24 => Format::u24(),
                virtio_sound::VIRTIO_SND_PCM_FMT_S32 => Format::s32(),
                virtio_sound::VIRTIO_SND_PCM_FMT_U32 => Format::r#u32(),
                virtio_sound::VIRTIO_SND_PCM_FMT_FLOAT => Format::float(),
                virtio_sound::VIRTIO_SND_PCM_FMT_FLOAT64 => Format::float64(),
                virtio_sound::VIRTIO_SND_PCM_FMT_DSD_U8 => Format::DSDU8,
                virtio_sound::VIRTIO_SND_PCM_FMT_DSD_U16 => Format::DSDU16LE,
                virtio_sound::VIRTIO_SND_PCM_FMT_DSD_U32 => Format::DSDU32LE,
                virtio_sound::VIRTIO_SND_PCM_FMT_IEC958_SUBFRAME => Format::iec958_subframe(),
                // We check if a format value is supported in PCM_SET_PARAMS so it should never have
                // an unknown value.
                _ => unreachable!(),
            })?;

            hwp.set_access(Access::RWInterleaved)?;

            let frame_size = u32::from(s.params.channels)
                * match s.params.format {
                    virtio_sound::VIRTIO_SND_PCM_FMT_A_LAW
                    | virtio_sound::VIRTIO_SND_PCM_FMT_S8
                    | virtio_sound::VIRTIO_SND_PCM_FMT_U8
                    | virtio_sound::VIRTIO_SND_PCM_FMT_DSD_U8
                    | virtio_sound::VIRTIO_SND_PCM_FMT_MU_LAW => 1,
                    virtio_sound::VIRTIO_SND_PCM_FMT_S16
                    | virtio_sound::VIRTIO_SND_PCM_FMT_U16
                    | virtio_sound::VIRTIO_SND_PCM_FMT_DSD_U16
                    | virtio_sound::VIRTIO_SND_PCM_FMT_IMA_ADPCM => 2,
                    virtio_sound::VIRTIO_SND_PCM_FMT_S18_3
                    | virtio_sound::VIRTIO_SND_PCM_FMT_U18_3
                    | virtio_sound::VIRTIO_SND_PCM_FMT_S20_3
                    | virtio_sound::VIRTIO_SND_PCM_FMT_U20_3
                    | virtio_sound::VIRTIO_SND_PCM_FMT_S24_3
                    | virtio_sound::VIRTIO_SND_PCM_FMT_U24_3
                    | virtio_sound::VIRTIO_SND_PCM_FMT_S24
                    | virtio_sound::VIRTIO_SND_PCM_FMT_U24 => 3,
                    virtio_sound::VIRTIO_SND_PCM_FMT_S20
                    | virtio_sound::VIRTIO_SND_PCM_FMT_U20
                    | virtio_sound::VIRTIO_SND_PCM_FMT_S32
                    | virtio_sound::VIRTIO_SND_PCM_FMT_U32
                    | virtio_sound::VIRTIO_SND_PCM_FMT_FLOAT
                    | virtio_sound::VIRTIO_SND_PCM_FMT_DSD_U32
                    | virtio_sound::VIRTIO_SND_PCM_FMT_IEC958_SUBFRAME => 4,
                    virtio_sound::VIRTIO_SND_PCM_FMT_FLOAT64 => 8,
                    // We check if a format value is supported in PCM_SET_PARAMS so it should never
                    // have an unknown value.
                    _ => unreachable!(),
                };

            // Calculate desirable bytes/sec rate to achieve the stream's desired
            // parameters:

            let bps_rate = frame_size * rate;

            // Calculate period size for ~100ms (arbitrary) interrupt period:

            let period_bytes = bps_rate / 10;

            // Finally, calculate the size of a period (in frames):

            let period_frames = period_bytes / frame_size;

            hwp.set_period_size(i64::from(period_frames), alsa::ValueOr::Less)?;

            // Online ALSA driver recommendations seem to be that the buffer should be at
            // least 2 * period_size.
            //
            // https://www.alsa-project.org/wiki/FramesPeriods says:
            //
            // > It seems (writing-an-alsa-driver.pdf), however, that it is the ALSA runtime that
            // > decides on the actual buffer_size and period_size, depending on: the requested
            // > number of channels, and their respective properties (rate and sampling resolution) -
            // > as well as the parameters set in the snd_pcm_hardware structure (in the driver).
            //
            // So, if the operation fails let's assume the ALSA runtime has set a better value.
            if let Err(err) = hwp.set_buffer_size_near(2 * i64::from(period_frames)) {
                log::error!("could not set buffer size {}: {}", 2 * period_frames, err);
            }

            // Read more at https://www.alsa-project.org/wiki/FramesPeriods.

            pcm.hw_params(&hwp)?;
        }
        pcm
    };
    Ok(())
}

// Returns `Ok(true)` if the function should be called again, because there are
// are more data left to write.
fn write_samples_direct(
    pcm: &alsa::PCM,
    stream: &mut Stream,
    mmap: &mut alsa::direct::pcm::MmapPlayback<u8>,
) -> AResult<bool> {
    while mmap.avail() > 0 {
        let Some(request) = stream.requests.front_mut() else {
            return Ok(false);
        };
        if !matches!(stream.state, PCMState::Start) {
            return Ok(false);
        }
        let n_bytes = request.len() - request.pos;
        let mut buf = vec![0; n_bytes];
        let read_bytes = match request.read_output(&mut buf) {
            Err(err) => {
                log::error!(
                    "Could not read TX request from guest, dropping it immediately: {}",
                    err
                );
                stream.requests.pop_front();
                continue;
            }
            Ok(v) => v,
        };
        // Write samples to DMA area from iterator
        let mut iter = buf[0..read_bytes as usize].iter().cloned();
        let frames = mmap.write(&mut iter);
        let written_bytes = pcm.frames_to_bytes(frames);
        if let Ok(written_bytes) = usize::try_from(written_bytes) {
            request.pos += written_bytes;
        }
        if request.pos >= request.len() {
            stream.requests.pop_front();
        }
    }
    match mmap.status().state() {
        State::Suspended | State::Running | State::Prepared => Ok(false),
        State::XRun => Ok(true), // Recover from this in next round
        n => panic!("Unexpected pcm state {:?}", n),
    }
}

// Returns `Ok(true)` if the function should be called again, because there are
// are more data left to read.
fn read_samples_direct(
    _pcm: &alsa::PCM,
    stream: &mut Stream,
    mmap: &mut alsa::direct::pcm::MmapCapture<u8>,
) -> AResult<bool> {
    while mmap.avail() > 0 {
        let Some(request) = stream.requests.front_mut() else {
            return Ok(false);
        };

        // Read samples from DMA area with an iterator
        let mut iter = mmap.iter();

        let mut n_bytes = 0;
        // We can't access the descriptor memory region as a slice (see
        // [`vm_memory::volatile_memory::VolatileSlice`]) and we can't use alsa's readi
        // without a slice: use an intermediate buffer and copy it to the
        // descriptor.
        let mut intermediate_buf = vec![0; request.len() - request.pos];
        for (sample, byte) in intermediate_buf.iter_mut().zip(&mut iter) {
            *sample = byte;
            n_bytes += 1;
        }
        if request
            .write_input(&intermediate_buf[0..n_bytes])
            .expect("Could not write data to guest memory")
            == 0
        {
            break;
        }

        drop(iter);
        if request.pos >= request.len() || mmap.avail() == 0 {
            stream.requests.pop_front();
        }
    }

    match mmap.status().state() {
        State::Suspended | State::Running | State::Prepared => Ok(false),
        State::XRun => Ok(true), // Recover from this in next round
        n => panic!("Unexpected pcm state {:?}", n),
    }
}

// Returns `Ok(true)` if the function should be called again, because there are
// are more data left to write.
fn write_samples_io(
    p: &alsa::PCM,
    streams: &Arc<RwLock<Vec<Stream>>>,
    stream_id: usize,
    io: &alsa::pcm::IO<u8>,
) -> AResult<bool> {
    let avail = match p.avail_update() {
        Ok(n) => n,
        Err(err) => {
            log::trace!("Recovering from {}", err);
            p.recover(err.errno() as std::os::raw::c_int, true)?;
            if let Err(err) = p.start() {
                log::error!(
                    "Could not restart stream {}; ALSA returned: {}",
                    stream_id,
                    err
                );
                return Err(err);
            }
            p.avail_update()?
        }
    };
    if avail != 0 {
        io.mmap(avail as usize, |buf| {
            let stream = &mut streams.write().unwrap()[stream_id];
            let Some(request) = stream.requests.front_mut() else {
                return 0;
            };
            if !matches!(stream.state, PCMState::Start) {
                stream.requests.pop_front();
                return 0;
            }

            let n_bytes = std::cmp::min(buf.len(), request.len() - request.pos);
            // read_output() always reads (request.len() - request.pos) bytes
            let read_bytes = match request.read_output(&mut buf[0..n_bytes]) {
                Ok(v) => v,
                Err(err) => {
                    log::error!(
                        "Could not read TX request, dropping it immediately: {}",
                        err
                    );
                    stream.requests.pop_front();
                    return 0;
                }
            };

            request.pos += read_bytes as usize;
            if request.pos >= request.len() {
                stream.requests.pop_front();
            }
            p.bytes_to_frames(isize::try_from(read_bytes).unwrap())
                .try_into()
                .unwrap_or_default()
        })?;
    } else {
        return Ok(false);
    }

    match p.state() {
        State::Suspended | State::Running | State::Prepared => Ok(false),
        State::XRun => Ok(true), // Recover from this in next round
        n => panic!("Unexpected pcm state {:?}", n),
    }
}

// Returns `Ok(true)` if the function should be called again, because there are
// are more data left to read.
fn read_samples_io(
    p: &alsa::PCM,
    streams: &Arc<RwLock<Vec<Stream>>>,
    stream_id: usize,
    io: &alsa::pcm::IO<u8>,
) -> AResult<bool> {
    let avail = match p.avail_update() {
        Ok(n) => n,
        Err(err) => {
            log::trace!("Recovering from {}", err);
            p.recover(err.errno() as std::os::raw::c_int, true)?;
            if let Err(err) = p.start() {
                log::error!(
                    "Could not restart stream {}; ALSA returned: {}",
                    stream_id,
                    err
                );
                return Err(err);
            }
            p.avail_update()?
        }
    };
    if avail == 0 {
        return Ok(false);
    }
    let stream = &mut streams.write().unwrap()[stream_id];
    let Some(request) = stream.requests.front_mut() else {
        return Ok(false);
    };
    if !matches!(stream.state, PCMState::Start) {
        stream.requests.pop_front();
        return Ok(false);
    }
    let mut frames_read = 0;

    // We can't access the descriptor memory region as a slice (see
    // [`vm_memory::volatile_memory::VolatileSlice`]) and we can't use alsa's readi
    // without a slice: use an intermediate buffer and copy it to the
    // descriptor.
    let mut intermediate_buf = vec![0; request.len() - request.pos];
    while let Some(frames) = io
        .readi(&mut intermediate_buf[0..(request.len() - request.pos)])
        .map(std::num::NonZeroUsize::new)?
        .map(std::num::NonZeroUsize::get)
    {
        frames_read += frames;
        let n_bytes =
            usize::try_from(p.frames_to_bytes(frames.try_into().unwrap())).unwrap_or_default();
        if request
            .write_input(&intermediate_buf[0..n_bytes])
            .expect("Could not write data to guest memory")
            == 0
        {
            break;
        }
    }

    let bytes_read = p.frames_to_bytes(frames_read.try_into().unwrap());
    if request.pos >= request.len() || bytes_read == 0 {
        stream.requests.pop_front();
    }

    match p.state() {
        State::Suspended | State::Running | State::Prepared => Ok(false),
        State::XRun => Ok(true), // Recover from this in next round
        n => panic!("Unexpected pcm state {:?}", n),
    }
}

fn alsa_worker(
    pcm: Arc<Mutex<PCM>>,
    streams: Arc<RwLock<Vec<Stream>>>,
    receiver: &Receiver<bool>,
    stream_id: usize,
) -> AResult<()> {
    let direction = streams.write().unwrap()[stream_id].direction;
    loop {
        // We get a `true` every time a new I/O message is received from the guest.
        // If the recv() returns `Ok(false)` or an error, terminate this worker thread.
        let Ok(do_work) = receiver.recv() else {
            return Ok(());
        };
        if do_work {
            let has_buffers = || -> bool {
                // Hold `streams` lock as short as possible.
                let lck = streams.read().unwrap();
                !lck[stream_id].requests.is_empty()
                    && matches!(lck[stream_id].state, PCMState::Start)
            };
            // Run this loop till the stream's buffer vector is empty:
            'empty_buffers: while has_buffers() {
                // When we return from a read/write attempt and there is still space in the
                // stream's buffers, get the ALSA file descriptors and poll them till the host
                // sound device tells us there is more available data.
                let mut fds = {
                    let lck = pcm.lock().unwrap();
                    match direction {
                        Direction::Output => {
                            let mut mmap = lck.direct_mmap_playback::<u8>().ok();

                            if let Some(ref mut mmap) = mmap {
                                if write_samples_direct(
                                    &lck,
                                    &mut streams.write().unwrap()[stream_id],
                                    mmap,
                                )? {
                                    continue 'empty_buffers;
                                }
                            } else {
                                let io = lck.io_bytes();
                                // Direct mode unavailable, use alsa-lib's mmap emulation instead
                                if write_samples_io(&lck, &streams, stream_id, &io)? {
                                    continue 'empty_buffers;
                                }
                            }
                        }
                        Direction::Input => {
                            let mut mmap = lck.direct_mmap_capture::<u8>().ok();

                            if let Some(ref mut mmap) = mmap {
                                if read_samples_direct(
                                    &lck,
                                    &mut streams.write().unwrap()[stream_id],
                                    mmap,
                                )? {
                                    continue 'empty_buffers;
                                }
                            } else {
                                let io = lck.io_bytes();
                                if read_samples_io(&lck, &streams, stream_id, &io)? {
                                    continue 'empty_buffers;
                                }
                            }
                        }
                    }
                    lck.get()?
                };
                alsa::poll::poll(&mut fds, 100)?;
            }
        }
    }
}

impl AlsaBackend {
    pub fn new(streams: Arc<RwLock<Vec<Stream>>>) -> Self {
        let streams_no = streams.read().unwrap().len();

        let mut vec = Vec::with_capacity(streams_no);
        let mut senders = Vec::with_capacity(streams_no);

        for i in 0..streams_no {
            let (sender, receiver) = channel();
            // Initialize with a dummy value, which will be updated every time we call
            // `update_pcm`.
            let pcm = Arc::new(Mutex::new(
                PCM::new("default", Direction::Output.into(), false).unwrap(),
            ));

            let mtx = Arc::clone(&pcm);
            let streams = Arc::clone(&streams);
            // create worker
            thread::spawn(move || {
                while let Err(err) = alsa_worker(mtx.clone(), streams.clone(), &receiver, i) {
                    log::error!(
                        "Worker thread exited with error: {}, sleeping for 500ms",
                        err
                    );
                    sleep(Duration::from_millis(500));
                }
            });

            vec.push(pcm);
            senders.push(sender);
        }

        for (i, pcm) in vec.iter_mut().enumerate() {
            update_pcm(pcm, i, &streams).unwrap();
        }

        Self {
            senders,
            streams,
            pcms: vec,
        }
    }
}

impl AudioBackend for AlsaBackend {
    fn read(&self, stream_id: u32) -> CrateResult<()> {
        if stream_id >= self.streams.read().unwrap().len() as u32 {
            log::error!(
                "Received DoWork action for stream id {} but there are only {} PCM streams.",
                stream_id,
                self.streams.read().unwrap().len()
            );
            return Err(Error::StreamWithIdNotFound(stream_id));
        }
        if matches!(
            self.streams.read().unwrap()[stream_id as usize].state,
            PCMState::Start | PCMState::Prepare
        ) {
            self.senders[stream_id as usize].send(true).unwrap();
        } else {
            return Err(Error::Stream(crate::stream::Error::InvalidState(
                "read",
                self.streams.read().unwrap()[stream_id as usize].state,
            )));
        }
        Ok(())
    }

    fn write(&self, stream_id: u32) -> CrateResult<()> {
        if stream_id >= self.streams.read().unwrap().len() as u32 {
            log::error!(
                "Received DoWork action for stream id {} but there are only {} PCM streams.",
                stream_id,
                self.streams.read().unwrap().len()
            );
            return Err(Error::StreamWithIdNotFound(stream_id));
        }
        if matches!(
            self.streams.read().unwrap()[stream_id as usize].state,
            PCMState::Start | PCMState::Prepare
        ) {
            self.senders[stream_id as usize].send(true).unwrap();
        } else {
            return Err(Error::Stream(crate::stream::Error::InvalidState(
                "write",
                self.streams.read().unwrap()[stream_id as usize].state,
            )));
        }
        Ok(())
    }

    fn start(&self, stream_id: u32) -> CrateResult<()> {
        if stream_id >= self.streams.read().unwrap().len() as u32 {
            log::error!(
                "Received Start action for stream id {} but there are only {} PCM streams.",
                stream_id,
                self.streams.read().unwrap().len()
            );
            return Err(Error::StreamWithIdNotFound(stream_id));
        }
        if let Err(err) = self.streams.write().unwrap()[stream_id as usize]
            .state
            .start()
        {
            return Err(Error::Stream(err));
        }
        let pcm = &self.pcms[stream_id as usize];
        let lck = pcm.lock().unwrap();
        if !matches!(lck.state(), State::Running) {
            // Fail gracefully if Start does not succeed.
            if let Err(err) = lck.start() {
                log::error!(
                    "Could not start stream {}; ALSA returned: {}",
                    stream_id,
                    err
                );
                return Err(Error::UnexpectedAudioBackendError(err.to_string()));
            }
        }
        self.senders[stream_id as usize].send(true).unwrap();
        Ok(())
    }

    fn prepare(&self, stream_id: u32) -> CrateResult<()> {
        if stream_id >= self.streams.read().unwrap().len() as u32 {
            log::error!(
                "Received Prepare action for stream id {} but there are only {} PCM streams.",
                stream_id,
                self.streams.read().unwrap().len() as u32
            );
            return Err(Error::StreamWithIdNotFound(stream_id));
        }
        if let Err(err) = self.streams.write().unwrap()[stream_id as usize]
            .state
            .prepare()
        {
            log::error!("Stream {}: {}", stream_id, err);
            return Err(Error::Stream(err));
        }
        let pcm = &self.pcms[stream_id as usize];
        let lck = pcm.lock().unwrap();
        if !matches!(lck.state(), State::Running) {
            // Fail gracefully if Prepare does not succeed.
            if let Err(err) = lck.prepare() {
                log::error!(
                    "Could not prepare stream {}; ALSA returned: {}",
                    stream_id,
                    err
                );
                return Err(Error::UnexpectedAudioBackendError(err.to_string()));
            }
        }
        Ok(())
    }

    fn stop(&self, id: u32) -> CrateResult<()> {
        if let Err(err) = self
            .streams
            .write()
            .unwrap()
            .get_mut(id as usize)
            .ok_or_else(|| Error::StreamWithIdNotFound(id))?
            .state
            .stop()
        {
            log::error!("Stream {} stop {}", id, err);
        }
        Ok(())
    }

    fn set_parameters(&self, stream_id: u32, request: VirtioSndPcmSetParams) -> CrateResult<()> {
        if stream_id >= self.streams.read().unwrap().len() as u32 {
            log::error!(
                "Received SetParameters action for stream id {} but there are only {} PCM streams.",
                stream_id,
                self.streams.read().unwrap().len() as u32
            );
            return Err(Error::StreamWithIdNotFound(stream_id));
        }
        {
            let mut streams = self.streams.write().unwrap();
            let st = &mut streams[stream_id as usize];
            if let Err(err) = st.state.set_parameters() {
                log::error!("Stream {} set_parameters {}", stream_id, err);
                return Err(Error::Stream(err));
            } else if !st.supports_format(request.format) || !st.supports_rate(request.rate) {
                return Err(Error::UnexpectedAudioBackendConfiguration);
            } else {
                st.params.buffer_bytes = request.buffer_bytes;
                st.params.period_bytes = request.period_bytes;
                st.params.features = request.features;
                st.params.channels = request.channels;
                st.params.format = request.format;
                st.params.rate = request.rate;
            }
        }
        update_pcm(
            &self.pcms[stream_id as usize],
            stream_id as usize,
            &self.streams,
        )
        .unwrap();
        Ok(())
    }

    fn release(&self, stream_id: u32) -> CrateResult<()> {
        if stream_id >= self.streams.read().unwrap().len() as u32 {
            log::error!(
                "Received Release action for stream id {} but there are only {} PCM streams.",
                stream_id,
                self.streams.read().unwrap().len() as u32
            );
            return Err(Error::StreamWithIdNotFound(stream_id));
        }
        let mut streams = self.streams.write().unwrap();
        if let Err(err) = streams[stream_id as usize].state.release() {
            log::error!("Stream {}: {}", stream_id, err);
            return Err(Error::Stream(err));
        }
        // Stop worker thread
        self.senders[stream_id as usize].send(false).unwrap();
        // Drop pending stream requests to complete pending I/O messages
        //
        // This will release requests even if state transition is invalid. If it is
        // invalid, we won't be in a valid device state anyway so better to get rid of
        // them and free the virt queue.
        std::mem::take(&mut streams[stream_id as usize].requests);
        Ok(())
    }

    #[cfg(test)]
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}

#[cfg(test)]
/// Utilities for temporarily setting a test-specific alsa config.
pub mod test_utils;

#[cfg(test)]
mod tests {
    use super::{test_utils::setup_alsa_conf, *};
    use crate::{stream::PcmParams, virtio_sound::*};

    const RATES: [u8; _VIRTIO_SND_PCM_RATE_MAX as usize] = [
        virtio_sound::VIRTIO_SND_PCM_RATE_5512,
        virtio_sound::VIRTIO_SND_PCM_RATE_8000,
        virtio_sound::VIRTIO_SND_PCM_RATE_11025,
        virtio_sound::VIRTIO_SND_PCM_RATE_16000,
        virtio_sound::VIRTIO_SND_PCM_RATE_22050,
        virtio_sound::VIRTIO_SND_PCM_RATE_32000,
        virtio_sound::VIRTIO_SND_PCM_RATE_44100,
        virtio_sound::VIRTIO_SND_PCM_RATE_48000,
        virtio_sound::VIRTIO_SND_PCM_RATE_64000,
        virtio_sound::VIRTIO_SND_PCM_RATE_88200,
        virtio_sound::VIRTIO_SND_PCM_RATE_96000,
        virtio_sound::VIRTIO_SND_PCM_RATE_176400,
        virtio_sound::VIRTIO_SND_PCM_RATE_192000,
        virtio_sound::VIRTIO_SND_PCM_RATE_384000,
    ];

    const FORMATS: [u8; _VIRTIO_SND_PCM_FMT_MAX as usize] = [
        virtio_sound::VIRTIO_SND_PCM_FMT_IMA_ADPCM,
        virtio_sound::VIRTIO_SND_PCM_FMT_MU_LAW,
        virtio_sound::VIRTIO_SND_PCM_FMT_A_LAW,
        virtio_sound::VIRTIO_SND_PCM_FMT_S8,
        virtio_sound::VIRTIO_SND_PCM_FMT_U8,
        virtio_sound::VIRTIO_SND_PCM_FMT_S16,
        virtio_sound::VIRTIO_SND_PCM_FMT_U16,
        virtio_sound::VIRTIO_SND_PCM_FMT_S18_3,
        virtio_sound::VIRTIO_SND_PCM_FMT_U18_3,
        virtio_sound::VIRTIO_SND_PCM_FMT_S20_3,
        virtio_sound::VIRTIO_SND_PCM_FMT_U20_3,
        virtio_sound::VIRTIO_SND_PCM_FMT_S24_3,
        virtio_sound::VIRTIO_SND_PCM_FMT_U24_3,
        virtio_sound::VIRTIO_SND_PCM_FMT_S20,
        virtio_sound::VIRTIO_SND_PCM_FMT_U20,
        virtio_sound::VIRTIO_SND_PCM_FMT_S24,
        virtio_sound::VIRTIO_SND_PCM_FMT_U24,
        virtio_sound::VIRTIO_SND_PCM_FMT_S32,
        virtio_sound::VIRTIO_SND_PCM_FMT_U32,
        virtio_sound::VIRTIO_SND_PCM_FMT_FLOAT,
        virtio_sound::VIRTIO_SND_PCM_FMT_FLOAT64,
        virtio_sound::VIRTIO_SND_PCM_FMT_DSD_U8,
        virtio_sound::VIRTIO_SND_PCM_FMT_DSD_U16,
        virtio_sound::VIRTIO_SND_PCM_FMT_DSD_U32,
        virtio_sound::VIRTIO_SND_PCM_FMT_IEC958_SUBFRAME,
    ];

    #[test]
    fn test_alsa_trait_impls() {
        crate::init_logger();
        let _harness = setup_alsa_conf();

        let _: alsa::Direction = Direction::Output.into();
        let _: alsa::Direction = Direction::Input.into();

        let backend = AlsaBackend::new(Default::default());
        #[allow(clippy::redundant_clone)]
        let _ = backend.clone();

        _ = format!("{:?}", backend);
    }

    #[test]
    fn test_alsa_ops() {
        crate::init_logger();
        let _harness = setup_alsa_conf();

        let streams = Arc::new(RwLock::new(vec![
            Stream::default(),
            Stream {
                id: 1,
                direction: Direction::Input,
                ..Stream::default()
            },
        ]));
        let backend = AlsaBackend::new(streams);
        let request = VirtioSndPcmSetParams {
            hdr: VirtioSoundPcmHeader {
                stream_id: 0.into(),
            },
            format: VIRTIO_SND_PCM_FMT_S16,
            rate: VIRTIO_SND_PCM_RATE_44100,
            channels: 2,
            features: 0.into(),
            buffer_bytes: 8192.into(),
            period_bytes: 4096.into(),
            padding: 0,
        };
        backend.set_parameters(0, request).unwrap();
        backend.prepare(0).unwrap();
        backend.start(0).unwrap();
        backend.write(0).unwrap();
        backend.read(0).unwrap();
        backend.stop(0).unwrap();
        backend.release(0).unwrap();
    }

    #[test]
    fn test_alsa_invalid_stream_id() {
        crate::init_logger();
        let _harness = setup_alsa_conf();

        let streams = Arc::new(RwLock::new(vec![
            Stream::default(),
            Stream {
                id: 1,
                direction: Direction::Input,
                ..Stream::default()
            },
        ]));
        let backend = AlsaBackend::new(streams);
        let request = VirtioSndPcmSetParams {
            hdr: VirtioSoundPcmHeader {
                stream_id: 3.into(),
            },
            format: VIRTIO_SND_PCM_FMT_S16,
            rate: VIRTIO_SND_PCM_RATE_44100,
            channels: 2,
            features: 0.into(),
            buffer_bytes: 8192.into(),
            period_bytes: 4096.into(),
            padding: 0,
        };
        backend.set_parameters(3, request).unwrap_err();
        backend.prepare(3).unwrap_err();
        backend.start(3).unwrap_err();
        backend.write(3).unwrap_err();
        backend.read(3).unwrap_err();
        backend.stop(3).unwrap_err();
        backend.release(3).unwrap_err();
    }

    #[test]
    fn test_alsa_invalid_state_transitions() {
        crate::init_logger();
        let _harness = setup_alsa_conf();

        let streams = Arc::new(RwLock::new(vec![
            Stream::default(),
            Stream {
                id: 1,
                direction: Direction::Input,
                ..Stream::default()
            },
        ]));
        let request = VirtioSndPcmSetParams {
            hdr: VirtioSoundPcmHeader {
                stream_id: 3.into(),
            },
            format: VIRTIO_SND_PCM_FMT_S16,
            rate: VIRTIO_SND_PCM_RATE_44100,
            channels: 2,
            features: 0.into(),
            buffer_bytes: 8192.into(),
            period_bytes: 4096.into(),
            padding: 0,
        };
        {
            let backend = AlsaBackend::new(streams.clone());

            // Invalid, but we allow it.
            backend.stop(0).unwrap();
            // Invalid, but we don't allow it.
            backend.release(0).unwrap_err();
            backend.start(0).unwrap_err();
            backend.release(0).unwrap_err();
        }
        {
            let backend = AlsaBackend::new(streams.clone());

            // set_parameters -> set_parameters | VALID
            backend.set_parameters(0, request).unwrap();

            // set_parameters -> prepare | VALID
            backend.prepare(0).unwrap();

            // Invalid, but we allow it.
            // prepare -> stop | INVALID
            backend.stop(0).unwrap();
            // prepare -> release | VALID
            backend.release(0).unwrap();

            // release -> start | INVALID
            backend.start(0).unwrap_err();
            // release -> stop | VALID
            backend.stop(0).unwrap();
            // release -> prepare | VALID
            backend.prepare(0).unwrap();

            // prepare -> start | VALID
            backend.start(0).unwrap();

            // start -> start | INVALID
            backend.start(0).unwrap_err();
            // start -> set_parameters | INVALID
            backend.set_parameters(0, request).unwrap_err();
            // start -> prepare | INVALID
            backend.prepare(0).unwrap_err();
            // start -> release | INVALID
            backend.release(0).unwrap_err();
            // start -> stop | VALID
            backend.stop(0).unwrap();
            // stop -> start | VALID
            backend.start(0).unwrap();
            // start -> stop | VALID
            backend.stop(0).unwrap();
            // stop -> prepare | INVALID
            backend.prepare(0).unwrap_err();
            // stop -> set_parameters | INVALID
            backend.set_parameters(0, request).unwrap_err();
            // stop -> release | VALID
            backend.release(0).unwrap();
        }

        // Redundant checks? Oh well.
        //
        // Generated with:
        //
        // ```python
        // import itertools
        // states = ["SetParameters", "Prepare", "Release", "Start", "Stop"]
        // combs = set(itertools.product(states, repeat=2))
        // ```
        {
            let backend = AlsaBackend::new(streams.clone());
            backend.set_parameters(0, request).unwrap();
            backend.prepare(0).unwrap();
        }
        {
            let backend = AlsaBackend::new(streams.clone());
            backend.prepare(0).unwrap();
            backend.stop(0).unwrap();
        }
        {
            let backend = AlsaBackend::new(streams.clone());
            backend.start(0).unwrap();
            backend.start(0).unwrap_err();
        }
        {
            let backend = AlsaBackend::new(streams.clone());
            backend.prepare(0).unwrap_err();
            backend.start(0).unwrap_err();
        }
        {
            let backend = AlsaBackend::new(streams.clone());
            backend.stop(0).unwrap();
            backend.release(0).unwrap();
        }
        {
            let backend = AlsaBackend::new(streams.clone());
            backend.stop(0).unwrap();
            backend.prepare(0).unwrap();
        }
        {
            let backend = AlsaBackend::new(streams.clone());
            backend.release(0).unwrap();
            backend.set_parameters(0, request).unwrap();
        }
        {
            let backend = AlsaBackend::new(streams.clone());
            backend.start(0).unwrap_err();
            backend.set_parameters(0, request).unwrap();
        }
        {
            let backend = AlsaBackend::new(streams.clone());
            backend.prepare(0).unwrap();
            backend.set_parameters(0, request).unwrap();
        }
        {
            let backend = AlsaBackend::new(streams.clone());
            backend.release(0).unwrap_err();
            backend.read(0).unwrap_err();
            backend.write(0).unwrap_err();
        }
        {
            let backend = AlsaBackend::new(streams.clone());
            backend.set_parameters(0, request).unwrap();
            backend.stop(0).unwrap();
        }
        {
            let backend = AlsaBackend::new(streams.clone());
            backend.release(0).unwrap_err();
            backend.prepare(0).unwrap();
        }
        {
            let backend = AlsaBackend::new(streams.clone());
            backend.set_parameters(0, request).unwrap();
            backend.start(0).unwrap_err();
        }
        {
            let backend = AlsaBackend::new(streams.clone());
            backend.start(0).unwrap_err();
            backend.release(0).unwrap_err();
        }
        {
            let backend = AlsaBackend::new(streams.clone());
            backend.prepare(0).unwrap();
            backend.release(0).unwrap();
        }
        {
            let backend = AlsaBackend::new(streams.clone());
            backend.start(0).unwrap_err();
            backend.prepare(0).unwrap();
        }
        {
            let backend = AlsaBackend::new(streams.clone());
            backend.stop(0).unwrap();
            backend.stop(0).unwrap();
        }
        {
            let backend = AlsaBackend::new(streams.clone());
            backend.prepare(0).unwrap();
            backend.prepare(0).unwrap();
        }
        {
            let backend = AlsaBackend::new(streams.clone());
            backend.stop(0).unwrap();
            backend.start(0).unwrap();
        }
        {
            let backend = AlsaBackend::new(streams.clone());
            backend.set_parameters(0, request).unwrap_err();
            backend.release(0).unwrap_err();
        }
        {
            let backend = AlsaBackend::new(streams.clone());
            backend.release(0).unwrap_err();
            backend.stop(0).unwrap();
        }
        {
            let backend = AlsaBackend::new(streams.clone());
            backend.stop(0).unwrap();
            backend.set_parameters(0, request).unwrap_err();
        }
        {
            let backend = AlsaBackend::new(streams.clone());
            backend.release(0).unwrap();
            backend.start(0).unwrap_err();
        }
        {
            let backend = AlsaBackend::new(streams);
            backend.start(0).unwrap_err();
            backend.stop(0).unwrap();
        }
    }

    #[test]
    fn test_alsa_worker() {
        crate::init_logger();
        let _harness = setup_alsa_conf();

        let streams = Arc::new(RwLock::new(vec![
            Stream::default(),
            Stream {
                id: 1,
                direction: Direction::Input,
                ..Stream::default()
            },
        ]));
        let (sender, receiver) = channel();
        let pcm = Arc::new(Mutex::new(
            PCM::new("null", Direction::Output.into(), false).unwrap(),
        ));

        let mtx = Arc::clone(&pcm);
        let streams = Arc::clone(&streams);
        let _handle =
            thread::spawn(move || alsa_worker(mtx.clone(), streams.clone(), &receiver, 0));
        sender.send(false).unwrap();
    }

    #[test]
    fn test_alsa_valid_parameters() {
        crate::init_logger();
        let _harness = setup_alsa_conf();

        let streams = Arc::new(RwLock::new(vec![
            Stream::default(),
            Stream {
                id: 1,
                direction: Direction::Input,
                ..Stream::default()
            },
        ]));
        let mut request = VirtioSndPcmSetParams {
            hdr: VirtioSoundPcmHeader {
                stream_id: 0.into(),
            },
            format: VIRTIO_SND_PCM_FMT_S16,
            rate: VIRTIO_SND_PCM_RATE_44100,
            channels: 2,
            features: 0.into(),
            buffer_bytes: 8192.into(),
            period_bytes: 4096.into(),
            padding: 0,
        };

        for rate in RATES
            .iter()
            .cloned()
            .filter(|rt| ((1 << *rt) & crate::SUPPORTED_RATES) > 0)
        {
            request.rate = rate;
            let backend = AlsaBackend::new(streams.clone());
            backend.set_parameters(0, request).unwrap();
        }

        for rate in RATES
            .iter()
            .cloned()
            .filter(|rt| ((1 << *rt) & crate::SUPPORTED_RATES) == 0)
        {
            request.rate = rate;
            let backend = AlsaBackend::new(streams.clone());
            backend.set_parameters(0, request).unwrap_err();
        }
        request.rate = VIRTIO_SND_PCM_RATE_44100;

        for format in FORMATS
            .iter()
            .cloned()
            .filter(|fmt| ((1 << *fmt) & crate::SUPPORTED_FORMATS) > 0)
        {
            request.format = format;
            let backend = AlsaBackend::new(streams.clone());
            backend.set_parameters(0, request).unwrap();
        }

        for format in FORMATS
            .iter()
            .cloned()
            .filter(|fmt| ((1 << *fmt) & crate::SUPPORTED_FORMATS) == 0)
        {
            request.format = format;
            let backend = AlsaBackend::new(streams.clone());
            backend.set_parameters(0, request).unwrap_err();
        }

        {
            for format in FORMATS
                .iter()
                .cloned()
                .filter(|fmt| ((1 << *fmt) & crate::SUPPORTED_FORMATS) > 0)
            {
                let streams = Arc::new(RwLock::new(vec![Stream {
                    params: PcmParams {
                        format,
                        ..PcmParams::default()
                    },
                    ..Stream::default()
                }]));
                let pcm = Arc::new(Mutex::new(
                    PCM::new("null", Direction::Output.into(), false).unwrap(),
                ));
                update_pcm(&pcm, 0, &streams).unwrap();
            }
        }
    }

    #[test]
    #[should_panic(expected = "unreachable")]
    fn test_alsa_invalid_rate() {
        crate::init_logger();
        let _harness = setup_alsa_conf();

        let streams = Arc::new(RwLock::new(vec![Stream {
            params: PcmParams {
                rate: _VIRTIO_SND_PCM_RATE_MAX,
                ..PcmParams::default()
            },
            ..Stream::default()
        }]));
        let pcm = Arc::new(Mutex::new(
            PCM::new("null", Direction::Output.into(), false).unwrap(),
        ));
        update_pcm(&pcm, 0, &streams).unwrap();
    }

    #[test]
    #[should_panic(expected = "unreachable")]
    fn test_alsa_invalid_fmt() {
        crate::init_logger();
        let _harness = setup_alsa_conf();

        let streams = Arc::new(RwLock::new(vec![Stream {
            params: PcmParams {
                format: _VIRTIO_SND_PCM_FMT_MAX,
                ..PcmParams::default()
            },
            ..Stream::default()
        }]));
        let pcm = Arc::new(Mutex::new(
            PCM::new("null", Direction::Output.into(), false).unwrap(),
        ));
        update_pcm(&pcm, 0, &streams).unwrap();
    }
}
