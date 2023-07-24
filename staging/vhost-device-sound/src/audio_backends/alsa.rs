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
use virtio_queue::Descriptor;
use vm_memory::Bytes;

use super::AudioBackend;
use crate::{
    device::ControlMessage,
    stream::{PCMState, Stream},
    virtio_sound::{self, VirtioSndPcmSetParams, VIRTIO_SND_S_BAD_MSG, VIRTIO_SND_S_NOT_SUPP},
    Direction, Result as CrateResult,
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

#[derive(Clone, Debug)]
pub struct AlsaBackend {
    sender: Arc<Mutex<Sender<AlsaAction>>>,
    streams: Arc<RwLock<Vec<Stream>>>,
}

#[derive(Debug)]
enum AlsaAction {
    SetParameters(usize, ControlMessage),
    Prepare(usize),
    Release(usize, ControlMessage),
    Start(usize),
    DoWork(usize),
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

            hwp.set_period_size(period_frames as i64, alsa::ValueOr::Less)?;

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
            if let Err(err) = hwp.set_buffer_size_near(2 * period_frames as i64) {
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
        let Some(buffer) = stream.buffers.front_mut() else {
            return Ok(false);
        };
        if !matches!(stream.state, PCMState::Start) {
            return Ok(false);
        }
        let n_bytes = buffer.desc_len() as usize - buffer.pos;
        let mut buf = vec![0; n_bytes];
        let read_bytes = match buffer.consume(&mut buf) {
            Err(err) => {
                log::error!(
                    "Could not read TX buffer from guest, dropping it immediately: {}",
                    err
                );
                stream.buffers.pop_front();
                continue;
            }
            Ok(v) => v,
        };
        // Write samples to DMA area from iterator
        let mut iter = buf[0..read_bytes as usize].iter().cloned();
        let frames = mmap.write(&mut iter);
        let written_bytes = pcm.frames_to_bytes(frames);
        if let Ok(written_bytes) = usize::try_from(written_bytes) {
            buffer.pos += written_bytes;
        }
        if buffer.pos >= buffer.desc_len() as usize {
            stream.buffers.pop_front();
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
        let Some(buffer) = stream.buffers.front_mut() else {
            return Ok(false);
        };

        // Read samples from DMA area with an iterator
        let mut iter = mmap.iter();

        let mut n_bytes = 0;
        // We can't access the descriptor memory region as a slice (see
        // [`vm_memory::volatile_memory::VolatileSlice`]) and we can't use alsa's readi
        // without a slice: use an intermediate buffer and copy it to the
        // descriptor.
        let mut intermediate_buf = vec![0; buffer.desc_len() as usize - buffer.pos];
        for (sample, byte) in intermediate_buf.iter_mut().zip(&mut iter) {
            *sample = byte;
            n_bytes += 1;
        }
        if buffer
            .write_input(&intermediate_buf[0..n_bytes])
            .expect("Could not write data to guest memory")
            == 0
        {
            break;
        }

        drop(iter);
        if buffer.pos as u32 >= buffer.desc_len() || mmap.avail() == 0 {
            stream.buffers.pop_front();
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
    io: &mut alsa::pcm::IO<u8>,
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
            let Some(buffer) = stream.buffers.front_mut() else {
                return 0;
            };
            if !matches!(stream.state, PCMState::Start) {
                stream.buffers.pop_front();
                return 0;
            }

            let n_bytes = std::cmp::min(buf.len(), buffer.desc_len() as usize - buffer.pos);
            // consume() always reads (buffer.desc_len() - buffer.pos) bytes
            let read_bytes = match buffer.consume(&mut buf[0..n_bytes]) {
                Ok(v) => v,
                Err(err) => {
                    log::error!("Could not read TX buffer, dropping it immediately: {}", err);
                    stream.buffers.pop_front();
                    return 0;
                }
            };

            buffer.pos += read_bytes as usize;
            if buffer.pos as u32 >= buffer.desc_len() {
                stream.buffers.pop_front();
            }
            p.bytes_to_frames(read_bytes as isize)
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
    io: &mut alsa::pcm::IO<u8>,
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
    let Some(buffer) = stream.buffers.front_mut() else {
        return Ok(false);
    };
    if !matches!(stream.state, PCMState::Start) {
        stream.buffers.pop_front();
        return Ok(false);
    }
    let mut frames_read = 0;

    // We can't access the descriptor memory region as a slice (see
    // [`vm_memory::volatile_memory::VolatileSlice`]) and we can't use alsa's readi
    // without a slice: use an intermediate buffer and copy it to the
    // descriptor.
    let mut intermediate_buf = vec![0; buffer.desc_len() as usize - buffer.pos];
    while let Some(frames) = io
        .readi(&mut intermediate_buf[0..(buffer.desc_len() as usize - buffer.pos)])
        .map(std::num::NonZeroUsize::new)?
        .map(std::num::NonZeroUsize::get)
    {
        frames_read += frames;
        let n_bytes = usize::try_from(p.frames_to_bytes(frames as i64)).unwrap_or_default();
        if buffer
            .write_input(&intermediate_buf[0..n_bytes])
            .expect("Could not write data to guest memory")
            == 0
        {
            break;
        }
    }

    let bytes_read = p.frames_to_bytes(frames_read as i64);
    if buffer.pos as u32 >= buffer.desc_len() || bytes_read == 0 {
        stream.buffers.pop_front();
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
                !lck[stream_id].buffers.is_empty()
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
                                let mut io = lck.io_bytes();
                                // Direct mode unavailable, use alsa-lib's mmap emulation instead
                                if write_samples_io(&lck, &streams, stream_id, &mut io)? {
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
                                let mut io = lck.io_bytes();
                                if read_samples_io(&lck, &streams, stream_id, &mut io)? {
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
        let (sender, receiver) = channel();
        let sender = Arc::new(Mutex::new(sender));
        let streams2 = Arc::clone(&streams);

        thread::spawn(move || {
            if let Err(err) = Self::run(streams2, receiver) {
                log::error!("Main thread exited with error: {}", err);
            }
        });

        Self { sender, streams }
    }

    fn run(
        streams: Arc<RwLock<Vec<Stream>>>,
        receiver: Receiver<AlsaAction>,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let streams_no: usize;

        let (mut pcms, senders) = {
            streams_no = streams.read().unwrap().len();
            let mut vec = Vec::with_capacity(streams_no);
            let mut senders = Vec::with_capacity(streams_no);
            for i in 0..streams_no {
                let (sender, receiver) = channel();

                // Initialize with a dummy value, which will be updated every time we call
                // `update_pcm`.
                let pcm = Arc::new(Mutex::new(PCM::new(
                    "default",
                    Direction::Output.into(),
                    false,
                )?));

                let mtx = Arc::clone(&pcm);
                let streams = Arc::clone(&streams);
                thread::spawn(move || {
                    // TODO: exponential backoff? send fatal error to daemon?
                    while let Err(err) = alsa_worker(mtx.clone(), streams.clone(), &receiver, i) {
                        log::error!(
                            "Worker thread exited with error: {}, sleeping for 500ms",
                            err
                        );
                        sleep(Duration::from_millis(500));
                    }
                });

                senders.push(sender);
                vec.push(pcm);
            }
            (vec, senders)
        };
        for (i, pcm) in pcms.iter_mut().enumerate() {
            update_pcm(pcm, i, &streams)?;
        }

        while let Ok(action) = receiver.recv() {
            match action {
                AlsaAction::DoWork(stream_id) => {
                    if stream_id >= streams_no {
                        log::error!(
                            "Received DoWork action for stream id {} but there are only {} PCM \
                             streams.",
                            stream_id,
                            pcms.len()
                        );
                        continue;
                    };
                    if matches!(
                        streams.write().unwrap()[stream_id].state,
                        PCMState::Start | PCMState::Prepare
                    ) {
                        senders[stream_id].send(true).unwrap();
                    }
                }
                AlsaAction::Start(stream_id) => {
                    if stream_id >= streams_no {
                        log::error!(
                            "Received Start action for stream id {} but there are only {} PCM \
                             streams.",
                            stream_id,
                            pcms.len()
                        );
                        continue;
                    };
                    if let Err(err) = streams.write().unwrap()[stream_id].state.start() {
                        log::error!("Stream {}: {}", stream_id, err);
                        continue;
                    }
                    let pcm = &pcms[stream_id];
                    let lck = pcm.lock().unwrap();
                    if !matches!(lck.state(), State::Running) {
                        // Fail gracefully if Start does not succeed.
                        if let Err(err) = lck.start() {
                            log::error!(
                                "Could not start stream {}; ALSA returned: {}",
                                stream_id,
                                err
                            );
                        }
                    }
                    senders[stream_id].send(true).unwrap();
                }
                AlsaAction::Prepare(stream_id) => {
                    if stream_id >= streams_no {
                        log::error!(
                            "Received Prepare action for stream id {} but there are only {} PCM \
                             streams.",
                            stream_id,
                            pcms.len()
                        );
                        continue;
                    };
                    if let Err(err) = streams.write().unwrap()[stream_id].state.prepare() {
                        log::error!("Stream {}: {}", stream_id, err);
                        continue;
                    }
                    let pcm = &pcms[stream_id];
                    let lck = pcm.lock().unwrap();
                    if !matches!(lck.state(), State::Running) {
                        // Fail gracefully if Prepare does not succeed.
                        if let Err(err) = lck.prepare() {
                            log::error!(
                                "Could not prepare stream {}; ALSA returned: {}",
                                stream_id,
                                err
                            );
                        }
                    }
                }
                AlsaAction::Release(stream_id, mut msg) => {
                    if stream_id >= streams_no {
                        log::error!(
                            "Received Release action for stream id {} but there are only {} PCM \
                             streams.",
                            stream_id,
                            pcms.len()
                        );
                        msg.code = VIRTIO_SND_S_BAD_MSG;
                        continue;
                    };
                    // Stop worker thread
                    senders[stream_id].send(false).unwrap();
                    let mut streams = streams.write().unwrap();
                    if let Err(err) = streams[stream_id].state.release() {
                        log::error!("Stream {}: {}", stream_id, err);
                        msg.code = VIRTIO_SND_S_BAD_MSG;
                    }
                    // Drop pending stream buffers to complete pending I/O messages
                    //
                    // This will release buffers even if state transition is invalid. If it is
                    // invalid, we won't be in a valid device state anyway so better to get rid of
                    // them and free the virt queue.
                    std::mem::take(&mut streams[stream_id].buffers);
                }
                AlsaAction::SetParameters(stream_id, mut msg) => {
                    if stream_id >= streams_no {
                        log::error!(
                            "Received SetParameters action for stream id {} but there are only {} \
                             PCM streams.",
                            stream_id,
                            pcms.len()
                        );
                        msg.code = VIRTIO_SND_S_BAD_MSG;
                        continue;
                    };
                    let descriptors: Vec<Descriptor> = msg.desc_chain.clone().collect();
                    let desc_request = &descriptors[0];
                    let request = msg
                        .desc_chain
                        .memory()
                        .read_obj::<VirtioSndPcmSetParams>(desc_request.addr())
                        .unwrap();
                    {
                        let mut streams = streams.write().unwrap();
                        let st = &mut streams[stream_id];
                        if let Err(err) = st.state.set_parameters() {
                            log::error!("Stream {} set_parameters {}", stream_id, err);
                            msg.code = VIRTIO_SND_S_BAD_MSG;
                            continue;
                        } else if !st.supports_format(request.format)
                            || !st.supports_rate(request.rate)
                        {
                            msg.code = VIRTIO_SND_S_NOT_SUPP;
                            continue;
                        } else {
                            st.params.buffer_bytes = request.buffer_bytes;
                            st.params.period_bytes = request.period_bytes;
                            st.params.features = request.features;
                            st.params.channels = request.channels;
                            st.params.format = request.format;
                            st.params.rate = request.rate;
                        }
                        // Manually drop msg for faster response: the kernel has a timeout.
                        drop(msg);
                    }
                    update_pcm(&pcms[stream_id], stream_id, &streams)?;
                }
            }
        }

        Ok(())
    }
}

macro_rules! send_action {
    ($($fn_name:ident $action:tt),+$(,)?) => {
        $(
            fn $fn_name(&self, id: u32) -> CrateResult<()> {
                self.sender
                    .lock()
                    .unwrap()
                    .send(AlsaAction::$action(id as usize))
                    .unwrap();
                Ok(())
            }
        )*
    };
    ($(ctrl $fn_name:ident $action:tt),+$(,)?) => {
        $(
            fn $fn_name(&self, id: u32, msg: ControlMessage) -> CrateResult<()> {
                self.sender
                    .lock()
                    .unwrap()
                    .send(AlsaAction::$action(id as usize, msg))
                    .unwrap();
                Ok(())
            }
        )*
    }
}

impl AudioBackend for AlsaBackend {
    send_action! {
        write DoWork,
        read DoWork,
        prepare Prepare,
        start Start,
    }

    fn stop(&self, id: u32) -> CrateResult<()> {
        if let Some(Err(err)) = self
            .streams
            .write()
            .unwrap()
            .get_mut(id as usize)
            .map(|s| s.state.stop())
        {
            log::error!("Stream {} stop {}", id, err);
        }
        Ok(())
    }

    send_action! {
        ctrl set_parameters SetParameters,
        ctrl release Release,
    }
}
