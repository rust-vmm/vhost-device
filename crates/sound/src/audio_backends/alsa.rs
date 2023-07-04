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
    Direction, PollDescriptors, ValueOr,
};
use virtio_queue::Descriptor;
use vm_memory::Bytes;

use super::AudioBackend;
use crate::{
    device::ControlMessage,
    stream::Stream,
    virtio_sound::{
        VirtioSndPcmSetParams, VIRTIO_SND_D_INPUT, VIRTIO_SND_D_OUTPUT, VIRTIO_SND_S_BAD_MSG,
        VIRTIO_SND_S_NOT_SUPP,
    },
    Result as CrateResult,
};

type AResult<T> = std::result::Result<T, alsa::Error>;

#[derive(Clone, Debug)]
pub struct AlsaBackend {
    sender: Arc<Mutex<Sender<AlsaAction>>>,
}

#[derive(Debug)]
enum AlsaAction {
    SetParameters(usize, ControlMessage),
    Prepare(usize),
    Release(usize, ControlMessage),
    Start(usize),
    Stop(usize),
    Write(usize),
    Read(usize),
}

fn update_pcm(
    pcm_: &Arc<Mutex<PCM>>,
    stream_id: usize,
    streams: &RwLock<Vec<Stream>>,
) -> AResult<()> {
    *pcm_.lock().unwrap() = {
        let streams = streams.read().unwrap();
        let s = &streams[stream_id];
        let pcm = PCM::new(
            "default",
            match s.direction {
                d if d == VIRTIO_SND_D_OUTPUT => Direction::Playback,
                d if d == VIRTIO_SND_D_INPUT => Direction::Capture,
                other => panic!("Invalid virtio-sound stream: {}", other),
            },
            false,
        )?;

        {
            let hwp = HwParams::any(&pcm)?;
            hwp.set_channels(s.params.channels.into())?;
            hwp.set_rate(
                match s.params.rate {
                    crate::virtio_sound::VIRTIO_SND_PCM_RATE_5512 => 5512,
                    crate::virtio_sound::VIRTIO_SND_PCM_RATE_8000 => 8000,
                    crate::virtio_sound::VIRTIO_SND_PCM_RATE_11025 => 11025,
                    crate::virtio_sound::VIRTIO_SND_PCM_RATE_16000 => 16000,
                    crate::virtio_sound::VIRTIO_SND_PCM_RATE_22050 => 22050,
                    crate::virtio_sound::VIRTIO_SND_PCM_RATE_32000 => 32000,
                    crate::virtio_sound::VIRTIO_SND_PCM_RATE_44100 => 44100,
                    crate::virtio_sound::VIRTIO_SND_PCM_RATE_48000 => 48000,
                    crate::virtio_sound::VIRTIO_SND_PCM_RATE_64000 => 64000,
                    crate::virtio_sound::VIRTIO_SND_PCM_RATE_88200 => 88200,
                    crate::virtio_sound::VIRTIO_SND_PCM_RATE_96000 => 96000,
                    crate::virtio_sound::VIRTIO_SND_PCM_RATE_176400 => 176400,
                    crate::virtio_sound::VIRTIO_SND_PCM_RATE_192000 => 192000,
                    crate::virtio_sound::VIRTIO_SND_PCM_RATE_384000 => 384000,
                    _ => 44100,
                },
                ValueOr::Nearest,
            )?;
            hwp.set_format(match s.params.format {
                crate::virtio_sound::VIRTIO_SND_PCM_FMT_IMA_ADPCM => Format::ImaAdPCM,
                crate::virtio_sound::VIRTIO_SND_PCM_FMT_MU_LAW => Format::MuLaw,
                crate::virtio_sound::VIRTIO_SND_PCM_FMT_A_LAW => Format::ALaw,
                crate::virtio_sound::VIRTIO_SND_PCM_FMT_S8 => Format::S8,
                crate::virtio_sound::VIRTIO_SND_PCM_FMT_U8 => Format::U8,
                crate::virtio_sound::VIRTIO_SND_PCM_FMT_S16 => Format::s16(),
                crate::virtio_sound::VIRTIO_SND_PCM_FMT_U16 => Format::r#u16(),
                crate::virtio_sound::VIRTIO_SND_PCM_FMT_S18_3 => Format::S183LE,
                crate::virtio_sound::VIRTIO_SND_PCM_FMT_U18_3 => Format::U183LE,
                crate::virtio_sound::VIRTIO_SND_PCM_FMT_S20_3 => Format::S203LE,
                crate::virtio_sound::VIRTIO_SND_PCM_FMT_U20_3 => Format::U203LE,
                crate::virtio_sound::VIRTIO_SND_PCM_FMT_S24_3 => Format::S24LE,
                crate::virtio_sound::VIRTIO_SND_PCM_FMT_U24_3 => Format::U24LE,
                crate::virtio_sound::VIRTIO_SND_PCM_FMT_S20 => Format::s20_3(),
                crate::virtio_sound::VIRTIO_SND_PCM_FMT_U20 => Format::u20_3(),
                crate::virtio_sound::VIRTIO_SND_PCM_FMT_S24 => Format::s24(),
                crate::virtio_sound::VIRTIO_SND_PCM_FMT_U24 => Format::u24(),
                crate::virtio_sound::VIRTIO_SND_PCM_FMT_S32 => Format::s32(),
                crate::virtio_sound::VIRTIO_SND_PCM_FMT_U32 => Format::r#u32(),
                crate::virtio_sound::VIRTIO_SND_PCM_FMT_FLOAT => Format::float(),
                crate::virtio_sound::VIRTIO_SND_PCM_FMT_FLOAT64 => Format::float64(),
                crate::virtio_sound::VIRTIO_SND_PCM_FMT_DSD_U8 => Format::DSDU8,
                crate::virtio_sound::VIRTIO_SND_PCM_FMT_DSD_U16 => Format::DSDU16LE,
                crate::virtio_sound::VIRTIO_SND_PCM_FMT_DSD_U32 => Format::DSDU32LE,
                crate::virtio_sound::VIRTIO_SND_PCM_FMT_IEC958_SUBFRAME => {
                    Format::iec958_subframe()
                }
                _ => Format::Unknown,
            })?;

            hwp.set_access(Access::RWInterleaved)?;

            // > A period is the number of frames in between each hardware interrupt.
            // - https://www.alsa-project.org/wiki/FramesPeriods

            // FIXME
            if let Err(err) = hwp.set_buffer_size(4096) {
                log::error!("Could not set buffer size of 4096 bytes: {}.", err,);
            }
            pcm.hw_params(&hwp)?;
        }

        // FIXME
        //if let Err(err) = hwp.set_period_size(_, ValueOr::Greater) {
        //        log::error!(
        //            "Could not set period size: {}",
        //            err,
        //        );
        //    }
        //}

        /*
        //  {
        // Make sure we don't start the stream too early
        let hwp = pcm.hw_params_current()?;
        let swp = pcm.sw_params_current()?;
        //swp.set_start_threshold(hwp.get_buffer_size()?)?;
        //swp.set_stop_threshold(hwp.get_buffer_size()?)?;
        pcm.sw_params(&swp)?;
        }
        */
        pcm
    };
    Ok(())
}

fn write_samples_direct(
    pcm: &alsa::PCM,
    stream: &mut Stream,
    mmap: &mut alsa::direct::pcm::MmapPlayback<u8>,
) -> AResult<bool> {
    while mmap.avail() > 0 {
        // Write samples to DMA area from iterator
        //
        let Some(buffer) = stream.buffers.front_mut() else {
            return Ok(false);
        };
        let mut iter = buffer.bytes[buffer.pos..].iter().cloned();
        let frames = mmap.write(&mut iter);
        let written_bytes = pcm.frames_to_bytes(frames);
        if let Ok(written_bytes) = usize::try_from(written_bytes) {
            buffer.pos += written_bytes;
        }
        if buffer.pos >= buffer.bytes.len() {
            stream.buffers.pop_front();
        }
    }
    match mmap.status().state() {
        State::Running => {
            return Ok(false);
        } // All fine
        State::Prepared => {
            //log::trace!("Starting audio output stream");
            //p.start()?
        }
        State::XRun => {
            log::trace!("Underrun in audio output stream!");
            pcm.prepare()?
        }
        State::Suspended => {
            //log::trace!("Resuming audio output stream");
            //p.resume()?
        }
        n => panic!("Unexpected pcm state {:?}", n),
    }
    Ok(true) // Call us again, please, there might be more data to write
}

fn write_samples_io(
    p: &alsa::PCM,

    stream: &mut Stream,
    io: &mut alsa::pcm::IO<u8>,
) -> AResult<bool> {
    macro_rules! avail {
        () => {{
            (match p.avail_update() {
                Ok(n) => n,
                Err(err) => {
                    log::trace!("Recovering from {}", err);
                    p.recover(err.errno() as std::os::raw::c_int, true)?;
                    p.avail_update()?
                }
            }) as usize
        }};
    }

    loop {
        let avail = avail!();
        if avail == 0 {
            break;
        }
        let written = io.mmap(avail, |buf| {
            let Some(buffer) = stream.buffers.front_mut() else {
                return 0;
            };
            let mut iter = buffer.bytes[buffer.pos..].iter().cloned();

            let mut written_bytes = 0;
            for (sample, byte) in buf.iter_mut().zip(&mut iter) {
                *sample = byte;
                written_bytes += 1;
            }
            buffer.pos += written_bytes as usize;
            if buffer.pos >= buffer.bytes.len() {
                stream.buffers.pop_front();
            }
            p.bytes_to_frames(written_bytes)
                .try_into()
                .unwrap_or_default()
        })?;
        if written == 0 {
            break;
        };
    }

    match p.state() {
        State::Suspended | State::Running => Ok(false), // All fine
        State::Prepared => {
            //p.start()?;
            Ok(false)
        }
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
    loop {
        let Ok(do_write) = receiver.recv() else {
            return Ok(());
        };
        if do_write {
            loop {
                if matches!(receiver.try_recv(), Ok(false)) {
                    break;
                }

                let mut fds = {
                    let lck = pcm.lock().unwrap();
                    if matches!(lck.state(), State::Running | State::Prepared | State::XRun) {
                        let mut mmap = lck.direct_mmap_playback::<u8>().ok();

                        if let Some(ref mut mmap) = mmap {
                            if write_samples_direct(
                                &lck,
                                &mut streams.write().unwrap()[stream_id],
                                mmap,
                            )? {
                                continue;
                            }
                        } else {
                            let mut io = lck.io_bytes();
                            // Direct mode unavailable, use alsa-lib's mmap emulation instead
                            if write_samples_io(
                                &lck,
                                &mut streams.write().unwrap()[stream_id],
                                &mut io,
                            )? {
                                continue;
                            }
                        }
                        lck.get()?
                    } else {
                        drop(lck);
                        sleep(Duration::from_millis(500));
                        continue;
                    }
                };
                // Nothing to do, let's sleep until woken up by the kernel.
                alsa::poll::poll(&mut fds, 100)?;
            }
        }
    }
}

impl AlsaBackend {
    pub fn new(streams: Arc<RwLock<Vec<Stream>>>) -> Self {
        let (sender, receiver) = channel();
        let sender = Arc::new(Mutex::new(sender));

        thread::spawn(move || {
            if let Err(err) = Self::run(streams, receiver) {
                log::error!("Main thread exited with error: {}", err);
            }
        });

        Self { sender }
    }

    fn run(
        streams: Arc<RwLock<Vec<Stream>>>,
        receiver: Receiver<AlsaAction>,
    ) -> std::result::Result<(), Box<dyn std::error::Error>> {
        let streams_no: usize;

        let (mut pcms, senders) = {
            let lck = streams.read().unwrap();
            streams_no = lck.len();
            let mut vec = Vec::with_capacity(streams_no);
            let mut senders = Vec::with_capacity(streams_no);
            for i in 0..streams_no {
                let (sender, receiver) = channel();
                let pcm = Arc::new(Mutex::new(PCM::new("default", Direction::Playback, false)?));

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
                AlsaAction::Read(_) => {}
                AlsaAction::Write(stream_id) => {
                    if stream_id >= streams_no {
                        log::error!(
                            "Received Write action for stream id {} but there are only {} PCM \
                             streams.",
                            stream_id,
                            pcms.len()
                        );
                        continue;
                    };
                    if matches!(
                        streams.write().unwrap()[stream_id].state,
                        crate::stream::PCMState::Start | crate::stream::PCMState::Prepare
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

                    let start_result = streams.write().unwrap()[stream_id].state.start();
                    if let Err(err) = start_result {
                        log::error!("Stream {} start {}", stream_id, err);
                    } else {
                        let pcm = &pcms[stream_id];
                        let lck = pcm.lock().unwrap();
                        match lck.state() {
                            State::Running => {}
                            _ => lck.start()?,
                        }
                    }
                }
                AlsaAction::Stop(stream_id) => {
                    if stream_id >= streams_no {
                        log::error!(
                            "Received Stop action for stream id {} but there are only {} PCM \
                             streams.",
                            stream_id,
                            pcms.len()
                        );
                        continue;
                    };
                    let stop_result = streams.write().unwrap()[stream_id].state.stop();
                    if let Err(err) = stop_result {
                        log::error!("Stream {} stop {}", stream_id, err);
                    }
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
                    let prepare_result = streams.write().unwrap()[stream_id].state.prepare();
                    if let Err(err) = prepare_result {
                        log::error!("Stream {} prepare {}", stream_id, err);
                    } else {
                        let pcm = &pcms[stream_id];
                        let lck = pcm.lock().unwrap();
                        match lck.state() {
                            State::Running => {}
                            _ => lck.prepare()?,
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
                    let release_result = streams.write().unwrap()[stream_id].state.release();
                    if let Err(err) = release_result {
                        log::error!("Stream {} release {}", stream_id, err);
                        msg.code = VIRTIO_SND_S_BAD_MSG;
                    } else {
                        senders[stream_id].send(false).unwrap();
                        let mut streams = streams.write().unwrap();
                        std::mem::take(&mut streams[stream_id].buffers);
                    }
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
                            st.params.features = request.features;
                            st.params.buffer_bytes = request.buffer_bytes;
                            st.params.period_bytes = request.period_bytes;
                            st.params.channels = request.channels;
                            st.params.format = request.format;
                            st.params.rate = request.rate;
                            st.params.period_bytes = request.period_bytes;
                            st.params.buffer_bytes = request.buffer_bytes;
                        }
                    }
                    drop(msg);
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
        write Write,
        read Read,
        prepare Prepare,
        start Start,
        stop Stop,
    }
    send_action! {
        ctrl set_parameters SetParameters,
        ctrl release Release,
    }
}
