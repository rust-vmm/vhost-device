// Pipewire backend device
// SPDX-License-Identifier: Apache-2.0 or BSD-3-Clause

use std::{
    collections::HashMap,
    convert::TryInto,
    mem::size_of,
    ptr,
    sync::{Arc, RwLock},
};

use log::debug;
use pw::{properties, spa, sys::PW_ID_CORE, Context, Core, ThreadLoop};
use spa::{
    param::{
        audio::{AudioFormat, AudioInfoRaw},
        ParamType,
    },
    pod::{serialize::PodSerializer, Object, Pod, Value},
    sys::{
        spa_audio_info_raw, SPA_PARAM_EnumFormat, SPA_TYPE_OBJECT_Format, SPA_AUDIO_CHANNEL_FC,
        SPA_AUDIO_CHANNEL_FL, SPA_AUDIO_CHANNEL_FR, SPA_AUDIO_CHANNEL_LFE, SPA_AUDIO_CHANNEL_MONO,
        SPA_AUDIO_CHANNEL_RC, SPA_AUDIO_CHANNEL_RL, SPA_AUDIO_CHANNEL_RR,
        SPA_AUDIO_CHANNEL_UNKNOWN, SPA_AUDIO_FORMAT_ALAW, SPA_AUDIO_FORMAT_F32,
        SPA_AUDIO_FORMAT_F64, SPA_AUDIO_FORMAT_S16, SPA_AUDIO_FORMAT_S18_LE, SPA_AUDIO_FORMAT_S20,
        SPA_AUDIO_FORMAT_S20_LE, SPA_AUDIO_FORMAT_S24, SPA_AUDIO_FORMAT_S24_LE,
        SPA_AUDIO_FORMAT_S32, SPA_AUDIO_FORMAT_S8, SPA_AUDIO_FORMAT_U16, SPA_AUDIO_FORMAT_U18_LE,
        SPA_AUDIO_FORMAT_U20, SPA_AUDIO_FORMAT_U20_LE, SPA_AUDIO_FORMAT_U24,
        SPA_AUDIO_FORMAT_U24_LE, SPA_AUDIO_FORMAT_U32, SPA_AUDIO_FORMAT_U8, SPA_AUDIO_FORMAT_ULAW,
        SPA_AUDIO_FORMAT_UNKNOWN,
    },
};
use virtio_queue::Descriptor;
use vm_memory::Bytes;

use super::AudioBackend;
use crate::{
    device::ControlMessage,
    virtio_sound::{
        VirtioSndPcmSetParams, VIRTIO_SND_D_INPUT, VIRTIO_SND_D_OUTPUT, VIRTIO_SND_PCM_FMT_A_LAW,
        VIRTIO_SND_PCM_FMT_FLOAT, VIRTIO_SND_PCM_FMT_FLOAT64, VIRTIO_SND_PCM_FMT_MU_LAW,
        VIRTIO_SND_PCM_FMT_S16, VIRTIO_SND_PCM_FMT_S18_3, VIRTIO_SND_PCM_FMT_S20,
        VIRTIO_SND_PCM_FMT_S20_3, VIRTIO_SND_PCM_FMT_S24, VIRTIO_SND_PCM_FMT_S24_3,
        VIRTIO_SND_PCM_FMT_S32, VIRTIO_SND_PCM_FMT_S8, VIRTIO_SND_PCM_FMT_U16,
        VIRTIO_SND_PCM_FMT_U18_3, VIRTIO_SND_PCM_FMT_U20, VIRTIO_SND_PCM_FMT_U20_3,
        VIRTIO_SND_PCM_FMT_U24, VIRTIO_SND_PCM_FMT_U24_3, VIRTIO_SND_PCM_FMT_U32,
        VIRTIO_SND_PCM_FMT_U8, VIRTIO_SND_PCM_RATE_11025, VIRTIO_SND_PCM_RATE_16000,
        VIRTIO_SND_PCM_RATE_176400, VIRTIO_SND_PCM_RATE_192000, VIRTIO_SND_PCM_RATE_22050,
        VIRTIO_SND_PCM_RATE_32000, VIRTIO_SND_PCM_RATE_384000, VIRTIO_SND_PCM_RATE_44100,
        VIRTIO_SND_PCM_RATE_48000, VIRTIO_SND_PCM_RATE_5512, VIRTIO_SND_PCM_RATE_64000,
        VIRTIO_SND_PCM_RATE_8000, VIRTIO_SND_PCM_RATE_88200, VIRTIO_SND_PCM_RATE_96000,
        VIRTIO_SND_S_NOT_SUPP,
    },
    Error, Result, Stream,
};

// SAFETY: Safe as the structure can be sent to another thread.
unsafe impl Send for PwBackend {}

// SAFETY: Safe as the structure can be shared with another thread as the state
// is protected with a lock.
unsafe impl Sync for PwBackend {}

pub struct PwBackend {
    pub stream_params: Arc<RwLock<Vec<Stream>>>,
    thread_loop: ThreadLoop,
    pub core: Core,
    #[allow(dead_code)]
    context: Context,
    pub stream_hash: RwLock<HashMap<u32, pw::stream::Stream>>,
    pub stream_listener: RwLock<HashMap<u32, pw::stream::StreamListener<i32>>>,
}

impl PwBackend {
    pub fn new(stream_params: Arc<RwLock<Vec<Stream>>>) -> Self {
        pw::init();

        let thread_loop = unsafe { ThreadLoop::new(Some("Pipewire thread loop")).unwrap() };

        let lock_guard = thread_loop.lock();

        let context = pw::Context::new(&thread_loop).expect("failed to create context");
        thread_loop.start();
        let core = context.connect(None).expect("Failed to connect to core");

        // Create new reference for the variable so that it can be moved into the
        // closure.
        let thread_clone = thread_loop.clone();

        // Trigger the sync event. The server's answer won't be processed until we start
        // the thread loop, so we can safely do this before setting up a
        // callback. This lets us avoid using a Cell.
        let pending = core.sync(0).expect("sync failed");
        let _listener_core = core
            .add_listener_local()
            .done(move |id, seq| {
                if id == PW_ID_CORE && seq == pending {
                    thread_clone.signal(false);
                }
            })
            .register();

        thread_loop.wait();
        lock_guard.unlock();

        log::trace!("pipewire backend running");

        Self {
            stream_params,
            thread_loop,
            core,
            context,
            stream_hash: RwLock::new(HashMap::new()),
            stream_listener: RwLock::new(HashMap::new()),
        }
    }
}

impl AudioBackend for PwBackend {
    fn write(&self, _stream_id: u32) -> Result<()> {
        Ok(())
    }

    fn read(&self, _stream_id: u32) -> Result<()> {
        log::trace!("PipewireBackend read stream_id {}", _stream_id);
        Ok(())
    }

    fn set_parameters(&self, stream_id: u32, mut msg: ControlMessage) -> Result<()> {
        let descriptors: Vec<Descriptor> = msg.desc_chain.clone().collect();
        let desc_request = &descriptors[0];
        let request = msg
            .desc_chain
            .memory()
            .read_obj::<VirtioSndPcmSetParams>(desc_request.addr())
            .unwrap();
        {
            let stream_clone = self.stream_params.clone();
            let mut stream_params = stream_clone.write().unwrap();
            let st = stream_params
                .get_mut(stream_id as usize)
                .expect("Stream does not exist");
            st.state.set_parameters();
            if !st.supports_format(request.format) || !st.supports_rate(request.rate) {
                msg.code = VIRTIO_SND_S_NOT_SUPP;
            } else {
                st.params.features = request.features;
                st.params.buffer_bytes = request.buffer_bytes;
                st.params.period_bytes = request.period_bytes;
                st.params.channels = request.channels;
                st.params.format = request.format;
                st.params.rate = request.rate;
            }
        }
        drop(msg);

        Ok(())
    }

    fn prepare(&self, stream_id: u32) -> Result<()> {
        debug!("pipewire prepare");
        self.stream_params.write().unwrap()[stream_id as usize]
            .state
            .prepare();
        let mut stream_hash = self.stream_hash.write().unwrap();
        let mut stream_listener = self.stream_listener.write().unwrap();
        let lock_guard = self.thread_loop.lock();
        let stream_params = self.stream_params.read().unwrap();
        let params = &stream_params[stream_id as usize].params;

        let mut pos: [u32; 64] = [SPA_AUDIO_CHANNEL_UNKNOWN; 64];

        match params.channels {
            6 => {
                pos[0] = SPA_AUDIO_CHANNEL_FL;
                pos[1] = SPA_AUDIO_CHANNEL_FR;
                pos[2] = SPA_AUDIO_CHANNEL_FC;
                pos[3] = SPA_AUDIO_CHANNEL_LFE;
                pos[4] = SPA_AUDIO_CHANNEL_RL;
                pos[5] = SPA_AUDIO_CHANNEL_RR;
            }
            5 => {
                pos[0] = SPA_AUDIO_CHANNEL_FL;
                pos[1] = SPA_AUDIO_CHANNEL_FR;
                pos[2] = SPA_AUDIO_CHANNEL_FC;
                pos[3] = SPA_AUDIO_CHANNEL_LFE;
                pos[4] = SPA_AUDIO_CHANNEL_RC;
            }
            4 => {
                pos[0] = SPA_AUDIO_CHANNEL_FL;
                pos[1] = SPA_AUDIO_CHANNEL_FR;
                pos[2] = SPA_AUDIO_CHANNEL_FC;
                pos[3] = SPA_AUDIO_CHANNEL_RC;
            }
            3 => {
                pos[0] = SPA_AUDIO_CHANNEL_FL;
                pos[1] = SPA_AUDIO_CHANNEL_FR;
                pos[2] = SPA_AUDIO_CHANNEL_LFE;
            }
            2 => {
                pos[0] = SPA_AUDIO_CHANNEL_FL;
                pos[1] = SPA_AUDIO_CHANNEL_FR;
            }
            1 => {
                pos[0] = SPA_AUDIO_CHANNEL_MONO;
            }
            _ => {
                return Err(Error::ChannelNotSupported(params.channels));
            }
        }

        let info = spa_audio_info_raw {
            format: match params.format {
                VIRTIO_SND_PCM_FMT_MU_LAW => SPA_AUDIO_FORMAT_ULAW,
                VIRTIO_SND_PCM_FMT_A_LAW => SPA_AUDIO_FORMAT_ALAW,
                VIRTIO_SND_PCM_FMT_S8 => SPA_AUDIO_FORMAT_S8,
                VIRTIO_SND_PCM_FMT_U8 => SPA_AUDIO_FORMAT_U8,
                VIRTIO_SND_PCM_FMT_S16 => SPA_AUDIO_FORMAT_S16,
                VIRTIO_SND_PCM_FMT_U16 => SPA_AUDIO_FORMAT_U16,
                VIRTIO_SND_PCM_FMT_S18_3 => SPA_AUDIO_FORMAT_S18_LE,
                VIRTIO_SND_PCM_FMT_U18_3 => SPA_AUDIO_FORMAT_U18_LE,
                VIRTIO_SND_PCM_FMT_S20_3 => SPA_AUDIO_FORMAT_S20_LE,
                VIRTIO_SND_PCM_FMT_U20_3 => SPA_AUDIO_FORMAT_U20_LE,
                VIRTIO_SND_PCM_FMT_S24_3 => SPA_AUDIO_FORMAT_S24_LE,
                VIRTIO_SND_PCM_FMT_U24_3 => SPA_AUDIO_FORMAT_U24_LE,
                VIRTIO_SND_PCM_FMT_S20 => SPA_AUDIO_FORMAT_S20,
                VIRTIO_SND_PCM_FMT_U20 => SPA_AUDIO_FORMAT_U20,
                VIRTIO_SND_PCM_FMT_S24 => SPA_AUDIO_FORMAT_S24,
                VIRTIO_SND_PCM_FMT_U24 => SPA_AUDIO_FORMAT_U24,
                VIRTIO_SND_PCM_FMT_S32 => SPA_AUDIO_FORMAT_S32,
                VIRTIO_SND_PCM_FMT_U32 => SPA_AUDIO_FORMAT_U32,
                VIRTIO_SND_PCM_FMT_FLOAT => SPA_AUDIO_FORMAT_F32,
                VIRTIO_SND_PCM_FMT_FLOAT64 => SPA_AUDIO_FORMAT_F64,
                _ => SPA_AUDIO_FORMAT_UNKNOWN,
            },
            rate: match params.rate {
                VIRTIO_SND_PCM_RATE_5512 => 5512,
                VIRTIO_SND_PCM_RATE_8000 => 8000,
                VIRTIO_SND_PCM_RATE_11025 => 11025,
                VIRTIO_SND_PCM_RATE_16000 => 16000,
                VIRTIO_SND_PCM_RATE_22050 => 22050,
                VIRTIO_SND_PCM_RATE_32000 => 32000,
                VIRTIO_SND_PCM_RATE_44100 => 44100,
                VIRTIO_SND_PCM_RATE_48000 => 48000,
                VIRTIO_SND_PCM_RATE_64000 => 64000,
                VIRTIO_SND_PCM_RATE_88200 => 88200,
                VIRTIO_SND_PCM_RATE_96000 => 96000,
                VIRTIO_SND_PCM_RATE_176400 => 176400,
                VIRTIO_SND_PCM_RATE_192000 => 192000,
                VIRTIO_SND_PCM_RATE_384000 => 384000,
                _ => 44100,
            },
            flags: 0,
            channels: params.channels as u32,
            position: pos,
        };

        let mut audio_info = AudioInfoRaw::new();
        audio_info.set_format(AudioFormat::S16LE);
        audio_info.set_rate(info.rate);
        audio_info.set_channels(info.channels);

        let values: Vec<u8> = PodSerializer::serialize(
            std::io::Cursor::new(Vec::new()),
            &Value::Object(Object {
                type_: SPA_TYPE_OBJECT_Format,
                id: SPA_PARAM_EnumFormat,
                properties: audio_info.into(),
            }),
        )
        .unwrap()
        .0
        .into_inner();

        let value_clone = values.clone();

        let mut param = [Pod::from_bytes(&values).unwrap()];

        let props = properties! {
            *pw::keys::MEDIA_TYPE => "Audio",
            *pw::keys::MEDIA_CATEGORY => "Playback",
        };

        let stream = pw::stream::Stream::new(&self.core, "audio-output", props)
            .expect("could not create new stream");

        let streams = self.stream_params.clone();

        let listener_stream = stream
            .add_local_listener()
            .state_changed(|old, new| {
                debug!("State changed: {:?} -> {:?}", old, new);
            })
            .param_changed(move |stream, id, _data, param| {
                let Some(_param) = param else {
                    return;
                };
                if id != ParamType::Format.as_raw() {
                    return;
                }
                let mut param = [Pod::from_bytes(&value_clone).unwrap()];

                //callback to negotiate new set of streams
                stream
                    .update_params(&mut param)
                    .expect("could not update params");
            })
            .process(move |stream, _data| match stream.dequeue_buffer() {
                None => debug!("No buffer recieved"),
                Some(mut buf) => {
                    let datas = buf.datas_mut();
                    let frame_size = info.channels * size_of::<i16>() as u32;
                    let data = &mut datas[0];
                    let n_bytes = if let Some(slice) = data.data() {
                        let mut n_bytes = slice.len();
                        let mut streams = streams.write().unwrap();
                        let streams = streams
                            .get_mut(stream_id as usize)
                            .expect("Stream does not exist");
                        let Some(buffer) = streams.buffers.front_mut() else {
                            return;
                        };

                        let mut start = buffer.pos;

                        let avail = (buffer.bytes.len() - start) as i32;

                        if avail < n_bytes as i32 {
                            n_bytes = avail.try_into().unwrap();
                        }
                        let p = &mut slice[buffer.pos..start + n_bytes];
                        if avail <= 0 {
                            // pad with silence
                            unsafe {
                                ptr::write_bytes(p.as_mut_ptr(), 0, n_bytes);
                            }
                        } else {
                            let slice = &buffer.bytes[buffer.pos..start + n_bytes];
                            p.copy_from_slice(slice);

                            start += n_bytes;

                            buffer.pos = start;

                            if start >= buffer.bytes.len() {
                                streams.buffers.pop_front();
                            }
                        }
                        n_bytes
                    } else {
                        0
                    };
                    let chunk = data.chunk_mut();
                    *chunk.offset_mut() = 0;
                    *chunk.stride_mut() = frame_size as _;
                    *chunk.size_mut() = n_bytes as _;
                }
            })
            .register()
            .expect("failed to register stream listener");

        stream_listener.insert(stream_id, listener_stream);

        let direction = match stream_params[stream_id as usize].direction {
            VIRTIO_SND_D_OUTPUT => spa::Direction::Output,
            VIRTIO_SND_D_INPUT => spa::Direction::Input,
            _ => panic!("Invalid direction"),
        };

        stream
            .connect(
                direction,
                Some(pw::constants::ID_ANY),
                pw::stream::StreamFlags::RT_PROCESS
                    | pw::stream::StreamFlags::AUTOCONNECT
                    | pw::stream::StreamFlags::INACTIVE
                    | pw::stream::StreamFlags::MAP_BUFFERS,
                &mut param,
            )
            .expect("could not connect to the stream");

        // insert created stream in a hash table
        stream_hash.insert(stream_id, stream);
        lock_guard.unlock();
        Ok(())
    }

    fn release(&self, stream_id: u32, _msg: ControlMessage) -> Result<()> {
        debug!("pipewire backend, release function");
        self.stream_params.write().unwrap()[stream_id as usize]
            .state
            .release();
        let lock_guard = self.thread_loop.lock();
        let mut stream_hash = self.stream_hash.write().unwrap();
        let mut stream_listener = self.stream_listener.write().unwrap();
        let st_buffer = &mut self.stream_params.write().unwrap();
        let Some(stream) = stream_hash.get(&stream_id) else {
            return Err(Error::StreamWithIdNotFound(stream_id));
        };
        stream.disconnect().expect("could not disconnect stream");
        std::mem::take(&mut st_buffer[stream_id as usize].buffers);
        stream_hash.remove(&stream_id);
        stream_listener.remove(&stream_id);
        lock_guard.unlock();
        Ok(())
    }

    fn start(&self, stream_id: u32) -> Result<()> {
        debug!("pipewire start");
        self.stream_params.write().unwrap()[stream_id as usize]
            .state
            .start();
        let lock_guard = self.thread_loop.lock();
        let stream_hash = self.stream_hash.read().unwrap();
        let Some(stream) = stream_hash.get(&stream_id) else {
            return Err(Error::StreamWithIdNotFound(stream_id));
        };
        stream.set_active(true).expect("could not start stream");
        lock_guard.unlock();
        Ok(())
    }

    fn stop(&self, stream_id: u32) -> Result<()> {
        debug!("pipewire stop");
        self.stream_params.write().unwrap()[stream_id as usize]
            .state
            .stop();
        let lock_guard = self.thread_loop.lock();
        let stream_hash = self.stream_hash.read().unwrap();
        let Some(stream) = stream_hash.get(&stream_id) else {
            return Err(Error::StreamWithIdNotFound(stream_id));
        };
        stream.set_active(false).expect("could not stop stream");
        lock_guard.unlock();
        Ok(())
    }
}
