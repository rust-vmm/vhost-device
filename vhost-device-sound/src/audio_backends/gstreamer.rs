use std::{
    collections::HashMap,
    sync::{Arc, RwLock},
};

use gst::{glib::Error as GlibError, prelude::*, Pipeline};
use gst_app;
use gst_audio::{AudioFormat, AudioInfo};
use thiserror::Error as ThisError;

use super::AudioBackend;
use crate::{
    stream::{Error as StreamError, PCMState, PcmParams},
    virtio_sound::{
        VirtioSndPcmSetParams, VIRTIO_SND_PCM_FMT_A_LAW, VIRTIO_SND_PCM_FMT_FLOAT,
        VIRTIO_SND_PCM_FMT_FLOAT64, VIRTIO_SND_PCM_FMT_MU_LAW, VIRTIO_SND_PCM_FMT_S16,
        VIRTIO_SND_PCM_FMT_S18_3, VIRTIO_SND_PCM_FMT_S20, VIRTIO_SND_PCM_FMT_S20_3,
        VIRTIO_SND_PCM_FMT_S24, VIRTIO_SND_PCM_FMT_S24_3, VIRTIO_SND_PCM_FMT_S32,
        VIRTIO_SND_PCM_FMT_S8, VIRTIO_SND_PCM_FMT_U16, VIRTIO_SND_PCM_FMT_U18_3,
        VIRTIO_SND_PCM_FMT_U20, VIRTIO_SND_PCM_FMT_U20_3, VIRTIO_SND_PCM_FMT_U24,
        VIRTIO_SND_PCM_FMT_U24_3, VIRTIO_SND_PCM_FMT_U32, VIRTIO_SND_PCM_FMT_U8,
        VIRTIO_SND_PCM_RATE_11025, VIRTIO_SND_PCM_RATE_12000, VIRTIO_SND_PCM_RATE_16000,
        VIRTIO_SND_PCM_RATE_176400, VIRTIO_SND_PCM_RATE_192000, VIRTIO_SND_PCM_RATE_22050,
        VIRTIO_SND_PCM_RATE_24000, VIRTIO_SND_PCM_RATE_32000, VIRTIO_SND_PCM_RATE_384000,
        VIRTIO_SND_PCM_RATE_44100, VIRTIO_SND_PCM_RATE_48000, VIRTIO_SND_PCM_RATE_5512,
        VIRTIO_SND_PCM_RATE_64000, VIRTIO_SND_PCM_RATE_8000, VIRTIO_SND_PCM_RATE_88200,
        VIRTIO_SND_PCM_RATE_96000,
    },
    Direction, Error, Result, Stream,
};

/// Error type for the Gstreamer backend
#[derive(Debug, ThisError)]
pub enum GstError {
    #[error("Failed to initialize GStreamer: {0}")]
    InitError(GlibError),
}

pub struct GStreamerBackendIn {
    pipeline: Pipeline,
}

impl GStreamerBackendIn {
    pub fn new(
        caps: &gst::Caps,
        stream_id: u32,
        streams: Arc<RwLock<Vec<Stream>>>,
    ) -> Result<Self> {
        // Create the input pipeline
        let pipeline = gst::Pipeline::with_name("audio_input_pipeline");

        let autoaudiosrc =
            gst::ElementFactory::make_with_name("autoaudiosrc", Some("autoaudiosrc"))
                .map_err(|e| Error::UnexpectedAudioBackendError(e.into()))?;

        let appsink = gst_app::AppSink::builder()
            .name("audio_appsink")
            .caps(caps)
            .build();

        pipeline
            .add_many([&autoaudiosrc, appsink.upcast_ref()])
            .map_err(|e| Error::UnexpectedAudioBackendError(e.into()))?;

        gst::Element::link_many([&autoaudiosrc, appsink.upcast_ref()])
            .map_err(|e| Error::UnexpectedAudioBackendError(e.into()))?;

        appsink.set_callbacks(
            gst_app::AppSinkCallbacks::builder()
                .new_sample(move |appsink| {
                    log::debug!("AppSink new sample for stream {stream_id}");

                    // get sample and buffer
                    let sample = match appsink.pull_sample() {
                        Ok(sample) => sample,
                        Err(err) => {
                            log::error!("Failed to pull sample: {err:?}");
                            return Err(gst::FlowError::Eos);
                        }
                    };

                    let buffer = sample.buffer().ok_or_else(|| {
                        log::error!("Failed to get buffer from sample");
                        gst::FlowError::Error
                    })?;

                    let map = match buffer.map_readable() {
                        Ok(map) => map,
                        Err(err) => {
                            log::error!("Failed to map buffer: {err:?}");
                            return Err(gst::FlowError::Error);
                        }
                    };

                    let slice = map.as_slice();
                    let mut n_samples = slice.len();
                    let mut start = 0;

                    let mut stream_params = streams.write().unwrap();
                    let stream = match stream_params.get_mut(stream_id as usize) {
                        Some(s) => s,
                        None => {
                            log::error!("Stream {stream_id} not found in appsink callback");
                            return Err(gst::FlowError::Error);
                        }
                    };

                    while n_samples > 0 {
                        let Some(request) = stream.requests.front_mut() else {
                            log::debug!("No request available for input stream {stream_id}");
                            return Err(gst::FlowError::Eos);
                        };

                        let avail = request.len().saturating_sub(request.pos);
                        let n_bytes = n_samples.min(avail);

                        let p = &slice[start..start + n_bytes];

                        let written = request
                            .write_input(p)
                            .expect("Failed to write input to guest")
                            as usize;

                        if written == 0 {
                            log::debug!("Wrote 0 bytes, breaking");
                            break;
                        }

                        n_samples -= written;
                        start += written;

                        if request.pos >= request.len() {
                            stream.requests.pop_front();
                        }
                    }

                    Ok(gst::FlowSuccess::Ok)
                })
                .build(),
        );

        Ok(Self { pipeline })
    }
}

pub struct GStreamerBackendOut {
    pipeline: Pipeline,
}

impl GStreamerBackendOut {
    pub fn new(
        caps: &gst::Caps,
        stream_id: u32,
        streams: Arc<RwLock<Vec<Stream>>>,
    ) -> Result<Self> {
        // Create the output pipeline
        let pipeline = gst::Pipeline::with_name("audio_output_pipeline");

        let appsrc = gst_app::AppSrc::builder()
            .name("audio_appsrc")
            .caps(caps)
            .build();

        let autoaudiosink =
            gst::ElementFactory::make_with_name("autoaudiosink", Some("autoaudiosink"))
                .map_err(|e| Error::UnexpectedAudioBackendError(e.into()))?;

        pipeline
            .add_many([appsrc.upcast_ref(), &autoaudiosink])
            .map_err(|e| Error::UnexpectedAudioBackendError(e.into()))?;

        gst::Element::link_many([appsrc.upcast_ref(), &autoaudiosink])
            .map_err(|e| Error::UnexpectedAudioBackendError(e.into()))?;

        appsrc.set_callbacks(
            gst_app::AppSrcCallbacks::builder()
                .need_data(move |appsrc, _| {
                    log::debug!("AppSrc need data for stream {stream_id}");
                    let mut stream_params = streams.write().unwrap();
                    let stream = stream_params
                        .get_mut(stream_id as usize)
                        .expect("Stream does not exist");
                    let Some(request) = stream.requests.front_mut() else {
                        return;
                    };

                    // Check if the request has data to read
                    let avail = request.len().saturating_sub(request.pos);
                    if avail == 0 {
                        stream.requests.pop_front();
                        return;
                    }

                    // push data to appsrc
                    let period_bytes = stream.params.period_bytes.to_native() as usize;
                    let to_send = avail.min(period_bytes);

                    let mut buffer = match gst::Buffer::with_size(to_send) {
                        Ok(buf) => buf,
                        Err(e) => {
                            log::error!("Failed to create buffer: {e:?}");
                            return;
                        }
                    };

                    {
                        let buffer = match buffer.get_mut() {
                            Some(buf) => buf,
                            None => {
                                log::error!("Failed to get mutable buffer reference");
                                return;
                            }
                        };
                        let mut map = match buffer.map_writable() {
                            Ok(map) => map,
                            Err(e) => {
                                log::error!("Failed to map buffer: {e:?}");
                                return;
                            }
                        };
                        let slice = map.as_mut_slice();

                        // copy data from request to buffer
                        let written = request
                            .read_output(slice)
                            .expect("Failed to read output buffer from guest");

                        request.pos += written as usize;
                        if request.pos >= request.len() {
                            stream.requests.pop_front();
                        }
                    }

                    // push data to appsrc
                    if let Err(err) = appsrc.push_buffer(buffer) {
                        log::error!("Failed to push buffer: {err}");
                    }
                })
                .build(),
        );

        Ok(Self { pipeline })
    }
}

pub struct GStreamerBackend {
    stream_params: Arc<RwLock<Vec<Stream>>>,
    stream_in: RwLock<HashMap<u32, GStreamerBackendIn>>,
    stream_out: RwLock<HashMap<u32, GStreamerBackendOut>>,
}

impl GStreamerBackend {
    pub fn new(stream_params: Arc<RwLock<Vec<Stream>>>) -> std::result::Result<Self, GstError> {
        // init GStreamer
        log::debug!("Initializing GStreamer backend");

        gst::init().map_err(GstError::InitError)?;

        Ok(Self {
            stream_params,
            stream_in: RwLock::new(HashMap::new()),
            stream_out: RwLock::new(HashMap::new()),
        })
    }

    #[cfg(target_endian = "little")]
    pub fn set_format(&self, params: &PcmParams) -> Result<AudioFormat> {
        let format = match params.format {
            VIRTIO_SND_PCM_FMT_MU_LAW => AudioFormat::Encoded,
            VIRTIO_SND_PCM_FMT_A_LAW => AudioFormat::Encoded,
            VIRTIO_SND_PCM_FMT_S8 => AudioFormat::S8,
            VIRTIO_SND_PCM_FMT_U8 => AudioFormat::U8,
            VIRTIO_SND_PCM_FMT_S16 => AudioFormat::S16le,
            VIRTIO_SND_PCM_FMT_U16 => AudioFormat::U16le,
            VIRTIO_SND_PCM_FMT_S18_3 => AudioFormat::S18le,
            VIRTIO_SND_PCM_FMT_U18_3 => AudioFormat::U18le,
            VIRTIO_SND_PCM_FMT_S20_3 => AudioFormat::S20le,
            VIRTIO_SND_PCM_FMT_U20_3 => AudioFormat::U20le,
            VIRTIO_SND_PCM_FMT_S24_3 => AudioFormat::S24le,
            VIRTIO_SND_PCM_FMT_U24_3 => AudioFormat::U24le,
            VIRTIO_SND_PCM_FMT_S20 => {
                log::warn!("20-bit format not directly supported, using 24/32-bit format");
                AudioFormat::S2432le
            }
            VIRTIO_SND_PCM_FMT_U20 => {
                log::warn!("20-bit format not directly supported, using 24/32-bit format");
                AudioFormat::U2432le
            }
            VIRTIO_SND_PCM_FMT_S24 => AudioFormat::S2432le,
            VIRTIO_SND_PCM_FMT_U24 => AudioFormat::U2432le,
            VIRTIO_SND_PCM_FMT_S32 => AudioFormat::S32le,
            VIRTIO_SND_PCM_FMT_U32 => AudioFormat::U32le,
            VIRTIO_SND_PCM_FMT_FLOAT => AudioFormat::F32le,
            VIRTIO_SND_PCM_FMT_FLOAT64 => AudioFormat::F64le,
            _ => AudioFormat::Unknown,
        };
        Ok(format)
    }

    #[cfg(target_endian = "big")]
    pub fn set_format(&self, params: &PcmParams) -> Result<AudioFormat> {
        let format = match params.format {
            VIRTIO_SND_PCM_FMT_MU_LAW => AudioFormat::Encoded,
            VIRTIO_SND_PCM_FMT_A_LAW => AudioFormat::Encoded,
            VIRTIO_SND_PCM_FMT_S8 => AudioFormat::S8,
            VIRTIO_SND_PCM_FMT_U8 => AudioFormat::U8,
            VIRTIO_SND_PCM_FMT_S16 => AudioFormat::S16le,
            VIRTIO_SND_PCM_FMT_U16 => AudioFormat::U16le,
            VIRTIO_SND_PCM_FMT_S18_3 => AudioFormat::S18le,
            VIRTIO_SND_PCM_FMT_U18_3 => AudioFormat::U18le,
            VIRTIO_SND_PCM_FMT_S20_3 => AudioFormat::S20le,
            VIRTIO_SND_PCM_FMT_U20_3 => AudioFormat::U20le,
            VIRTIO_SND_PCM_FMT_S24_3 => AudioFormat::S24le,
            VIRTIO_SND_PCM_FMT_U24_3 => AudioFormat::U24le,
            VIRTIO_SND_PCM_FMT_S20 => {
                log::warn!("20-bit format not directly supported, using 24/32-bit format");
                AudioFormat::S2432be
            }
            VIRTIO_SND_PCM_FMT_U20 => {
                log::warn!("20-bit format not directly supported, using 24/32-bit format");
                AudioFormat::U2432be
            }
            VIRTIO_SND_PCM_FMT_S24 => AudioFormat::S2432be,
            VIRTIO_SND_PCM_FMT_U24 => AudioFormat::U2432be,
            VIRTIO_SND_PCM_FMT_S32 => AudioFormat::S32be,
            VIRTIO_SND_PCM_FMT_U32 => AudioFormat::U32be,
            VIRTIO_SND_PCM_FMT_FLOAT => AudioFormat::F32be,
            VIRTIO_SND_PCM_FMT_FLOAT64 => AudioFormat::F64be,
            _ => AudioFormat::Unknown,
        };

        Ok(format)
    }

    pub fn create_caps(&self, params: &PcmParams) -> Result<gst::Caps> {
        let channels = u32::from(params.channels);

        let format = self.set_format(params).map_err(|e| {
            log::error!("Failed to set audio format: {e}");
            Error::UnexpectedAudioBackendConfiguration
        })?;

        let rate = match params.rate {
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
            VIRTIO_SND_PCM_RATE_12000 => 12000,
            VIRTIO_SND_PCM_RATE_24000 => 24000,
            _ => 44100,
        };

        log::debug!("Creating caps for PCM stream: {format} {rate} {channels}");

        let caps = match params.format {
            VIRTIO_SND_PCM_FMT_MU_LAW => gst::Caps::builder("audio/x-mulaw")
                .field("rate", rate)
                .field("channels", channels)
                .build(),
            VIRTIO_SND_PCM_FMT_A_LAW => gst::Caps::builder("audio/x-alaw")
                .field("rate", rate)
                .field("channels", channels)
                .build(),
            _ => {
                let audio_info =
                    AudioInfo::builder(format, rate, channels)
                        .build()
                        .map_err(|e| {
                            log::error!("Failed to create AudioInfo: {e}");
                            Error::UnexpectedAudioBackendConfiguration
                        })?;

                audio_info.to_caps().map_err(|e| {
                    log::error!("Failed to create caps from AudioInfo: {e}");
                    Error::UnexpectedAudioBackendConfiguration
                })?
            }
        };

        Ok(caps)
    }
}

impl AudioBackend for GStreamerBackend {
    fn write(&self, stream_id: u32) -> Result<()> {
        if stream_id >= self.stream_params.read().unwrap().len() as u32 {
            log::error!(
                "Received DoWork action for stream id {} but there are only {} PCM streams.",
                stream_id,
                self.stream_params.read().unwrap().len()
            );
            return Err(Error::StreamWithIdNotFound(stream_id));
        }
        if !matches!(
            self.stream_params.read().unwrap()[stream_id as usize].state,
            PCMState::Start | PCMState::Prepare
        ) {
            return Err(Error::Stream(crate::stream::Error::InvalidState(
                "write",
                self.stream_params.read().unwrap()[stream_id as usize].state,
            )));
        }
        Ok(())
    }

    fn read(&self, stream_id: u32) -> Result<()> {
        if !matches!(
            self.stream_params.read().unwrap()[stream_id as usize].state,
            PCMState::Start | PCMState::Prepare
        ) {
            return Err(Error::Stream(crate::stream::Error::InvalidState(
                "read",
                self.stream_params.read().unwrap()[stream_id as usize].state,
            )));
        }
        Ok(())
    }

    fn set_parameters(&self, stream_id: u32, request: VirtioSndPcmSetParams) -> Result<()> {
        log::debug!("Setting parameters for stream {stream_id}");

        let stream_clone = self.stream_params.clone();
        let mut stream_params = stream_clone.write().unwrap();
        if let Some(st) = stream_params.get_mut(stream_id as usize) {
            if let Err(err) = st.state.set_parameters() {
                log::error!("Stream {stream_id} set_parameters {err}");
                return Err(Error::Stream(err));
            } else if !st.supports_format(request.format) || !st.supports_rate(request.rate) {
                return Err(Error::UnexpectedAudioBackendConfiguration);
            } else {
                st.params.features = request.features;
                st.params.buffer_bytes = request.buffer_bytes;
                st.params.period_bytes = request.period_bytes;
                st.params.channels = request.channels;
                st.params.format = request.format;
                st.params.rate = request.rate;
            }
        } else {
            return Err(Error::StreamWithIdNotFound(stream_id));
        }
        log::debug!("Stream parameters after set: {stream_params:?}");

        Ok(())
    }

    fn prepare(&self, stream_id: u32) -> Result<()> {
        log::debug!("Preparing stream {stream_id}");
        self.stream_params
            .write()
            .unwrap()
            .get_mut(stream_id as usize)
            .ok_or(Error::StreamWithIdNotFound(stream_id))?
            .state
            .prepare()
            .inspect_err(|err| log::error!("Stream {stream_id} prepare {err}"))
            .map_err(Error::Stream)?;

        log::debug!("Stream {stream_id} prepared successfully");
        let stream_params = self.stream_params.read().unwrap();
        let params = &stream_params[stream_id as usize].params;
        let mut stream_in = self.stream_in.write().unwrap();
        let mut stream_out = self.stream_out.write().unwrap();

        if let Some(stream) = stream_in.remove(&stream_id) {
            if let Err(err) = stream.pipeline.set_state(gst::State::Null) {
                log::error!("Failed to set pipeline to Null state: {err}");
                return Err(Error::Stream(StreamError::CouldNotDisconnectStream));
            }
        }

        if let Some(stream) = stream_out.remove(&stream_id) {
            if let Err(err) = stream.pipeline.set_state(gst::State::Null) {
                log::error!("Failed to set pipeline to Null state: {err}");
                return Err(Error::Stream(StreamError::CouldNotDisconnectStream));
            }
        }

        let caps = self.create_caps(params)?;

        let streams = self.stream_params.clone();

        let direction = stream_params[stream_id as usize].direction;

        if direction == Direction::Input {
            let pipeline_in = GStreamerBackendIn::new(&caps, stream_id, streams)?;
            stream_in.insert(stream_id, pipeline_in);
        } else if direction == Direction::Output {
            let pipeline_out = GStreamerBackendOut::new(&caps, stream_id, streams)?;
            stream_out.insert(stream_id, pipeline_out);
        }
        Ok(())
    }

    fn release(&self, stream_id: u32) -> Result<()> {
        log::debug!("Releasing stream {stream_id}");
        self.stream_params
            .write()
            .unwrap()
            .get_mut(stream_id as usize)
            .ok_or(Error::StreamWithIdNotFound(stream_id))?
            .state
            .release()
            .inspect_err(|err| log::error!("Stream {stream_id} release {err}"))
            .map_err(Error::Stream)?;

        let stream = &mut self.stream_params.write().unwrap();
        let direction = stream[stream_id as usize].direction;

        if direction == Direction::Input {
            let mut stream_in = self.stream_in.write().unwrap();
            let pipeline_in = stream_in
                .get(&stream_id)
                .ok_or(Error::StreamWithIdNotFound(stream_id))?;
            if let Err(err) = pipeline_in.pipeline.set_state(gst::State::Null) {
                log::error!("Failed to set pipeline in to Null state: {err}");
                return Err(Error::Stream(StreamError::CouldNotDisconnectStream));
            }
            stream_in.remove(&stream_id);
        } else if direction == Direction::Output {
            let mut stream_out = self.stream_out.write().unwrap();
            let pipeline_out = stream_out
                .get(&stream_id)
                .ok_or(Error::StreamWithIdNotFound(stream_id))?;
            if let Err(err) = pipeline_out.pipeline.set_state(gst::State::Null) {
                log::error!("Failed to set pipeline out to Null state: {err}");
                return Err(Error::Stream(StreamError::CouldNotDisconnectStream));
            }
            stream_out.remove(&stream_id);
        }

        // clear requests for the stream
        std::mem::take(&mut stream[stream_id as usize].requests);

        Ok(())
    }

    fn start(&self, stream_id: u32) -> Result<()> {
        log::debug!("Starting stream {stream_id}");
        self.stream_params
            .write()
            .unwrap()
            .get_mut(stream_id as usize)
            .ok_or(Error::StreamWithIdNotFound(stream_id))?
            .state
            .start()
            .inspect_err(|err| log::error!("Stream {stream_id} start {err}"))
            .map_err(Error::Stream)?;

        let stream = self.stream_params.read().unwrap();
        let direction = stream[stream_id as usize].direction;

        if direction == Direction::Input {
            let stream_in = self.stream_in.read().unwrap();
            let pipeline_in = stream_in
                .get(&stream_id)
                .ok_or(Error::StreamWithIdNotFound(stream_id))?;
            if let Err(err) = pipeline_in.pipeline.set_state(gst::State::Playing) {
                log::error!("Failed to set pipeline in to Playing state: {err}");
                return Err(Error::Stream(StreamError::CouldNotStartStream));
            }
        } else if direction == Direction::Output {
            let stream_out = self.stream_out.read().unwrap();
            let pipeline_out = stream_out
                .get(&stream_id)
                .ok_or(Error::StreamWithIdNotFound(stream_id))?;
            if let Err(err) = pipeline_out.pipeline.set_state(gst::State::Playing) {
                log::error!("Failed to set pipeline out to Playing state: {err}");
                return Err(Error::Stream(StreamError::CouldNotStartStream));
            }
        }

        Ok(())
    }

    fn stop(&self, stream_id: u32) -> Result<()> {
        log::debug!("Stopping stream {stream_id}");
        self.stream_params
            .write()
            .unwrap()
            .get_mut(stream_id as usize)
            .ok_or(Error::StreamWithIdNotFound(stream_id))?
            .state
            .stop()
            .inspect_err(|err| log::error!("Stream {stream_id} start {err}"))
            .map_err(Error::Stream)?;

        let stream = self.stream_params.read().unwrap();
        let direction = stream[stream_id as usize].direction;

        if direction == Direction::Input {
            let stream_in = self.stream_in.read().unwrap();
            let pipeline_in = stream_in
                .get(&stream_id)
                .ok_or(Error::StreamWithIdNotFound(stream_id))?;
            if let Err(err) = pipeline_in.pipeline.set_state(gst::State::Paused) {
                log::error!("Failed to set pipeline in to Paused state: {err}");
                return Err(Error::Stream(StreamError::CouldNotStopStream));
            }
        } else if direction == Direction::Output {
            let stream_out = self.stream_out.read().unwrap();
            let pipeline_out = stream_out
                .get(&stream_id)
                .ok_or(Error::StreamWithIdNotFound(stream_id))?;
            if let Err(err) = pipeline_out.pipeline.set_state(gst::State::Paused) {
                log::error!("Failed to set pipeline out to Paused state: {err}");
                return Err(Error::Stream(StreamError::CouldNotStopStream));
            }
        }
        Ok(())
    }

    #[cfg(test)]
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}

#[cfg(test)]
pub mod test_utils;

#[cfg(test)]
mod tests {
    use rusty_fork::rusty_fork_test;

    use super::{test_utils::GStreamerTestHarness, *};
    use crate::{stream::Stream, virtio_sound::*};

    // `GStreamerTestHarness` modifies the process's environment, so this test should
    // be executed on a forked process.
    rusty_fork_test! {
        #[test]
        fn test_gstreamer_backend_success() {
            crate::init_logger();
            let stream = Stream {
                direction: Direction::Input,
                ..Default::default()
            };

            let stream_params = Arc::new(RwLock::new(vec![stream]));

            let _test_harness = GStreamerTestHarness::new();

            let gst_backend = GStreamerBackend::new(stream_params).unwrap();

            // Test input stream lifecycle
            let request = VirtioSndPcmSetParams {
                format: VIRTIO_SND_PCM_FMT_S16,
                rate: VIRTIO_SND_PCM_RATE_44100,
                channels: 2,
                ..Default::default()
            };
            gst_backend.set_parameters(0, request).unwrap();
            gst_backend.prepare(0).unwrap();
            gst_backend.start(0).unwrap();
            gst_backend.write(0).unwrap();
            gst_backend.read(0).unwrap();
            gst_backend.stop(0).unwrap();
            gst_backend.release(0).unwrap();
        }
    }

    // `GStreamerTestHarness` modifies the process's environment, so this test should
    // be executed on a forked process.
    rusty_fork_test! {
        #[test]
        fn test_gstreamer_backend_invalid_stream_id() {
            crate::init_logger();
            let stream_params = Arc::new(RwLock::new(vec![Stream::default()]));

            let _test_harness = GStreamerTestHarness::new();

            let gst_backend = GStreamerBackend::new(stream_params).unwrap();
            let result = gst_backend.write(1);
            assert!(result.is_err());
        }
    }

    // `GStreamerTestHarness` modifies the process's environment, so this test should
    // be executed on a forked process.
    rusty_fork_test! {
        #[test]
        fn test_gstreamer_invalid_stream() {
            crate::init_logger();
            let stream_params = Arc::new(RwLock::new(vec![]));

            let _test_harness = GStreamerTestHarness::new();

            let gst_backend = GStreamerBackend::new(stream_params).unwrap();
            let request = VirtioSndPcmSetParams::default();
            let res = gst_backend.set_parameters(0, request);
            assert_eq!(
                res.unwrap_err().to_string(),
                Error::StreamWithIdNotFound(0).to_string()
            );

            for res in [
                gst_backend.prepare(0),
                gst_backend.start(0),
                gst_backend.stop(0),
            ] {
                assert_eq!(
                    res.unwrap_err().to_string(),
                    Error::StreamWithIdNotFound(0).to_string()
                );
            }

            let res = gst_backend.release(0);
            assert_eq!(
                res.unwrap_err().to_string(),
                Error::StreamWithIdNotFound(0).to_string()
            );
        }
    }

    // `GStreamerTestHarness` modifies the process's environment, so this test should
    // be executed on a forked process.
    rusty_fork_test! {
        #[test]
        fn test_gstreamer_invalid_state_transitions() {
            crate::init_logger();
            let stream_params = Arc::new(RwLock::new(vec![Stream::default()]));

            let _test_harness = GStreamerTestHarness::new();

            let gst_backend = GStreamerBackend::new(stream_params).unwrap();

            // Test invalid state transitions
            assert!(gst_backend.start(0).is_err());
            assert!(gst_backend.stop(0).is_err());
            assert!(gst_backend.release(0).is_err());

            let request = VirtioSndPcmSetParams {
                format: VIRTIO_SND_PCM_FMT_S16,
                rate: VIRTIO_SND_PCM_RATE_44100,
                channels: 2,
                ..Default::default()
            };
            gst_backend.set_parameters(0, request).unwrap();
            gst_backend.prepare(0).unwrap();

            assert!(gst_backend.stop(0).is_err());
        }
    }

    // `GStreamerTestHarness` modifies the process's environment, so this test should
    // be executed on a forked process.
    rusty_fork_test! {
        #[test]
        fn test_gstreamer_invalid_parameters() {
            crate::init_logger();
            let stream_params = Arc::new(RwLock::new(vec![Stream::default()]));

            let _test_harness = GStreamerTestHarness::new();

            let gst_backend = GStreamerBackend::new(stream_params).unwrap();

            let unsupported_request = VirtioSndPcmSetParams {
                format: VIRTIO_SND_PCM_FMT_IMA_ADPCM,
                rate: VIRTIO_SND_PCM_RATE_44100,
                channels: 2,
                ..Default::default()
            };
            assert!(gst_backend.set_parameters(0, unsupported_request).is_err());

            // Test unsupported rate
            let unsupported_rate_request = VirtioSndPcmSetParams {
                format: VIRTIO_SND_PCM_FMT_S16,
                rate: VIRTIO_SND_PCM_RATE_5512,
                channels: 2,
                ..Default::default()
            };
            assert!(gst_backend.set_parameters(0, unsupported_rate_request).is_err());
        }
    }

    // `GStreamerTestHarness` modifies the process's environment, so this test should
    // be executed on a forked process.
    rusty_fork_test! {
        #[test]
        fn test_gstreamer_mu_law_a_law_caps() {
            crate::init_logger();
            let stream_params = Arc::new(RwLock::new(vec![Stream::default()]));

            let _test_harness = GStreamerTestHarness::new();

            let gst_backend = GStreamerBackend::new(stream_params).unwrap();

            // Test μ-law format
            let mu_law_params = PcmParams {
                format: VIRTIO_SND_PCM_FMT_MU_LAW,
                rate: VIRTIO_SND_PCM_RATE_8000,
                channels: 1,
                ..Default::default()
            };
            let caps = gst_backend.create_caps(&mu_law_params).unwrap();
            let caps_str = caps.to_string();
            assert!(caps_str.contains("audio/x-mulaw"));

            // Test A-law format
            let a_law_params = PcmParams {
                format: VIRTIO_SND_PCM_FMT_A_LAW,
                rate: VIRTIO_SND_PCM_RATE_8000,
                channels: 1,
                ..Default::default()
            };
            let caps = gst_backend.create_caps(&a_law_params).unwrap();
            let caps_str = caps.to_string();
            assert!(caps_str.contains("audio/x-alaw"));
        }
    }

    // `GStreamerTestHarness` modifies the process's environment, so this test should
    // be executed on a forked process.
    rusty_fork_test! {
        #[test]
        fn test_gstreamer_caps_creation() {
            crate::init_logger();
            let stream_params = Arc::new(RwLock::new(vec![Stream::default()]));

            let _test_harness = GStreamerTestHarness::new();

            let gst_backend = GStreamerBackend::new(stream_params).unwrap();

            // Test different audio formats
            let test_cases = vec![
                (VIRTIO_SND_PCM_FMT_S16, VIRTIO_SND_PCM_RATE_44100, 2),
                (VIRTIO_SND_PCM_FMT_S32, VIRTIO_SND_PCM_RATE_48000, 1),
                (VIRTIO_SND_PCM_FMT_FLOAT, VIRTIO_SND_PCM_RATE_96000, 6),
                (VIRTIO_SND_PCM_FMT_S24, VIRTIO_SND_PCM_RATE_192000, 4),
            ];

            for (format, rate, channels) in test_cases {
                let params = PcmParams {
                    format,
                    rate,
                    channels,
                    ..Default::default()
                };
                let caps = gst_backend.create_caps(&params).unwrap();
                assert!(!caps.is_empty());

                // Verify caps structure
                let structure = caps.structure(0).unwrap();
                assert!(structure.has_field("channels"));
                assert!(structure.has_field("rate"));
            }
        }
    }

    // `GStreamerTestHarness` modifies the process's environment, so this test should
    // be executed on a forked process.
    rusty_fork_test! {
        #[test]
        fn test_gstreamer_all_supported_formats() {
            crate::init_logger();
            let stream_params = Arc::new(RwLock::new(vec![Stream::default()]));

            let _test_harness = GStreamerTestHarness::new();

            let gst_backend = GStreamerBackend::new(stream_params).unwrap();

            // Test all supported audio formats
            let formats = vec![
                VIRTIO_SND_PCM_FMT_S8,
                VIRTIO_SND_PCM_FMT_U8,
                VIRTIO_SND_PCM_FMT_S16,
                VIRTIO_SND_PCM_FMT_U16,
                VIRTIO_SND_PCM_FMT_S18_3,
                VIRTIO_SND_PCM_FMT_U18_3,
                VIRTIO_SND_PCM_FMT_S20_3,
                VIRTIO_SND_PCM_FMT_U20_3,
                VIRTIO_SND_PCM_FMT_S24_3,
                VIRTIO_SND_PCM_FMT_U24_3,
                VIRTIO_SND_PCM_FMT_S20,
                VIRTIO_SND_PCM_FMT_U20,
                VIRTIO_SND_PCM_FMT_S24,
                VIRTIO_SND_PCM_FMT_U24,
                VIRTIO_SND_PCM_FMT_S32,
                VIRTIO_SND_PCM_FMT_U32,
                VIRTIO_SND_PCM_FMT_FLOAT,
                VIRTIO_SND_PCM_FMT_FLOAT64,
            ];

            for format in formats {
                let params = PcmParams {
                    format,
                    rate: VIRTIO_SND_PCM_RATE_44100,
                    channels: 2,
                    ..Default::default()
                };
                let audio_format = gst_backend.set_format(&params).unwrap();
                assert_ne!(audio_format, AudioFormat::Unknown);

                let caps = gst_backend.create_caps(&params).unwrap();
                assert!(!caps.is_empty());
            }
        }
    }

    // `GStreamerTestHarness` modifies the process's environment, so this test should
    // be executed on a forked process.
    rusty_fork_test! {
        #[test]
        fn test_gstreamer_all_supported_rates() {
            crate::init_logger();
            let stream_params = Arc::new(RwLock::new(vec![Stream::default()]));

            let _test_harness = GStreamerTestHarness::new();

            let gst_backend = GStreamerBackend::new(stream_params).unwrap();

            // Test all supported sample rates
            let rates = vec![
                VIRTIO_SND_PCM_RATE_5512,
                VIRTIO_SND_PCM_RATE_8000,
                VIRTIO_SND_PCM_RATE_11025,
                VIRTIO_SND_PCM_RATE_12000,
                VIRTIO_SND_PCM_RATE_16000,
                VIRTIO_SND_PCM_RATE_22050,
                VIRTIO_SND_PCM_RATE_24000,
                VIRTIO_SND_PCM_RATE_32000,
                VIRTIO_SND_PCM_RATE_44100,
                VIRTIO_SND_PCM_RATE_48000,
                VIRTIO_SND_PCM_RATE_64000,
                VIRTIO_SND_PCM_RATE_88200,
                VIRTIO_SND_PCM_RATE_96000,
                VIRTIO_SND_PCM_RATE_176400,
                VIRTIO_SND_PCM_RATE_192000,
                VIRTIO_SND_PCM_RATE_384000,
            ];

            for rate in rates {
                let params = PcmParams {
                    format: VIRTIO_SND_PCM_FMT_S16,
                    rate,
                    channels: 2,
                    ..Default::default()
                };
                let caps = gst_backend.create_caps(&params).unwrap();
                assert!(!caps.is_empty());

                let structure = caps.structure(0).unwrap();
                assert!(structure.has_field("rate"));
            }
        }
    }

    // `GStreamerTestHarness` modifies the process's environment, so this test should
    // be executed on a forked process.
    rusty_fork_test! {
        #[test]
        fn test_gstreamer_unknown_format() {
            crate::init_logger();
            let stream_params = Arc::new(RwLock::new(vec![Stream::default()]));

            let _test_harness = GStreamerTestHarness::new();

            let gst_backend = GStreamerBackend::new(stream_params).unwrap();

            // Test unknown format (using invalid format value)
            let params = PcmParams {
                format: 255,
                rate: VIRTIO_SND_PCM_RATE_44100,
                channels: 2,
                ..Default::default()
            };
            let audio_format = gst_backend.set_format(&params).unwrap();
            assert_eq!(audio_format, AudioFormat::Unknown);
        }
    }

    // `GStreamerTestHarness` modifies the process's environment, so this test should
    // be executed on a forked process.
    rusty_fork_test! {
        #[test]
        fn test_gstreamer_unknown_rate() {
            crate::init_logger();
            let stream_params = Arc::new(RwLock::new(vec![Stream::default()]));

            let _test_harness = GStreamerTestHarness::new();

            let gst_backend = GStreamerBackend::new(stream_params).unwrap();

            let params = PcmParams {
                format: VIRTIO_SND_PCM_FMT_S16,
                rate: 255,
                channels: 2,
                ..Default::default()
            };
            let caps = gst_backend.create_caps(&params).unwrap();
            assert!(!caps.is_empty());

            let structure = caps.structure(0).unwrap();
            let rate: i32 = structure.get("rate").unwrap();
            assert_eq!(rate, 44100);
        }
    }

    // `GStreamerTestHarness` modifies the process's environment, so this test should
    // be executed on a forked process.
    rusty_fork_test! {
        #[test]
        fn test_gstreamer_multiple_prepare_release_cycles() {
            crate::init_logger();
            let stream_params = Arc::new(RwLock::new(vec![Stream::default()]));

            let _test_harness = GStreamerTestHarness::new();

            let gst_backend = GStreamerBackend::new(stream_params).unwrap();

            let request = VirtioSndPcmSetParams {
                format: VIRTIO_SND_PCM_FMT_S16,
                rate: VIRTIO_SND_PCM_RATE_44100,
                channels: 2,
                ..Default::default()
            };

            // Test multiple prepare/release cycles
            for _ in 0..3 {
                gst_backend.set_parameters(0, request).unwrap();
                gst_backend.prepare(0).unwrap();
                gst_backend.release(0).unwrap();
            }
        }
    }

    // `GStreamerTestHarness` modifies the process's environment, so this test should
    // be executed on a forked process.
    rusty_fork_test! {
        #[test]
        fn test_gstreamer_different_channel_counts() {
            crate::init_logger();
            let stream_params = Arc::new(RwLock::new(vec![Stream::default()]));

            let _test_harness = GStreamerTestHarness::new();

            let gst_backend = GStreamerBackend::new(stream_params).unwrap();

            // Test different channel counts
            let channel_counts = vec![1, 2, 4, 6, 8];

            for channels in channel_counts {
                let params = PcmParams {
                    format: VIRTIO_SND_PCM_FMT_S16,
                    rate: VIRTIO_SND_PCM_RATE_44100,
                    channels,
                    ..Default::default()
                };
                let caps = gst_backend.create_caps(&params).unwrap();
                assert!(!caps.is_empty());

                let structure = caps.structure(0).unwrap();
                let caps_channels: i32 = structure.get("channels").unwrap();
                assert_eq!(caps_channels, i32::from(channels))
            }
        }
    }

    // `GStreamerTestHarness` modifies the process's environment, so this test should
    // be executed on a forked process.
    rusty_fork_test! {
        #[test]
        fn test_gstreamer_all_3byte_formats() {
            crate::init_logger();
            let stream_params = Arc::new(RwLock::new(vec![Stream::default()]));

            let _test_harness = GStreamerTestHarness::new();

            let gst_backend = GStreamerBackend::new(stream_params).unwrap();

            // Test all 3-byte formats
            let formats_3byte = vec![
                VIRTIO_SND_PCM_FMT_S18_3,
                VIRTIO_SND_PCM_FMT_U18_3,
                VIRTIO_SND_PCM_FMT_S20_3,
                VIRTIO_SND_PCM_FMT_U20_3,
                VIRTIO_SND_PCM_FMT_S24_3,
                VIRTIO_SND_PCM_FMT_U24_3,
            ];

            for format in formats_3byte {
                let params = PcmParams {
                    format,
                    rate: VIRTIO_SND_PCM_RATE_48000,
                    channels: 2,
                    ..Default::default()
                };
                let audio_format = gst_backend.set_format(&params).unwrap();
                assert_ne!(audio_format, AudioFormat::Unknown);

                let caps = gst_backend.create_caps(&params).unwrap();
                assert!(!caps.is_empty());
            }
        }
    }

    // `GStreamerTestHarness` modifies the process's environment, so this test should
    // be executed on a forked process.
    #[cfg(target_endian = "little")]
    rusty_fork_test! {
        #[test]
        fn test_gstreamer_little_endian_formats() {
            crate::init_logger();
            let stream_params = Arc::new(RwLock::new(vec![Stream::default()]));

            let _test_harness = GStreamerTestHarness::new();

            let gst_backend = GStreamerBackend::new(stream_params).unwrap();

            // Test little endian specific format mapping
            let params = PcmParams {
                format: VIRTIO_SND_PCM_FMT_S16,
                rate: VIRTIO_SND_PCM_RATE_44100,
                channels: 2,
                ..Default::default()
            };
            let audio_format = gst_backend.set_format(&params).unwrap();
            assert_eq!(audio_format, AudioFormat::S16le);

            let params = PcmParams {
                format: VIRTIO_SND_PCM_FMT_FLOAT,
                rate: VIRTIO_SND_PCM_RATE_44100,
                channels: 2,
                ..Default::default()
            };
            let audio_format = gst_backend.set_format(&params).unwrap();
            assert_eq!(audio_format, AudioFormat::F32le);
        }
    }

    // `GStreamerTestHarness` modifies the process's environment, so this test should
    // be executed on a forked process.
    #[cfg(target_endian = "big")]
    rusty_fork_test! {
        #[test]
        fn test_gstreamer_big_endian_formats() {
            crate::init_logger();
            let stream_params = Arc::new(RwLock::new(vec![Stream::default()]));

            let _test_harness = GStreamerTestHarness::new();

            let gst_backend = GStreamerBackend::new(stream_params).unwrap();

            // Test big endian specific format mapping
            let params = PcmParams {
                format: VIRTIO_SND_PCM_FMT_S16,
                rate: VIRTIO_SND_PCM_RATE_44100,
                channels: 2,
                ..Default::default()
            };
            let audio_format = gst_backend.set_format(&params).unwrap();
            assert_eq!(audio_format, AudioFormat::S16be);

            let params = PcmParams {
                format: VIRTIO_SND_PCM_FMT_FLOAT,
                rate: VIRTIO_SND_PCM_RATE_44100,
                channels: 2,
                ..Default::default()
            };
            let audio_format = gst_backend.set_format(&params).unwrap();
            assert_eq!(audio_format, AudioFormat::F32be);
        }
    }
}
