use std::sync::{Arc, RwLock};

use gst::{Pipeline,prelude::*};
use gst_app::{AppSink, AppSrc};
use gst_audio::{AudioInfo, AudioFormat};

use crate::{
    stream::{Error as StreamError, PCMState},
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
    Stream, Error, Result,
}; 

use super::AudioBackend;

pub struct GStreamerBackend {
    stream_params: Arc<RwLock<Vec<Stream>>>,
    appsrc: AppSrc,
    appsink: AppSink,
    pipeline: Pipeline,
}

impl GStreamerBackend {
    pub fn new(stream_params: Arc<RwLock<Vec<Stream>>>) -> Self {
        // init GStreamer
        log::debug!("Initializing GStreamer backend");

        gst::init().expect("Failed to initialize GStreamer");

        // create GStreamer elements
        let pipeline = gst::Pipeline::with_name("audio_pipeline");

        let appsrc = gst_app::AppSrc::builder()
            .name("audio_appsrc")
            .caps(&gst::Caps::new_any())
            .build();

        let audioconvert = gst::ElementFactory::make("audioconvert")
            .name("audioconvert")
            .build()
            .unwrap();

        let audioresample = gst::ElementFactory::make("audioresample")
            .name("audioresample")
            .build()
            .unwrap();
        let autoaudiosink = gst::ElementFactory::make("autoaudiosink")
            .name("autoaudiosink")
            .build()
            .unwrap();

        // maybe no use
        let appsink = gst_app::AppSink::builder()
            .name("audio_appsink")
            .caps(&gst::Caps::new_any())
            .build();

        pipeline
            .add_many(&[appsrc.upcast_ref(), &audioconvert, &audioresample, &autoaudiosink])
            .expect("Failed to add elements to pipeline");

        gst::Element::link_many(&[appsrc.upcast_ref(), &audioconvert, &audioresample, &autoaudiosink])
            .expect("Failed to link elements");

        GStreamerBackend {
            stream_params: stream_params,
            appsrc,
            appsink,
            pipeline,
        }
    }

}

impl AudioBackend for GStreamerBackend {
    // TODO
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
        log::debug!("PipewireBackend read stream_id {}", stream_id);
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
        log::debug!("Setting parameters for stream {}", stream_id);
        log::debug!("Request: {:?}", request);
        log::debug!("Stream parameters: {:?}", self.stream_params);
        let stream_clone = self.stream_params.clone();
        let mut stream_params = stream_clone.write().unwrap();
        if let Some(st) = stream_params.get_mut(stream_id as usize) {
            if let Err(err) = st.state.set_parameters() {
                log::error!("Stream {} set_parameters {}", stream_id, err);
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
        log::debug!("Stream parameters after set: {:?}", stream_params);

        Ok(())
    }
    fn prepare(&self, stream_id: u32) -> Result<()> {
        log::debug!("Preparing stream {}", stream_id);
        let prepare_result = self
            .stream_params
            .write()
            .unwrap()
            .get_mut(stream_id as usize)
            .ok_or(Error::StreamWithIdNotFound(stream_id))?
            .state
            .prepare();
        if let Err(err) = prepare_result {
            log::error!("Stream {} prepare {}", stream_id, err);
            return Err(Error::Stream(err));
        } else {
            log::debug!("Stream {} prepared successfully", stream_id);
            let stream_params = self.stream_params.read().unwrap();
            let params = &stream_params[stream_id as usize].params;
        
            let channels = params.channels as u32;
            let format = match params.format {
                VIRTIO_SND_PCM_FMT_MU_LAW => AudioFormat::Encoded, // TODO
                VIRTIO_SND_PCM_FMT_A_LAW => AudioFormat::Encoded,  // TODO
                VIRTIO_SND_PCM_FMT_S8 => AudioFormat::S8,
                VIRTIO_SND_PCM_FMT_U8 => AudioFormat::U8,
                VIRTIO_SND_PCM_FMT_S16 => AudioFormat::S16le,
                VIRTIO_SND_PCM_FMT_U16 => AudioFormat::U16le,
                VIRTIO_SND_PCM_FMT_S18_3 => AudioFormat::S18le, // TODO
                VIRTIO_SND_PCM_FMT_U18_3 => AudioFormat::U18le, // TODO
                VIRTIO_SND_PCM_FMT_S20 => AudioFormat::S20le,
                VIRTIO_SND_PCM_FMT_U20 => AudioFormat::U20le,
                VIRTIO_SND_PCM_FMT_S20_3 => AudioFormat::S20le, // TODO
                VIRTIO_SND_PCM_FMT_U20_3 => AudioFormat::U20le, // TODO
                VIRTIO_SND_PCM_FMT_S24 => AudioFormat::S24le,
                VIRTIO_SND_PCM_FMT_U24 => AudioFormat::U24le,
                VIRTIO_SND_PCM_FMT_S24_3 => AudioFormat::S24le, // TODO
                VIRTIO_SND_PCM_FMT_U24_3 => AudioFormat::U24le, // TODO
                VIRTIO_SND_PCM_FMT_S32 => AudioFormat::S32le,
                VIRTIO_SND_PCM_FMT_U32 => AudioFormat::U32le,
                VIRTIO_SND_PCM_FMT_FLOAT => AudioFormat::F32le,
                VIRTIO_SND_PCM_FMT_FLOAT64 => AudioFormat::F64le,
                _ => AudioFormat::Unknown,
            };

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

            let audio_info = AudioInfo::builder(format, rate, channels)
                .build()
                .expect("Failed to create AudioInfo");

            let caps = audio_info.to_caps().expect("Failed to convert AudioInfo to Caps");
            self.appsrc.set_caps(Some(&caps));

        }
        Ok(())
    }

    fn release(&self, stream_id: u32) -> Result<()> {
        log::debug!("Releasing stream {}", stream_id);
        Ok(())
    }
    fn start(&self, stream_id: u32) -> Result<()> {
        log::debug!("Starting stream {}", stream_id);
        Ok(())
    }
    fn stop(&self, stream_id: u32) -> Result<()> {
        log::debug!("Stopping stream {}", stream_id);
        Ok(())
    }

    #[cfg(test)]
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}
