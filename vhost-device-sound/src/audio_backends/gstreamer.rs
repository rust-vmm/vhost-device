use std::sync::{Arc, RwLock};

use gst::prelude::*;
use gst::{Pipeline};
use gst_app::{AppSink, AppSrc};

use crate::{
    stream::{Error as StreamError, PCMState},
    Stream,
    Error, Result,VirtioSndPcmSetParams,
}; // 假设你已有这些定义

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
        log::trace!("Initializing GStreamer backend");

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

        // set appsrc caps to PCM audio format (a test)
        let audio_caps = gst::Caps::builder("audio/x-raw")
            .field("format", &"S16LE")
            .field("channels", &2i32)
            .field("rate", &48000i32)
            .build();
        appsrc.set_caps(Some(&audio_caps));
        // appsrc.set_property_format(gst::Format::Time);

        pipeline
            .set_state(gst::State::Playing)
            .expect("Unable to set pipeline to playing");

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
        log::trace!("PipewireBackend read stream_id {}", stream_id);
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
        log::trace!("Setting parameters for stream {}", stream_id);
        log::trace!("Request: {:?}", request);
        log::trace!("Stream parameters: {:?}", self.stream_params);
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
        log::trace!("Stream parameters after set: {:?}", stream_params);

        Ok(())
    }
    fn prepare(&self, _stream_id: u32) -> Result<()> {
        log::trace!("Preparing stream {}", _stream_id);
        Ok(())
    }
    fn release(&self, _stream_id: u32) -> Result<()> {
        log::trace!("Releasing stream {}", _stream_id);
        Ok(())
    }
    fn start(&self, _stream_id: u32) -> Result<()> {
        log::trace!("Starting stream {}", _stream_id);
        Ok(())
    }
    fn stop(&self, _stream_id: u32) -> Result<()> {
        log::trace!("Stopping stream {}", _stream_id);
        Ok(())
    }

    #[cfg(test)]
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}
