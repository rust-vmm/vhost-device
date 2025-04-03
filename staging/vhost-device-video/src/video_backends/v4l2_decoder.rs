// SPDX-License-Identifier: Apache-2.0 or BSD-3-Clause
use std::{collections::HashMap, fs::File, io, os::unix::io::AsRawFd, path::Path};

use log::{debug, warn};
use v4l2r::{
    bindings::{
        v4l2_fmtdesc, v4l2_format, v4l2_frmivalenum, v4l2_frmsizeenum, v4l2_queryctrl, v4l2_rect,
    },
    PixelFormat, PlaneLayout,
};
use vm_memory::Le32;

use super::{DqBufData, VideoBackend};
use crate::{
    stream,
    video::{
        self,
        CmdError::*,
        CmdResponseType::{AsyncQueue, Sync},
        InitFromValue, ToVirtio,
    },
};

pub(crate) trait ToV4L2 {
    fn to_v4l2(&self) -> u32;
}

struct FilePath {
    _file: File,
    _path: Box<Path>,
}

impl AsRawFd for FilePath {
    fn as_raw_fd(&self) -> i32 {
        self._file.as_raw_fd()
    }
}

impl FilePath {
    fn new(video_path: &Path) -> io::Result<Self> {
        Ok(Self {
            _file: File::create(video_path)?,
            _path: video_path.into(),
        })
    }

    fn path(&self) -> &Path {
        &self._path
    }
}

impl ToVirtio for PixelFormat {
    fn to_virtio(&self) -> Le32 {
        match self.to_string().as_str() {
            "ABGR" => (video::Format::Argb8888 as u32).into(),
            "NV12" => (video::Format::Nv12 as u32).into(),
            "YU12" => (video::Format::Yuv420 as u32).into(),
            "YV12" => (video::Format::Yvu420 as u32).into(),
            "MPG2" => (video::Format::Mpeg2 as u32).into(),
            "MPG4" => (video::Format::Mpeg4 as u32).into(),
            "H264" => (video::Format::H264 as u32).into(),
            "HEVC" => (video::Format::Hevc as u32).into(),
            "VP80" => (video::Format::Vp8 as u32).into(),
            "VP90" => (video::Format::Vp9 as u32).into(),
            "FWHT" => (video::Format::Fwht as u32).into(),
            _ => 0.into(),
        }
    }
}

impl InitFromValue<u32> for v4l2r::QueueType {
    fn from_value(value: u32) -> Option<Self> {
        match value {
            video::VIRTIO_VIDEO_QUEUE_TYPE_INPUT => Some(v4l2r::QueueType::VideoOutputMplane),
            video::VIRTIO_VIDEO_QUEUE_TYPE_OUTPUT => Some(v4l2r::QueueType::VideoCaptureMplane),
            _ => None,
        }
    }
}

impl ToVirtio for v4l2r::QueueType {
    fn to_virtio(&self) -> Le32 {
        match self {
            v4l2r::QueueType::VideoCaptureMplane => video::VIRTIO_VIDEO_QUEUE_TYPE_OUTPUT.into(),
            v4l2r::QueueType::VideoOutputMplane => video::VIRTIO_VIDEO_QUEUE_TYPE_INPUT.into(),
            _ => 0.into(),
        }
    }
}

impl ToV4L2 for video::QueueType {
    fn to_v4l2(&self) -> u32 {
        match self {
            video::QueueType::OutputQueue => v4l2r::QueueType::VideoCaptureMplane as u32,
            video::QueueType::InputQueue => v4l2r::QueueType::VideoOutputMplane as u32,
        }
    }
}

impl ToV4L2 for video::MemoryType {
    fn to_v4l2(&self) -> u32 {
        match self {
            Self::GuestPages => v4l2r::bindings::v4l2_memory_V4L2_MEMORY_USERPTR,
            Self::VirtioObject => v4l2r::bindings::v4l2_memory_V4L2_MEMORY_DMABUF,
        }
    }
}

impl ToV4L2 for video::ControlType {
    fn to_v4l2(&self) -> u32 {
        match self {
            Self::Bitrate => v4l2r::bindings::V4L2_CID_MPEG_VIDEO_BITRATE,
            Self::BitratePeak => v4l2r::bindings::V4L2_CID_MPEG_VIDEO_BITRATE_PEAK,
            Self::BitrateMode => v4l2r::bindings::V4L2_CID_MPEG_VIDEO_BITRATE_MODE,
            Self::Profile => v4l2r::bindings::V4L2_CID_MPEG_VIDEO_H264_PROFILE,
            Self::Level => v4l2r::bindings::V4L2_CID_MPEG_VIDEO_H264_LEVEL,
            Self::ForceKeyframe => v4l2r::bindings::V4L2_CID_MPEG_VIDEO_FORCE_KEY_FRAME,
            Self::PrependSpsPpsToIdr => v4l2r::bindings::V4L2_CID_MPEG_VIDEO_PREPEND_SPSPPS_TO_IDR,
        }
    }
}

impl ToVirtio for v4l2r::ioctl::BufferFlags {
    fn to_virtio(&self) -> Le32 {
        let mut flags = video::BufferFlags::default();
        if self.contains(v4l2r::ioctl::BufferFlags::ERROR) {
            flags.insert(video::BufferFlags::ERR);
        }
        if self.contains(v4l2r::ioctl::BufferFlags::LAST) {
            flags.insert(video::BufferFlags::EOS);
        }
        flags.into()
    }
}

impl video::virtio_video_format_desc {
    fn as_virtio_format(&mut self, pixelformat: u32) {
        self.format = PixelFormat::from(pixelformat).to_virtio();
        self.planes_layout = video::VIRTIO_VIDEO_PLANES_LAYOUT_SINGLE_BUFFER.into();
    }
}

impl From<v4l2_frmsizeenum> for video::virtio_video_format_frame {
    fn from(frame: v4l2_frmsizeenum) -> Self {
        match frame.size() {
            Some(v4l2r::ioctl::FrmSizeTypes::Discrete(size)) => Self {
                width: size.width.into(),
                length: size.height.into(),
                num_rates: 0.into(),
                padding: 0.into(),
                frame_rates: Vec::new(),
            },
            Some(v4l2r::ioctl::FrmSizeTypes::StepWise(size)) => Self {
                width: video::virtio_video_format_range {
                    min: size.min_width.into(),
                    max: size.max_width.into(),
                    step: size.step_width.into(),
                    padding: 0.into(),
                },
                length: video::virtio_video_format_range {
                    min: size.min_height.into(),
                    max: size.max_height.into(),
                    step: size.step_height.into(),
                    padding: 0.into(),
                },
                num_rates: 0.into(),
                padding: 0.into(),
                frame_rates: Vec::new(),
            },
            None => {
                warn!("Unexpected frame type: {}", frame.type_);
                Self::default()
            }
        }
    }
}

impl From<v4l2_frmivalenum> for video::virtio_video_format_range {
    fn from(ival: v4l2_frmivalenum) -> Self {
        let mut frate = video::virtio_video_format_range::default();
        match ival.intervals() {
            Some(v4l2r::ioctl::FrmIvalTypes::Discrete(fract)) => {
                frate.min = fract.denominator.into()
            }
            Some(v4l2r::ioctl::FrmIvalTypes::StepWise(interval)) => {
                frate.min = interval.min.denominator.into();
                frate.max = interval.max.denominator.into();
                if ival.type_ == v4l2r::bindings::v4l2_frmivaltypes_V4L2_FRMIVAL_TYPE_CONTINUOUS {
                    frate.step = 1.into();
                } else {
                    frate.step = interval.step.denominator.into();
                }
            }
            None => warn!("Unexpected ival type: {}", ival.type_),
        }
        frate
    }
}

fn process_timestamp(timestamp: u64) -> (i64, i64) {
    let n_per_sec: i64 = 1_000_000_000;
    let tv_sec: i64 = timestamp as i64 / n_per_sec;
    let nsec: i64 = tv_sec * n_per_sec;
    let tv_usec: i64 = (timestamp as i64 - nsec) / 1_000;
    (tv_sec, tv_usec)
}

pub struct V4L2Decoder {
    streams: HashMap<u32, stream::Stream>,
    video_device: FilePath,
}

impl VideoBackend for V4L2Decoder {
    fn stream(&self, stream_id: &u32) -> Option<&stream::Stream> {
        self.streams.get(stream_id)
    }

    fn stream_mut(&mut self, stream_id: &u32) -> Option<&mut stream::Stream> {
        self.streams.get_mut(stream_id)
    }

    fn create_stream(
        &mut self,
        stream_id: u32,
        in_memory_type: u32,
        out_memory_type: u32,
        coded_format: u32,
    ) -> video::CmdResponseType {
        let stream = match stream::Stream::new(
            stream_id,
            self.video_device.path(),
            in_memory_type,
            out_memory_type,
            coded_format,
        ) {
            Ok(s) => s,
            Err(e) => {
                warn!("{}", e);
                return Sync(video::CmdResponse::Error(InvalidParameter));
            }
        };
        self.streams.insert(stream_id, stream);
        Sync(video::CmdResponse::OkNoData)
    }

    fn destroy_stream(&mut self, stream_id: u32) -> video::CmdResponseType {
        self.streams.remove(&stream_id);
        Sync(video::CmdResponse::OkNoData)
    }

    fn queue_resource(
        &mut self,
        stream_id: u32,
        queue_type: video::QueueType,
        resource_id: u32,
        timestamp: u64,
        bytes_used: Vec<u32>,
    ) -> video::CmdResponseType {
        let stream = match self.streams.get_mut(&stream_id) {
            Some(stream) => stream,
            None => {
                return Sync(video::CmdResponse::Error(InvalidStreamId));
            }
        };
        // Clone stream to burrow the fd as inmutable
        let fd = stream.clone().file;
        let memory_type = stream.memory(queue_type);
        let queue = v4l2r::QueueType::from_value(queue_type as u32).unwrap();
        let bufcount = match queue_type {
            video::QueueType::InputQueue => stream.inputq_resources.map.len(),
            video::QueueType::OutputQueue => stream.outputq_resources.map.len(),
        };
        let all_created = stream.all_created(queue_type);
        let res = match stream.find_resource_mut(resource_id, queue_type) {
            Some(resource) => resource,
            None => {
                warn!("Invalid resource if: {}", resource_id);
                return Sync(video::CmdResponse::Error(InvalidParameter));
            }
        };
        if bufcount > 0 && all_created {
            if !Self::v4l2_request_buffers(&fd, queue_type, memory_type, bufcount as u32) {
                return Sync(video::CmdResponse::Error(InvalidParameter));
            }
            res.set_queried();
        }

        if res.planes.len() != bytes_used.len() {
            warn!("Number of planes mismatch");
            return Sync(video::CmdResponse::Error(InvalidParameter));
        }
        res.buffer_data.write().unwrap().timestamp = timestamp;
        // Assumes UserPtrHandle
        if memory_type == video::MemoryType::VirtioObject {
            warn!("Virtio Object Memory NOT YET supported");
            return Sync(video::CmdResponse::Error(InvalidParameter));
        }
        if !Self::v4l2_queue_buffer(&fd, queue_type, timestamp, res) {
            return Sync(video::CmdResponse::Error(InvalidParameter));
        }
        res.set_queued();
        if stream.state() == stream::StreamState::Stopped {
            if let Err(e) = v4l2r::ioctl::subscribe_event(
                stream,
                v4l2r::ioctl::EventType::SourceChange(0),
                v4l2r::ioctl::SubscribeEventFlags::empty(),
            ) {
                warn!("subscribe_event failed: {}", e);
            }

            if let Err(e) = v4l2r::ioctl::subscribe_event(
                stream,
                v4l2r::ioctl::EventType::Eos,
                v4l2r::ioctl::SubscribeEventFlags::empty(),
            ) {
                warn!("subscribe_event failed: {}", e);
            }
            stream.set_state(stream::StreamState::Subscribed);
        }

        if stream::StreamState::Draining != stream.state() && !stream.is_queue_streaming(queue_type)
        {
            if let Err(e) = v4l2r::ioctl::streamon(stream, queue) {
                warn!("streamon failed: {}", e);
            }
            stream.set_queue_streaming(queue_type);
            stream.set_state(stream::StreamState::Streaming);
        }

        AsyncQueue {
            stream_id: stream.stream_id,
            queue_type,
            resource_id,
        }
    }

    fn query_capability(&self, queue_type: video::QueueType) -> video::CmdResponseType {
        let mut index: u32 = 0;
        let mut desc_list: Vec<video::virtio_video_format_desc> = Vec::new();
        while let Some(fmtdesc) = self.v4l2_enum_formats(queue_type, index) {
            if index != fmtdesc.index {
                warn!("v4l2 driver modified index {}", fmtdesc.index);
            }

            let format = PixelFormat::from(fmtdesc.pixelformat);
            if format.to_virtio() == 0 {
                debug!(
                    "Unsupported format for virtio-video ({}), skipping.",
                    format
                );
                index += 1;
                continue;
            }

            let mut desc = video::virtio_video_format_desc::default();
            desc.append_frames(&mut self.video_enum_frame_sizes(fmtdesc.pixelformat));
            desc.as_virtio_format(fmtdesc.pixelformat);
            desc_list.push(desc);
            index += 1;
        }

        debug!("Enumerated {} formats:", desc_list.len());
        let num_formats = desc_list.len();
        for desc in &mut desc_list {
            desc.generate_mask(num_formats);
            debug!("{:?}", desc);
        }

        Sync(video::CmdResponse::QueryCapability(desc_list))
    }

    fn query_control(&self, control: video::ControlType) -> video::CmdResponseType {
        let queryctrl: v4l2_queryctrl = match self.v4l2_query_control(control) {
            Some(queryctrl) => queryctrl,
            None => {
                return Sync(video::CmdResponse::Error(UnsupportedControl));
            }
        };

        Sync(video::CmdResponse::QueryControl(
            video::VideoControl::new_from_type(control, queryctrl.type_.into()),
        ))
    }

    fn clear_queue(
        &mut self,
        stream_id: u32,
        queue_type: video::QueueType,
    ) -> video::CmdResponseType {
        let stream = match self.streams.get_mut(&stream_id) {
            Some(stream) => stream,
            None => {
                return Sync(video::CmdResponse::Error(InvalidStreamId));
            }
        };
        let queue = v4l2r::QueueType::from_value(queue_type as u32).unwrap();
        // send replies for all in-flight buffers
        for resource in stream.queued_resources_mut(queue_type) {
            resource.ready_with(video::BufferFlags::ERR, 0);
        }
        /*
         * QUEUE_CLEAR behaviour from virtio-video spec
         * Return already queued buffers back from the input or the output queue
         * of the device. The device SHOULD return all of the buffers from the
         * respective queue as soon as possible without pushing the buffers through
         * the processing pipeline.
         *
         * From v4l2 PoV we issue a VIDIOC_STREAMOFF on the queue which will abort
         * or finish any DMA in progress, unlocks any user pointer buffers locked
         * in physical memory, and it removes all buffers from the incoming and
         * outgoing queues.
         */
        if let Err(e) = v4l2r::ioctl::streamoff(stream, queue) {
            warn!("streamoff failed: {}", e);
            return Sync(video::CmdResponse::Error(InvalidParameter));
        }

        Sync(video::CmdResponse::OkNoData)
    }

    fn get_params(&self, stream_id: u32, queue_type: video::QueueType) -> video::CmdResponseType {
        let stream = match self.streams.get(&stream_id) {
            Some(stream) => stream,
            None => {
                return Sync(video::CmdResponse::Error(InvalidStreamId));
            }
        };
        let mut params = video::virtio_video_params::default();
        let format = match Self::v4l2_get_format(stream, queue_type) {
            Some(format) => format,
            None => {
                return Sync(video::CmdResponse::Error(InvalidParameter));
            }
        };

        params.queue_type = (queue_type as u32).into();
        params.min_buffers = 1.into();
        params.max_buffers = 32.into();
        // SAFETY: The member of the union that gets initialised is determined
        // by the implementation, as it only supports multiplanar video devices.
        let pix_fmt = unsafe { &format.fmt.pix_mp };
        params.format = PixelFormat::from(pix_fmt.pixelformat).to_virtio();
        params.frame_width = pix_fmt.width.into();
        params.frame_heigth = pix_fmt.height.into();
        params.num_planes = (pix_fmt.num_planes as u32).into();

        for i in 0..pix_fmt.num_planes {
            params.plane_formats[i as usize].stride =
                pix_fmt.plane_fmt[i as usize].bytesperline.into();
            params.plane_formats[i as usize].plane_size =
                pix_fmt.plane_fmt[i as usize].sizeimage.into();
        }
        let queue = v4l2r::QueueType::from_value(queue_type as u32).unwrap();
        if queue.direction() == v4l2r::QueueDirection::Capture {
            if let Some(sel) = Self::v4l2_get_selection(stream, queue_type) {
                params.crop.left = (sel.left as u32).into();
                params.crop.top = (sel.top as u32).into();
                params.crop.width = sel.width.into();
                params.crop.heigth = sel.height.into();
            }
        }

        Sync(video::CmdResponse::GetParams { queue_type, params })
    }

    fn set_params(
        &mut self,
        stream_id: u32,
        params: video::virtio_video_params,
    ) -> video::CmdResponseType {
        let stream = match self.streams.get_mut(&stream_id) {
            Some(stream) => stream,
            None => {
                return Sync(video::CmdResponse::Error(InvalidStreamId));
            }
        };
        let queue_type = v4l2r::QueueType::from_value(params.queue_type.into()).unwrap();
        let mut format = v4l2r::Format {
            width: params.frame_width.into(),
            height: params.frame_heigth.into(),
            pixelformat: PixelFormat::from(<Le32 as Into<u32>>::into(params.format)),
            ..Default::default()
        };
        for plane_fmt in params.plane_formats {
            format.plane_fmt.push(PlaneLayout {
                sizeimage: plane_fmt.plane_size.into(),
                bytesperline: plane_fmt.stride.into(),
            })
        }
        if let Err(e) = v4l2r::ioctl::s_fmt::<_, v4l2r::Format>(stream, (queue_type, &format)) {
            warn!("s_fmt failed: {}", e);
            return Sync(video::CmdResponse::Error(InvalidParameter));
        };

        /*if queue_type.direction() == v4l2r::QueueDirection::Capture {
            todo!("compose on CAPTURE");
        }*/

        Sync(video::CmdResponse::OkNoData)
    }

    fn create_resource(
        &mut self,
        stream_id: u32,
        resource_id: u32,
        planes_layout: u32,
        planes: Vec<stream::ResourcePlane>,
        queue_type: video::QueueType,
    ) -> video::CmdResponseType {
        let stream = match self.streams.get_mut(&stream_id) {
            Some(stream) => stream,
            None => {
                return Sync(video::CmdResponse::Error(InvalidStreamId));
            }
        };
        if stream.find_resource(resource_id, queue_type).is_some() {
            return Sync(video::CmdResponse::Error(InvalidResourceId));
        }
        if planes_layout == video::VIRTIO_VIDEO_PLANES_LAYOUT_SINGLE_BUFFER {
            stream.add_resource(resource_id, planes_layout, planes, queue_type);
        } else {
            todo!();
        }
        Sync(video::CmdResponse::OkNoData)
    }

    fn destroy_resources(
        &mut self,
        stream_id: u32,
        queue_type: video::QueueType,
    ) -> video::CmdResponseType {
        let stream = match self.streams.get_mut(&stream_id) {
            Some(stream) => stream,
            None => {
                return Sync(video::CmdResponse::Error(InvalidStreamId));
            }
        };
        let memory_type = stream.memory(queue_type);
        let memory = v4l2r::memory::MemoryType::n(memory_type.to_v4l2()).unwrap();
        let queue = v4l2r::QueueType::from_value(queue_type as u32).unwrap();
        if let Err(e) = v4l2r::ioctl::reqbufs::<()>(stream, queue, memory, 0) {
            warn!("reqbufs failed: {}", e);
        }
        stream.empty_resources(queue_type);

        Sync(video::CmdResponse::OkNoData)
    }

    fn drain_stream(&mut self, stream_id: u32) -> video::CmdResponseType {
        let stream = match self.streams.get_mut(&stream_id) {
            Some(stream) => stream,
            None => {
                return Sync(video::CmdResponse::Error(InvalidStreamId));
            }
        };
        if let Err(e) =
            v4l2r::ioctl::decoder_cmd::<_, ()>(stream, v4l2r::ioctl::DecoderCommand::Stop)
        {
            warn!("decoder_cmd failed: {}", e);
            return Sync(video::CmdResponse::Error(InvalidParameter));
        }
        stream.set_state(stream::StreamState::Draining);
        Sync(video::CmdResponse::OkNoData)
    }

    fn dequeue_event(&self, stream_id: u32) -> Option<video::virtio_video_event> {
        let stream = match self.streams.get(&stream_id) {
            Some(stream) => stream,
            None => {
                return None;
            }
        };
        let event = match v4l2r::ioctl::dqevent(stream) {
            Ok(event) => event,
            Err(e) => {
                warn!("dqevent failed: {}", e);
                return Some(video::virtio_video_event {
                    event_type: video::VirtioVideoEventType::Error.into(),
                    stream_id: stream_id.into(),
                });
            }
        };

        match event {
            v4l2r::ioctl::Event::SrcChangeEvent(changes) => {
                debug!("Source change event: {:?}", changes);
                Some(video::virtio_video_event {
                    event_type: video::VirtioVideoEventType::DecoderResolutionChanged.into(),
                    stream_id: stream_id.into(),
                })
            }
            v4l2r::ioctl::Event::Eos => {
                debug!("Received EOS event");
                None
            }
        }
    }

    fn dequeue_resource(&self, stream_id: u32, queue_type: video::QueueType) -> Option<DqBufData> {
        let stream = match self.streams.get(&stream_id) {
            Some(stream) => stream,
            None => {
                return None;
            }
        };
        let queue = v4l2r::QueueType::from_value(queue_type as u32).unwrap();
        let v4l2_buffer = match v4l2r::ioctl::dqbuf::<v4l2r::ioctl::V4l2Buffer>(stream, queue) {
            Ok(buffer) => buffer,
            Err(e) => {
                warn!("dqbuf failed: {}", e);
                return None;
            }
        };
        Some(DqBufData {
            index: v4l2_buffer.index(),
            flags: video::BufferFlags::from(v4l2_buffer.flags().to_virtio()),
            size: v4l2_buffer.get_first_plane().bytesused(),
        })
    }
}

impl V4L2Decoder {
    pub fn new(video_path: &Path) -> io::Result<Self> {
        Ok(Self {
            streams: HashMap::new(),
            video_device: FilePath::new(video_path)?,
        })
    }

    #[cfg(not(test))]
    fn v4l2_queue_buffer<T: AsRawFd>(
        fd: &T,
        queue_type: video::QueueType,
        timestamp: u64,
        res: &stream::Resource,
    ) -> bool {
        use std::slice::from_raw_parts;
        let queue = v4l2r::QueueType::from_value(queue_type as u32).unwrap();
        let planes: Vec<v4l2r::ioctl::QBufPlane> = res
            .planes
            .iter()
            .map(|plane| {
                let handle = v4l2r::memory::UserPtrHandle::from(
                    // SAFETY: the address pointer memory is initialized by the guest.
                    unsafe { from_raw_parts(plane.address as *const u8, plane.length as usize) },
                );
                v4l2r::ioctl::QBufPlane::new_from_handle(&handle, plane.length as usize)
            })
            .collect();
        let (sec, usec) = process_timestamp(timestamp);
        let qbuffer: v4l2r::ioctl::QBuffer<v4l2r::memory::UserPtrHandle<Vec<u8>>> =
            v4l2r::ioctl::QBuffer {
                planes,
                ..Default::default()
            }
            .set_timestamp(sec, usec);
        match v4l2r::ioctl::qbuf::<_, ()>(fd, queue, res.index as usize, qbuffer) {
            Ok(_) => true,
            Err(e) => {
                warn!("qbuf failed: {}", e);
                false
            }
        }
    }

    #[cfg(not(test))]
    fn v4l2_enum_formats(&self, queue_type: video::QueueType, index: u32) -> Option<v4l2_fmtdesc> {
        let queue = v4l2r::QueueType::from_value(queue_type as u32).unwrap();
        match v4l2r::ioctl::enum_fmt(&self.video_device, queue, index) {
            Ok(fmtdesc) => Some(fmtdesc),
            Err(e) => {
                warn!("fmtdesc failed: {}", e);
                None
            }
        }
    }

    #[cfg(not(test))]
    fn v4l2_query_control(&self, control: video::ControlType) -> Option<v4l2_queryctrl> {
        let (id, flags) = v4l2r::ioctl::parse_ctrl_id_and_flags(control.to_v4l2());
        match v4l2r::ioctl::queryctrl(&self.video_device, id, flags) {
            Ok(queryctrl) => Some(queryctrl),
            Err(e) => {
                warn!("queryctrl failed: {}", e);
                None
            }
        }
    }

    #[cfg(not(test))]
    fn v4l2_get_format<T: AsRawFd>(fd: &T, queue_type: video::QueueType) -> Option<v4l2_format> {
        let queue = v4l2r::QueueType::from_value(queue_type as u32).unwrap();
        match v4l2r::ioctl::g_fmt(fd, queue) {
            Ok(format) => format,
            Err(e) => {
                warn!("g_fmt failed: {}", e);
                None
            }
        }
    }

    #[cfg(not(test))]
    fn v4l2_request_buffers<T: AsRawFd>(
        fd: &T,
        queue_type: video::QueueType,
        memory_type: video::MemoryType,
        bufcount: u32,
    ) -> bool {
        let memory = v4l2r::memory::MemoryType::n(memory_type.to_v4l2()).unwrap();
        let queue = v4l2r::QueueType::from_value(queue_type as u32).unwrap();
        if let Err(e) = v4l2r::ioctl::reqbufs::<()>(fd, queue, memory, bufcount) {
            warn!("reqbufs failed: {}", e);
            return false;
        }
        true
    }

    #[cfg(not(test))]
    fn v4l2_enum_frame_sizes(&self, pixformat: u32, index: u32) -> Option<v4l2_frmsizeenum> {
        let pixelformat: PixelFormat = PixelFormat::from(pixformat);
        match v4l2r::ioctl::enum_frame_sizes(&self.video_device, index, pixelformat) {
            Ok(frmsizeenum) => Some(frmsizeenum),
            Err(e) => {
                warn!("enum_frame_sizes failed: {}", e);
                None
            }
        }
    }

    #[cfg(not(test))]
    fn v4l2_enum_frame_intervals(
        &self,
        pixformat: u32,
        width: u32,
        height: u32,
        index: u32,
    ) -> Option<v4l2_frmivalenum> {
        let pixelformat: PixelFormat = PixelFormat::from(pixformat);
        match v4l2r::ioctl::enum_frame_intervals(
            &self.video_device,
            index,
            pixelformat,
            width,
            height,
        ) {
            Ok(frmivalenum) => Some(frmivalenum),
            Err(e) => {
                warn!("enum_frame_intervals failed! {}", e);
                None
            }
        }
    }

    fn video_enum_frame_sizes(&self, pixformat: u32) -> Vec<video::virtio_video_format_frame> {
        let mut index: u32 = 0;
        let mut frames: Vec<video::virtio_video_format_frame> = Vec::new();
        while let Some(frame) = self.v4l2_enum_frame_sizes(pixformat, index) {
            if index != frame.index {
                warn!("driver returned wrong frame index: {}", frame.index);
            }
            if pixformat != frame.pixel_format {
                warn!(
                    "driver returned wrong frame pixel format: {:#x}",
                    frame.pixel_format
                );
            }

            let mut format_frame: video::virtio_video_format_frame = frame.into();
            match frame.size() {
                Some(v4l2r::ioctl::FrmSizeTypes::Discrete(size)) => format_frame
                    .append_frame_rates(&mut self.video_enum_frame_intervals(
                        pixformat,
                        size.width,
                        size.height,
                    )),
                Some(v4l2r::ioctl::FrmSizeTypes::StepWise(size)) => {
                    if frame.type_
                        == v4l2r::bindings::v4l2_frmsizetypes_V4L2_FRMSIZE_TYPE_CONTINUOUS
                        && format_frame.width.step != 1
                        && format_frame.length.step != 1
                    {
                        warn!("invalid step for continious framesize");
                        break;
                    }

                    format_frame.append_frame_rates(&mut self.video_enum_frame_intervals(
                        pixformat,
                        size.max_width,
                        size.max_height,
                    ));
                }
                None => {
                    warn!("Unexpected frame type: {}", frame.type_);
                    break;
                }
            }
            frames.push(format_frame);
            index += 1;
        }

        frames
    }

    fn video_enum_frame_intervals(
        &self,
        pixformat: u32,
        width: u32,
        height: u32,
    ) -> Vec<video::virtio_video_format_range> {
        let mut index: u32 = 0;
        let mut frame_rates: Vec<video::virtio_video_format_range> = Vec::new();
        while let Some(ival) = self.v4l2_enum_frame_intervals(pixformat, width, height, index) {
            if index != ival.index {
                warn!("driver returned wrong ival index: {}", ival.index);
            }
            if pixformat != ival.pixel_format {
                warn!(
                    "driver returned wrong ival pixel format: {:#x}",
                    ival.pixel_format
                );
            }
            if width != ival.width {
                warn!("driver returned wrong ival width: {}", ival.width);
            }
            if height != ival.height {
                warn!("driver returned wrong ival heigth: {}", ival.height);
            }

            frame_rates.push(video::virtio_video_format_range::from(ival));
            index += 1;
        }

        frame_rates
    }

    fn v4l2_get_selection<T: AsRawFd>(fd: &T, queue_type: video::QueueType) -> Option<v4l2_rect> {
        let queue = v4l2r::QueueType::from_value(queue_type as u32).unwrap();
        let sel_type: v4l2r::ioctl::SelectionType = match queue {
            v4l2r::QueueType::VideoCaptureMplane => v4l2r::ioctl::SelectionType::Capture,
            v4l2r::QueueType::VideoOutputMplane => v4l2r::ioctl::SelectionType::Output,
            _ => return None,
        };
        let sel_target: v4l2r::ioctl::SelectionTarget =
            if queue.direction() == v4l2r::QueueDirection::Capture {
                v4l2r::ioctl::SelectionTarget::Compose
            } else {
                v4l2r::ioctl::SelectionTarget::Crop
            };

        match v4l2r::ioctl::g_selection(fd, sel_type, sel_target) {
            Ok(rect) => Some(rect),
            Err(e) => {
                warn!("g_selection failed: {}", e);
                None
            }
        }
    }
}

#[cfg(test)]
mod tests {

    use std::mem;

    use assert_matches::assert_matches;
    use rstest::*;
    use tempfile::TempDir;

    use super::*;
    use crate::vhu_video::tests::{test_dir, VideoDeviceMock};

    /// Mock implementations for v4l2r wrapped calls
    impl V4L2Decoder {
        pub fn v4l2_queue_buffer<T: AsRawFd>(
            _fd: &T,
            _queue_type: video::QueueType,
            _timestamp: u64,
            _res: &stream::Resource,
        ) -> bool {
            true
        }

        pub fn v4l2_enum_formats(
            &self,
            _queue_type: video::QueueType,
            index: u32,
        ) -> Option<v4l2_fmtdesc> {
            if index > 0 {
                return None;
            }
            Some(v4l2_fmtdesc {
                index,
                type_: v4l2r::bindings::v4l2_buf_type_V4L2_BUF_TYPE_VIDEO_CAPTURE_MPLANE,
                pixelformat: 0x3231564e, // NV12
                // SAFETY: test environment only.
                ..unsafe { mem::zeroed() }
            })
        }

        pub fn v4l2_query_control(&self, _control: video::ControlType) -> Option<v4l2_queryctrl> {
            Some(v4l2_queryctrl {
                // SAFETY: test environment only.
                ..unsafe { mem::zeroed() }
            })
        }

        pub fn v4l2_get_format<T: AsRawFd>(
            _fd: &T,
            _queue_type: video::QueueType,
        ) -> Option<v4l2_format> {
            Some(v4l2_format {
                // SAFETY: test environment only.
                ..unsafe { mem::zeroed() }
            })
        }

        pub fn v4l2_request_buffers<T: AsRawFd>(
            _fd: &T,
            _queue_type: video::QueueType,
            _memory_type: video::MemoryType,
            _bufcount: u32,
        ) -> bool {
            true
        }

        pub fn v4l2_enum_frame_sizes(
            &self,
            pixformat: u32,
            index: u32,
        ) -> Option<v4l2_frmsizeenum> {
            if index > 0 {
                return None;
            }
            Some(v4l2_frmsizeenum {
                index,
                pixel_format: pixformat,
                // SAFETY: test environment only.
                ..unsafe { mem::zeroed() }
            })
        }

        pub fn v4l2_enum_frame_intervals(
            &self,
            pixformat: u32,
            width: u32,
            height: u32,
            index: u32,
        ) -> Option<v4l2_frmivalenum> {
            if index > 0 {
                return None;
            }
            let ival = v4l2r::bindings::v4l2_frmivalenum__bindgen_ty_1 {
                discrete: v4l2r::bindings::v4l2_fract {
                    numerator: 1,
                    denominator: 1,
                },
            };
            Some(v4l2_frmivalenum {
                index,
                pixel_format: pixformat,
                width,
                height,
                type_: v4l2r::bindings::v4l2_frmivaltypes_V4L2_FRMIVAL_TYPE_DISCRETE,
                __bindgen_anon_1: ival,
                // SAFETY: test environment only.
                ..unsafe { mem::zeroed() }
            })
        }
    }

    #[rstest]
    fn test_backend_trait(test_dir: TempDir) {
        use video::{CmdResponse::*, CmdResponseType::*};
        // Mock video device, will not answer to requests
        let v4l2_device = VideoDeviceMock::new(&test_dir);
        let mut decoder = V4L2Decoder::new(Path::new(&v4l2_device.path)).unwrap();
        let stream_id = 1;
        let invalid_stream_id = 2;
        let resource_id = 1;
        let queue_type = video::QueueType::OutputQueue;
        // Create stream
        assert_matches!(decoder.create_stream(stream_id, 0, 1, 1), Sync(OkNoData));
        // Only stream_id 1 is retrievable
        assert_matches!(decoder.stream(&stream_id), Some(stream::Stream { .. }));
        assert_matches!(decoder.stream_mut(&stream_id), Some(stream::Stream { .. }));
        assert_matches!(decoder.stream(&invalid_stream_id), None);
        assert_matches!(decoder.stream_mut(&invalid_stream_id), None);
        // Check capabilities, control, params
        assert_matches!(
            decoder.query_capability(queue_type),
            Sync(QueryCapability(_))
        );
        assert_matches!(
            decoder.query_control(video::ControlType::Bitrate),
            Sync(QueryControl(video::VideoControl::Bitrate(_)))
        );
        let params = video::virtio_video_params {
            queue_type: <u32 as Into<Le32>>::into(queue_type as u32),
            ..Default::default()
        };
        assert_matches!(
            decoder.set_params(stream_id, params),
            Sync(Error(video::CmdError::InvalidParameter))
        );
        assert_matches!(
            decoder.get_params(stream_id, queue_type),
            Sync(GetParams { .. })
        );
        // Create resource, queue, and dequeue it
        assert_matches!(
            decoder.create_resource(stream_id, resource_id, 1, Vec::new(), queue_type),
            Sync(OkNoData)
        );
        assert_matches!(
            decoder.queue_resource(stream_id, queue_type, resource_id, 0, vec![0]),
            Sync(Error(video::CmdError::InvalidParameter))
        );
        assert_matches!(decoder.dequeue_resource(stream_id, queue_type), None);
        // End of stream
        assert_matches!(
            decoder.clear_queue(stream_id, queue_type),
            Sync(Error(video::CmdError::InvalidParameter))
        );
        assert_matches!(
            decoder.drain_stream(stream_id),
            Sync(Error(video::CmdError::InvalidParameter))
        );
        assert_matches!(
            decoder.destroy_resources(stream_id, queue_type),
            Sync(OkNoData)
        );
        // Destroying empty resources list shall not fail
        assert_matches!(
            decoder.destroy_resources(stream_id, video::QueueType::InputQueue),
            Sync(OkNoData)
        );
        assert_matches!(decoder.destroy_stream(stream_id), Sync(OkNoData));
    }

    #[rstest]
    fn test_backend_trait_errors(test_dir: TempDir) {
        use video::{CmdResponse::*, CmdResponseType::*};
        let stream_id = 1;
        let resource_id = 1;
        let queue_type = video::QueueType::OutputQueue;
        let params = video::virtio_video_params {
            queue_type: <u32 as Into<Le32>>::into(queue_type as u32),
            ..Default::default()
        };
        let v4l2_device = VideoDeviceMock::new(&test_dir);
        let mut decoder = V4L2Decoder::new(Path::new(&v4l2_device.path)).unwrap();
        // Invalid memory type, stream not created, other operations shall also fail
        assert_matches!(
            decoder.create_stream(stream_id, 2, 2, 1),
            Sync(Error(video::CmdError::InvalidParameter))
        );
        assert_matches!(
            decoder.set_params(stream_id, params),
            Sync(Error(video::CmdError::InvalidStreamId))
        );
        assert_matches!(
            decoder.create_resource(
                stream_id,
                resource_id,
                1,
                vec![stream::ResourcePlane::default()],
                queue_type
            ),
            Sync(Error(video::CmdError::InvalidStreamId))
        );
        assert_matches!(
            decoder.queue_resource(stream_id, queue_type, resource_id, 0, vec![0]),
            Sync(Error(video::CmdError::InvalidStreamId))
        );
        assert_matches!(decoder.dequeue_resource(stream_id, queue_type), None);
        assert_matches!(
            decoder.clear_queue(stream_id, queue_type),
            Sync(Error(video::CmdError::InvalidStreamId))
        );
        assert_matches!(
            decoder.drain_stream(stream_id),
            Sync(Error(video::CmdError::InvalidStreamId))
        );
        assert_matches!(
            decoder.destroy_resources(stream_id, queue_type),
            Sync(Error(video::CmdError::InvalidStreamId))
        );
    }

    #[rstest]
    fn test_backend_dequeue_event(test_dir: TempDir) {
        use video::{CmdResponse::*, CmdResponseType::*};
        // Mock video device, will not answer to requests
        let v4l2_device = VideoDeviceMock::new(&test_dir);
        let mut decoder = V4L2Decoder::new(Path::new(&v4l2_device.path)).unwrap();
        let stream_id = 1;
        // Create stream
        assert_matches!(decoder.create_stream(stream_id, 0, 1, 1), Sync(OkNoData));
        assert_matches!(
            decoder.dequeue_event(stream_id),
            Some(video::virtio_video_event { .. })
        );
    }

    #[rstest]
    fn test_v4l2_backend_helpers(test_dir: TempDir) {
        let v4l2_device = VideoDeviceMock::new(&test_dir);
        let decoder = V4L2Decoder::new(Path::new(&v4l2_device.path)).unwrap();
        let nv12 = u32::from_le(0x3231564e);
        assert_matches!(
            V4L2Decoder::v4l2_get_selection(&decoder.video_device, video::QueueType::InputQueue),
            None
        );
        let frames = decoder.video_enum_frame_sizes(nv12);
        assert_eq!(frames.len(), 0);
        let intervals = decoder.video_enum_frame_intervals(nv12, 640, 640);
        assert_eq!(intervals.len(), 1);
    }

    #[rstest]
    #[case::abgr(PixelFormat::from(b"ABGR"), video::Format::Argb8888)]
    #[case::nv12(PixelFormat::from(b"NV12"), video::Format::Nv12)]
    #[case::yu12(PixelFormat::from(b"YU12"), video::Format::Yuv420)]
    #[case::yv12(PixelFormat::from(b"YV12"), video::Format::Yvu420)]
    #[case::mpg2(PixelFormat::from(b"MPG2"), video::Format::Mpeg2)]
    #[case::mpg4(PixelFormat::from(b"MPG4"), video::Format::Mpeg4)]
    #[case::h264(PixelFormat::from(b"H264"), video::Format::H264)]
    #[case::hevc(PixelFormat::from(b"HEVC"), video::Format::Hevc)]
    #[case::vp8(PixelFormat::from(b"VP80"), video::Format::Vp8)]
    #[case::vp9(PixelFormat::from(b"VP90"), video::Format::Vp9)]
    #[case::fwht(PixelFormat::from(b"FWHT"), video::Format::Fwht)]
    fn test_v4l2r_pixelformat_trait(
        #[case] pixformat: PixelFormat,
        #[case] video_format: video::Format,
    ) {
        let expected: Le32 = (video_format as u32).into();
        assert_eq!(pixformat.to_virtio(), expected);
    }

    #[rstest]
    #[case::output_queue(
        v4l2r::QueueType::VideoOutputMplane,
        video::VIRTIO_VIDEO_QUEUE_TYPE_INPUT
    )]
    #[case::capture_queue(
        v4l2r::QueueType::VideoCaptureMplane,
        video::VIRTIO_VIDEO_QUEUE_TYPE_OUTPUT
    )]
    #[case::capture_queue(v4l2r::QueueType::VideoOverlay, 0)]
    fn test_v4l2r_queuetype_trait(#[case] v4l2r_queue: v4l2r::QueueType, #[case] video_queue: u32) {
        let expected: Le32 = video_queue.into();
        assert_eq!(v4l2r_queue.to_virtio(), expected);
    }

    #[rstest]
    #[case::output_queue(video::QueueType::InputQueue, v4l2r::QueueType::VideoOutputMplane)]
    #[case::capture_queue(video::QueueType::OutputQueue, v4l2r::QueueType::VideoCaptureMplane)]
    fn test_video_queuetype_trait(
        #[case] video_queue: video::QueueType,
        #[case] v4l2r_queue: v4l2r::QueueType,
    ) {
        assert_eq!(video_queue.to_v4l2(), v4l2r_queue as u32);
    }

    #[rstest]
    #[case::bitrate(
        video::ControlType::Bitrate,
        v4l2r::bindings::V4L2_CID_MPEG_VIDEO_BITRATE
    )]
    #[case::bitrate_peak(
        video::ControlType::BitratePeak,
        v4l2r::bindings::V4L2_CID_MPEG_VIDEO_BITRATE_PEAK
    )]
    #[case::bitrate_mode(
        video::ControlType::BitrateMode,
        v4l2r::bindings::V4L2_CID_MPEG_VIDEO_BITRATE_MODE
    )]
    #[case::profile(
        video::ControlType::Profile,
        v4l2r::bindings::V4L2_CID_MPEG_VIDEO_H264_PROFILE
    )]
    #[case::level(
        video::ControlType::Level,
        v4l2r::bindings::V4L2_CID_MPEG_VIDEO_H264_LEVEL
    )]
    #[case::force_key_frame(
        video::ControlType::ForceKeyframe,
        v4l2r::bindings::V4L2_CID_MPEG_VIDEO_FORCE_KEY_FRAME
    )]
    #[case::prepend_spspps_to_ids(
        video::ControlType::PrependSpsPpsToIdr,
        v4l2r::bindings::V4L2_CID_MPEG_VIDEO_PREPEND_SPSPPS_TO_IDR
    )]
    fn test_video_controltype_trait(
        #[case] control: video::ControlType,
        #[case] v4l2r_control: u32,
    ) {
        assert_eq!(control.to_v4l2(), v4l2r_control);
    }

    #[rstest]
    #[case::error(v4l2r::ioctl::BufferFlags::ERROR, video::BufferFlags::ERR)]
    #[case::eos(v4l2r::ioctl::BufferFlags::LAST, video::BufferFlags::EOS)]
    fn test_v4l2r_bufferflags_trait(
        #[case] v4l2r_flag: v4l2r::ioctl::BufferFlags,
        #[case] video_flag: video::BufferFlags,
    ) {
        let expected: Le32 = video_flag.into();
        assert_eq!(v4l2r_flag.to_virtio(), expected);
    }

    #[rstest]
    #[case(1000, (0, 1))]
    #[case(367000, (0, 367))]
    #[case(1000000000, (1, 0))]
    #[case(1200459000, (1, 200459))]
    #[case(12000972234, (12, 972))]
    fn test_timestamp_parser(#[case] timestamp: u64, #[case] result: (i64, i64)) {
        assert_eq!(process_timestamp(timestamp), result)
    }
}
