// SPDX-License-Identifier: Apache-2.0 or BSD-3-Clause

use std::mem::size_of;
use std::sync::RwLock;
use std::{io::Result as IoResult, u16, u32, u64, u8};
use std::sync::Arc;

use log::{error, debug};
use vhost::vhost_user::message::{VhostUserProtocolFeatures, VhostUserVirtioFeatures};
use vhost_user_backend::{VhostUserBackend, VringRwLock, VringT};
use virtio_bindings::bindings::{
    virtio_config::VIRTIO_F_NOTIFY_ON_EMPTY, virtio_config::VIRTIO_F_VERSION_1,
    virtio_ring::VIRTIO_RING_F_EVENT_IDX, virtio_ring::VIRTIO_RING_F_INDIRECT_DESC,
};
use virtio_queue::{DescriptorChain, QueueOwnedT};
use vm_memory::{Bytes, ByteValued, GuestAddressSpace, GuestMemoryAtomic, GuestMemoryMmap, GuestMemoryLoadGuard};
use vmm_sys_util::{
    epoll::EventSet,
    eventfd::{EventFd, EFD_NONBLOCK},
};

use crate::audio_backends::{alloc_audio_backend, AudioBackend};
use crate::virtio_sound::*;
use crate::{Error, Result, SoundConfig};
use vm_memory::{Le32, Le64};
use crate::PCMParams;

pub const SUPPORTED_FORMATS: u64 = 1 << VIRTIO_SND_PCM_FMT_U8
    | 1 << VIRTIO_SND_PCM_FMT_S16
    | 1 << VIRTIO_SND_PCM_FMT_S24
    | 1 << VIRTIO_SND_PCM_FMT_S32;

pub const SUPPORTED_RATES: u64 = 1 << VIRTIO_SND_PCM_RATE_8000
    | 1 << VIRTIO_SND_PCM_RATE_11025
    | 1 << VIRTIO_SND_PCM_RATE_16000
    | 1 << VIRTIO_SND_PCM_RATE_22050
    | 1 << VIRTIO_SND_PCM_RATE_32000
    | 1 << VIRTIO_SND_PCM_RATE_44100
    | 1 << VIRTIO_SND_PCM_RATE_48000;

pub const NR_STREAMS: usize = 1;

pub struct StreamInfo {
    pub features: Le32, /* 1 << VIRTIO_SND_PCM_F_XXX */
    pub formats: Le64,  /* 1 << VIRTIO_SND_PCM_FMT_XXX */
    pub rates: Le64,    /* 1 << VIRTIO_SND_PCM_RATE_XXX */
    pub direction: u8,
    pub channels_min: u8,
    pub channels_max: u8,
}

impl StreamInfo {
    pub fn output() -> Self {
        Self {
            features : 0.into(),
            formats : SUPPORTED_FORMATS.into(),
            rates : SUPPORTED_RATES.into(),
            direction : VIRTIO_SND_D_OUTPUT,
            channels_min : 1,
            channels_max : 6,
        }
    }
}

struct VhostUserSoundThread {
    mem: Option<GuestMemoryAtomic<GuestMemoryMmap>>,
    event_idx: bool,
    queue_indexes: Vec<u16>,
    audio_backend: Arc<Box<dyn AudioBackend + Send + Sync>>
}

impl VhostUserSoundThread {
    pub fn new(mut queue_indexes: Vec<u16>, audio_backend: Arc<Box<dyn AudioBackend + Send + Sync>>) -> Result<Self> {
        queue_indexes.sort();

        Ok(VhostUserSoundThread {
            event_idx: false,
            mem: None,
            queue_indexes,
            audio_backend
        })
    }

    fn queues_per_thread(&self) -> u64 {
        let mut queues_per_thread = 0u64;

        for idx in self.queue_indexes.iter() {
            queues_per_thread |= 1u64 << idx
        }

        queues_per_thread
    }

    fn set_event_idx(&mut self, enabled: bool) {
        self.event_idx = enabled;
    }

    fn update_memory(&mut self, mem: GuestMemoryAtomic<GuestMemoryMmap>) -> IoResult<()> {
        debug!("update memory");
        self.mem = Some(mem);
        Ok(())
    }

    fn handle_event(&self, device_event: u16, vrings: &[VringRwLock], stream_info: &[StreamInfo]) -> IoResult<bool> {
        let vring = &vrings[device_event as usize];
        let queue_idx = self.queue_indexes[device_event as usize];
        debug!("handle event call queue: {}", queue_idx);

        match queue_idx {
            CONTROL_QUEUE_IDX => {
                debug!("control queue: {}", CONTROL_QUEUE_IDX);
                let vring = &vrings[0];
                if self.event_idx {
                    // vm-virtio's Queue implementation only checks avail_index
                    // once, so to properly support EVENT_IDX we need to keep
                    // calling process_request_queue() until it stops finding
                    // new requests on the queue.
                    loop {
                        vring.disable_notification().unwrap();
                        self.process_control(vring, stream_info)?;
                        if !vring.enable_notification().unwrap() {
                            break;
                        }
                    }
                } else {
                    // Without EVENT_IDX, a single call is enough.
                    self.process_control(vring, stream_info)?;
                }
            }
            EVENT_QUEUE_IDX => {
                self.process_event(vring)?;
            }
            TX_QUEUE_IDX => {
                let vring = &vrings[2];
                if self.event_idx {
                    // vm-virtio's Queue implementation only checks avail_index
                    // once, so to properly support EVENT_IDX we need to keep
                    // calling process_request_queue() until it stops finding
                    // new requests on the queue.
                    loop {
                        vring.disable_notification().unwrap();
                        self.process_tx(vring)?;
                        if !vring.enable_notification().unwrap() {
                            break;
                        }
                    }
                } else {
                    // Without EVENT_IDX, a single call is enough.
                    self.process_tx(vring)?;
                }
            }
            RX_QUEUE_IDX => {
                self.process_rx(vring)?;
            }
            _ => {
                return Err(Error::HandleUnknownEvent.into());
            }
        }
        Ok(false)
    }

    /// Process the messages in the vring and dispatch replies
    fn process_control(&self, vring: &VringRwLock, stream_info: &[StreamInfo]) -> Result<bool> {
        let requests: Vec<SndDescriptorChain> = vring
            .get_mut()
            .get_queue_mut()
            .iter(self.mem.as_ref().unwrap().memory())
            .map_err(|_| Error::DescriptorNotFound)?
            .collect();

        let audio_backend = &self.audio_backend;

        debug!("Requests to process: {}", requests.len());
        if requests.is_empty() {
            debug!("yes, it's empty");
            return Ok(true);
        }
        //iterate over each sound request
        for desc_chain in requests {
            let descriptors: Vec<_> = desc_chain.clone().collect();
            debug!("Sound request with n descriptors: {}", descriptors.len());

            let desc_request = descriptors[0];
            if desc_request.is_write_only() {
                return Err(Error::UnexpectedWriteOnlyDescriptor(0));
            }
            let read_desc_len: usize = desc_request.len() as usize;
            let header_size = size_of::<VirtioSoundHeader>();
            if read_desc_len < header_size {
                return Err(Error::UnexpectedMinimumDescriptorSize(
                    header_size,
                    read_desc_len,
                ));
            }
            let hdr_request = desc_chain
                .memory()
                .read_obj::<VirtioSoundHeader>(desc_request.addr())
                .map_err(|_| Error::DescriptorReadFailed)?;

            let desc_response = descriptors[1];
            if !desc_response.is_write_only() {
                return Err(Error::UnexpectedReadableDescriptor(1));
            }

            let mut response = VirtioSoundHeader { code: VIRTIO_SND_S_OK.into(), };

            let mut len = desc_response.len();

            let request_type = hdr_request.code.to_native();
            match request_type {
                VIRTIO_SND_R_JACK_INFO => todo!(),
                VIRTIO_SND_R_PCM_INFO => {
                    if descriptors.len() != 3 {
                        return Err(Error::UnexpectedDescriptorCount(descriptors.len()));
                    }
                    let desc_pcm = descriptors[2];
                    if !desc_pcm.is_write_only() {
                        return Err(Error::UnexpectedReadableDescriptor(2));
                    }
                    let query_info = desc_chain
                        .memory()
                        .read_obj::<VirtioSoundQueryInfo>(desc_request.addr())
                        .map_err(|_| Error::DescriptorReadFailed)?;

                    let start_id: usize = u32::from(query_info.start_id) as usize;
                    let count: usize = u32::from(query_info.count) as usize;

                    if start_id + count > stream_info.len() {
                        error!(
                            "start_id({}) + count({}) must be smaller than the number of streams ({})",
                            start_id,
                            count,
                            stream_info.len()
                        );
                        desc_chain
                            .memory()
                            .write_obj(VIRTIO_SND_S_BAD_MSG, desc_response.addr())
                            .map_err(|_| Error::DescriptorWriteFailed)?;
                    } else {
                        desc_chain
                            .memory()
                            .write_obj(response, desc_response.addr())
                            .map_err(|_| Error::DescriptorWriteFailed)?;

                        let mut buf = vec![];

                        for (i, stream) in stream_info.iter().enumerate().skip(start_id).take(count) {
                            let pcm_info = VirtioSoundPcmInfo {
                                hdr : VirtioSoundInfo {
                                    hda_fn_nid : Le32::from(i as u32)
                                },
                                features : stream.features,
                                formats : stream.formats,
                                rates : stream.rates,
                                direction : stream.direction,
                                channels_min : stream.channels_min,
                                channels_max : stream.channels_max,
                                padding : [0; 5]
                            };
                            buf.extend_from_slice(pcm_info.as_slice());
                        };

                        // TODO: to support the case when the number of items
                        // do not fit in a single descriptor
                        desc_chain
                            .memory()
                            .write_slice(&buf, desc_pcm.addr())
                            .map_err(|_| Error::DescriptorWriteFailed)?;

                        len += desc_pcm.len();
                    }
                },
                VIRTIO_SND_R_CHMAP_INFO => todo!(),
                VIRTIO_SND_R_JACK_REMAP => todo!(),
                VIRTIO_SND_R_PCM_SET_PARAMS => {
                    if descriptors.len() != 2 {
                        return Err(Error::UnexpectedDescriptorCount(descriptors.len()));
                    }

                    let set_params = desc_chain
                        .memory()
                        .read_obj::<VirtioSndPcmSetParams>(desc_request.addr())
                        .map_err(|_| Error::DescriptorReadFailed)?;

                    let params = PCMParams {
                        buffer_bytes :  set_params.buffer_bytes,
                        period_bytes : set_params.period_bytes,
                        features : set_params.features,
                        rate : set_params.rate,
                        format : set_params.format,
                        channels : set_params.channels
                    };

                    let stream_id = set_params.hdr.stream_id.to_native();

                    if params.features != 0 {
                        error!("No feature is supported");
                        response = VirtioSoundHeader { code: VIRTIO_SND_S_NOT_SUPP.into() };
                    } else if set_params.buffer_bytes.to_native() % set_params.period_bytes.to_native() != 0 {
                        response = VirtioSoundHeader { code: VIRTIO_SND_S_BAD_MSG.into() };
                        error!("buffer_bytes({}) must be dividable by period_bytes({})",
                        set_params.buffer_bytes.to_native(), set_params.period_bytes.to_native());
                    } else if audio_backend.set_param(stream_id, params)
                           .is_err() {
                            error!("IO error during set_param()");
                            response = VirtioSoundHeader { code: VIRTIO_SND_S_IO_ERR.into() };
                    }
                    desc_chain
                        .memory()
                        .write_obj(response, desc_response.addr())
                        .map_err(|_| Error::DescriptorWriteFailed)?;

                    len = desc_response.len();
                },
                VIRTIO_SND_R_PCM_PREPARE
                | VIRTIO_SND_R_PCM_START
                | VIRTIO_SND_R_PCM_STOP
                | VIRTIO_SND_R_PCM_RELEASE => {
                    let pcm_hdr = desc_chain
                        .memory()
                        .read_obj::<VirtioSoundPcmHeader>(desc_request.addr())
                        .map_err(|_| Error::DescriptorReadFailed)?;
                    let stream_id: usize = u32::from(pcm_hdr.stream_id) as usize;
                    dbg!("stream_id: {}", stream_id );

                    desc_chain
                        .memory()
                        .write_obj(response, desc_response.addr())
                        .map_err(|_| Error::DescriptorWriteFailed)?;
                    len = desc_response.len();
                },
                _ => {
                    error!(
                        "virtio-snd: Unknown control queue message code: {}",
                        request_type
                    );
                }
            };
            if vring
                .add_used(desc_chain.head_index(), len)
                .is_err()
            {
                error!("Couldn't return used descriptors to the ring");
            }
        }
        // Send notification once all the requests are processed
        debug!("Sending processed request notification");
        vring
            .signal_used_queue()
            .map_err(|_| Error::SendNotificationFailed)?;
        debug!("Process control queue finished");

        Ok(false)
    }

    fn process_event(&self, _vring: &VringRwLock) -> IoResult<bool> {
        Ok(false)
    }

    fn process_tx(&self, vring: &VringRwLock) -> Result<bool> {
        let requests: Vec<SndDescriptorChain> = vring
            .get_mut()
            .get_queue_mut()
            .iter(self.mem.as_ref().unwrap().memory())
            .map_err(|_| Error::DescriptorNotFound)?
            .collect();

        debug!("Requests to tx: {}", requests.len());

        for desc_chain in requests {
            let descriptors: Vec<_> = desc_chain.clone().collect();
            debug!("Sound request with n descriptors: {}", descriptors.len());

            // TODO: to handle the case in which READ_ONLY descs
            // have both the header and the data

            let last_desc = descriptors.len() - 1;
            let desc_response = descriptors[last_desc];

            if desc_response.len() as usize != size_of::<VirtioSoundPcmStatus>() {
                return Err(Error::UnexpectedDescriptorSize(
                    size_of::<VirtioSoundPcmStatus>(),
                    desc_response.len() as usize,
                ));
            }

            if !desc_response.is_write_only() {
                return Err(Error::UnexpectedReadableDescriptor(1));
            }

            let response = VirtioSoundPcmStatus { status: VIRTIO_SND_S_OK.into(), latency_bytes: 0.into() };

            let desc_request = descriptors[0];

            if desc_request.len() as usize != size_of::<VirtioSoundPcmXfer>() {
                return Err(Error::UnexpectedDescriptorSize(
                    size_of::<VirtioSoundPcmXfer>(),
                    desc_request.len() as usize,
                ));
            }

            if desc_request.is_write_only() {
                return Err(Error::UnexpectedWriteOnlyDescriptor(1));
            }

            let mut all_bufs=Vec::<u8>::new();
            let data_descs = &descriptors[1..descriptors.len() -1];

            for data in data_descs{
                if data.is_write_only(){
                    return Err(Error::UnexpectedWriteOnlyDescriptor(1));
                }

                let mut buf = vec![0u8; data.len() as usize];

                desc_chain
                    .memory()
                    .read_slice(&mut buf, data.addr())
                    .map_err(|_| Error::DescriptorReadFailed)?;

                all_bufs.extend(buf);
            }

            let hdr_request = desc_chain
            .memory()
            .read_obj::<VirtioSoundPcmXfer>(desc_request.addr())
            .map_err(|_| Error::DescriptorReadFailed)?;

            let _stream_id = hdr_request.stream_id.to_native();

            // TODO: to invoke audio_backend.write(stream_id, all_bufs, len)

            // 5.14.6.8.1.1
            // The device MUST NOT complete the I/O request until the buffer is
            // totally consumed.
            desc_chain
                .memory()
                .write_obj(response, desc_response.addr())
                .map_err(|_| Error::DescriptorWriteFailed)?;

            let len = desc_response.len();

            if vring
                .add_used(desc_chain.head_index(), len)
                .is_err()
            {
                error!("Couldn't return used descriptors to the ring");
            }
        }
        // Send notification once all the requests are processed
        debug!("Sending processed tx notification");
        vring
            .signal_used_queue()
            .map_err(|_| Error::SendNotificationFailed)?;
        debug!("Process tx queue finished");
        Ok(false)
    }

    fn process_rx(&self, _vring: &VringRwLock) -> IoResult<bool> {
        Ok(false)
    }

}

pub struct VhostUserSoundBackend {
    threads: Vec<RwLock<VhostUserSoundThread>>,
    virtio_cfg: VirtioSoundConfig,
    exit_event: EventFd,
    streams_info: Vec<StreamInfo>
}

type SndDescriptorChain = DescriptorChain<GuestMemoryLoadGuard<GuestMemoryMmap<()>>>;

impl VhostUserSoundBackend {
    pub fn new(config: SoundConfig) -> Result<Self> {
        let audio_backend = alloc_audio_backend(config.audio_backend_name)?;
        let audio_backend_arc = Arc::new(audio_backend);
        let threads = if config.multi_thread {
            vec![
                RwLock::new(VhostUserSoundThread::new(vec![
                    CONTROL_QUEUE_IDX,
                    EVENT_QUEUE_IDX,
                ], audio_backend_arc.clone())?),
                RwLock::new(VhostUserSoundThread::new(vec![TX_QUEUE_IDX], Arc::clone(&audio_backend_arc))?),
                RwLock::new(VhostUserSoundThread::new(vec![RX_QUEUE_IDX], Arc::clone(&audio_backend_arc))?),
            ]
        } else {
            vec![RwLock::new(VhostUserSoundThread::new(vec![
                CONTROL_QUEUE_IDX,
                EVENT_QUEUE_IDX,
                TX_QUEUE_IDX,
                RX_QUEUE_IDX,
            ], Arc::clone(&audio_backend_arc))?)]
        };

        let mut streams = Vec::<StreamInfo>::with_capacity(NR_STREAMS);

        let stream_out_info = StreamInfo::output();
        // TODO: to add a input stream
        streams.push(stream_out_info);

        Ok(Self {
            threads,
            virtio_cfg: VirtioSoundConfig {
                jacks: 0.into(),
                streams: Le32::from(streams.len() as u32),
                chmaps: 0.into(),
            },
            streams_info: streams,
            exit_event: EventFd::new(EFD_NONBLOCK).map_err(Error::EventFdCreate)?
        })
    }

    pub fn send_exit_event(&self) {
        self.exit_event.write(1).unwrap();
    }
}

impl VhostUserBackend<VringRwLock, ()> for VhostUserSoundBackend {
    fn num_queues(&self) -> usize {
        NUM_QUEUES as usize
    }

    fn max_queue_size(&self) -> usize {
        256
    }

    fn features(&self) -> u64 {
        1 << VIRTIO_F_VERSION_1
            | 1 << VIRTIO_F_NOTIFY_ON_EMPTY
            | 1 << VIRTIO_RING_F_INDIRECT_DESC
            | 1 << VIRTIO_RING_F_EVENT_IDX
            | VhostUserVirtioFeatures::PROTOCOL_FEATURES.bits()
    }

    fn protocol_features(&self) -> VhostUserProtocolFeatures {
        VhostUserProtocolFeatures::CONFIG
    }

    fn set_event_idx(&self, enabled: bool) {
        for thread in self.threads.iter() {
            thread.write().unwrap().set_event_idx(enabled);
        }
    }

    fn update_memory(&self, mem: GuestMemoryAtomic<GuestMemoryMmap>) -> IoResult<()> {
        for thread in self.threads.iter() {
            thread.write().unwrap().update_memory(mem.clone())?;
        }

        Ok(())
    }

    fn handle_event(
        &self,
        device_event: u16,
        evset: EventSet,
        vrings: &[VringRwLock],
        thread_id: usize,
    ) -> IoResult<bool> {
        if evset != EventSet::IN {
            return Err(Error::HandleEventNotEpollIn.into());
        }

        self.threads[thread_id]
            .read()
            .unwrap()
            .handle_event(device_event, vrings, &self.streams_info)
    }

    fn get_config(&self, offset: u32, size: u32) -> Vec<u8> {
        let offset = offset as usize;
        let size = size as usize;

        let buf = self.virtio_cfg.as_slice();

        if offset + size > buf.len() {
            return Vec::new();
        }

        buf[offset..offset + size].to_vec()
    }

    fn queues_per_thread(&self) -> Vec<u64> {
        let mut vec = Vec::with_capacity(self.threads.len());

        for thread in self.threads.iter() {
            vec.push(thread.read().unwrap().queues_per_thread())
        }

        vec
    }

    fn exit_event(&self, _thread_index: usize) -> Option<EventFd> {
        self.exit_event.try_clone().ok()
    }
}
