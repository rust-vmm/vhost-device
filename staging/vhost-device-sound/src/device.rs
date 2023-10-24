// Manos Pitsidianakis <manos.pitsidianakis@linaro.org>
// Stefano Garzarella <sgarzare@redhat.com>
// SPDX-License-Identifier: Apache-2.0 or BSD-3-Clause

use std::{
    collections::BTreeSet,
    convert::TryFrom,
    io::Result as IoResult,
    mem::size_of,
    sync::{Arc, RwLock},
};

use vhost::vhost_user::message::{VhostUserProtocolFeatures, VhostUserVirtioFeatures};
use vhost_user_backend::{VhostUserBackend, VringRwLock, VringT};
use virtio_bindings::{
    bindings::virtio_config::{VIRTIO_F_NOTIFY_ON_EMPTY, VIRTIO_F_VERSION_1},
    virtio_ring::{VIRTIO_RING_F_EVENT_IDX, VIRTIO_RING_F_INDIRECT_DESC},
};
use virtio_queue::{DescriptorChain, QueueOwnedT};
use vm_memory::{
    ByteValued, Bytes, GuestAddressSpace, GuestMemoryAtomic, GuestMemoryLoadGuard, GuestMemoryMmap,
};
use vmm_sys_util::{
    epoll::EventSet,
    eventfd::{EventFd, EFD_NONBLOCK},
};

use crate::{
    audio_backends::{alloc_audio_backend, AudioBackend},
    stream::{Buffer, Error as StreamError, Stream},
    virtio_sound::{self, *},
    ControlMessageKind, Error, IOMessage, Result, SoundConfig,
};

pub struct VhostUserSoundThread {
    mem: Option<GuestMemoryAtomic<GuestMemoryMmap>>,
    event_idx: bool,
    chmaps: Arc<RwLock<Vec<VirtioSoundChmapInfo>>>,
    jacks: Arc<RwLock<Vec<VirtioSoundJackInfo>>>,
    queue_indexes: Vec<u16>,
    streams: Arc<RwLock<Vec<Stream>>>,
    streams_no: usize,
}

type SoundDescriptorChain = DescriptorChain<GuestMemoryLoadGuard<GuestMemoryMmap<()>>>;

impl VhostUserSoundThread {
    pub fn new(
        chmaps: Arc<RwLock<Vec<VirtioSoundChmapInfo>>>,
        jacks: Arc<RwLock<Vec<VirtioSoundJackInfo>>>,
        mut queue_indexes: Vec<u16>,
        streams: Arc<RwLock<Vec<Stream>>>,
        streams_no: usize,
    ) -> Result<Self> {
        queue_indexes.sort();

        Ok(Self {
            event_idx: false,
            mem: None,
            chmaps,
            jacks,
            queue_indexes,
            streams,
            streams_no,
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
        self.mem = Some(mem);
        Ok(())
    }

    fn handle_event(
        &self,
        device_event: u16,
        vrings: &[VringRwLock],
        audio_backend: &RwLock<Box<dyn AudioBackend + Send + Sync>>,
    ) -> IoResult<bool> {
        let vring = &vrings[device_event as usize];
        let queue_idx = self.queue_indexes[device_event as usize];
        if self.event_idx {
            // vm-virtio's Queue implementation only checks avail_index
            // once, so to properly support EVENT_IDX we need to keep
            // calling process_request_queue() until it stops finding
            // new requests on the queue.
            loop {
                vring.disable_notification().unwrap();
                match queue_idx {
                    CONTROL_QUEUE_IDX => self.process_control(vring, audio_backend),
                    EVENT_QUEUE_IDX => self.process_event(vring),
                    TX_QUEUE_IDX => self.process_tx(vring, audio_backend),
                    RX_QUEUE_IDX => self.process_rx(vring, audio_backend),
                    _ => Err(Error::HandleUnknownEvent.into()),
                }?;
                if !vring.enable_notification().unwrap() {
                    break;
                }
            }
        } else {
            // Without EVENT_IDX, a single call is enough.
            match queue_idx {
                CONTROL_QUEUE_IDX => self.process_control(vring, audio_backend),
                EVENT_QUEUE_IDX => self.process_event(vring),
                TX_QUEUE_IDX => self.process_tx(vring, audio_backend),
                RX_QUEUE_IDX => self.process_rx(vring, audio_backend),
                _ => Err(Error::HandleUnknownEvent.into()),
            }?;
        }
        Ok(false)
    }

    fn process_control(
        &self,
        vring: &VringRwLock,
        audio_backend: &RwLock<Box<dyn AudioBackend + Send + Sync>>,
    ) -> IoResult<bool> {
        let Some(ref atomic_mem) = self.mem else {
            return Err(Error::NoMemoryConfigured.into());
        };
        let requests: Vec<SoundDescriptorChain> = vring
            .get_mut()
            .get_queue_mut()
            .iter(atomic_mem.memory())
            .map_err(|_| Error::DescriptorNotFound)?
            .collect();

        if requests.is_empty() {
            return Ok(true);
        }

        // Reply to some requests right away, and defer others to the audio backend (for
        // example PcmRelease needs to complete all I/O before replying.
        //
        // Mark `any` as true if we need to reply to any request right away so we can
        // signal the queue as used.
        let mut any = false;

        for desc_chain in requests {
            let descriptors: Vec<_> = desc_chain.clone().collect();
            if descriptors.len() < 2 {
                return Err(Error::UnexpectedDescriptorCount(descriptors.len()).into());
            }

            // Request descriptor.
            let desc_request = descriptors[0];
            if desc_request.is_write_only() {
                return Err(Error::UnexpectedWriteOnlyDescriptor(0).into());
            }

            let request = desc_chain
                .memory()
                .read_obj::<VirtioSoundHeader>(desc_request.addr())
                .map_err(|_| Error::DescriptorReadFailed)?;

            // Keep track of bytes that will be written in the VQ.
            let mut used_len = 0;

            // Reply header descriptor.
            let desc_hdr = descriptors[1];
            if !desc_hdr.is_write_only() {
                return Err(Error::UnexpectedReadableDescriptor(1).into());
            }

            let mut resp = VirtioSoundHeader {
                code: VIRTIO_SND_S_OK.into(),
            };

            let code = ControlMessageKind::try_from(request.code).map_err(Error::from)?;
            match code {
                ControlMessageKind::ChmapInfo => {
                    if descriptors.len() != 3 {
                        log::error!("a CHMAP_INFO request should have three descriptors total.");
                        return Err(Error::UnexpectedDescriptorCount(descriptors.len()).into());
                    } else if !descriptors[2].is_write_only() {
                        log::error!(
                            "a CHMAP_INFO request should have a writeable descriptor for the info \
                             payload response after the header status response"
                        );
                        return Err(Error::UnexpectedReadableDescriptor(2).into());
                    }
                    let request = desc_chain
                        .memory()
                        .read_obj::<VirtioSoundQueryInfo>(desc_request.addr())
                        .map_err(|_| Error::DescriptorReadFailed)?;
                    let start_id = u32::from(request.start_id) as usize;
                    let count = u32::from(request.count) as usize;
                    let chmaps = self.chmaps.read().unwrap();
                    if chmaps.len() <= start_id || chmaps.len() < start_id + count {
                        resp.code = VIRTIO_SND_S_BAD_MSG.into();
                    } else {
                        let desc_response = descriptors[2];
                        let mut buf = vec![];

                        for i in chmaps.iter().skip(start_id).take(count) {
                            buf.extend_from_slice(i.as_slice());
                        }
                        desc_chain
                            .memory()
                            .write_slice(&buf, desc_response.addr())
                            .map_err(|_| Error::DescriptorWriteFailed)?;
                        used_len += desc_response.len();
                    }
                }
                ControlMessageKind::JackInfo => {
                    if descriptors.len() != 3 {
                        log::error!("a JACK_INFO request should have three descriptors total.");
                        return Err(Error::UnexpectedDescriptorCount(descriptors.len()).into());
                    } else if !descriptors[2].is_write_only() {
                        log::error!(
                            "a JACK_INFO request should have a writeable descriptor for the info \
                             payload response after the header status response"
                        );
                        return Err(Error::UnexpectedReadableDescriptor(2).into());
                    }
                    let request = desc_chain
                        .memory()
                        .read_obj::<VirtioSoundQueryInfo>(desc_request.addr())
                        .map_err(|_| Error::DescriptorReadFailed)?;

                    let start_id = u32::from(request.start_id) as usize;
                    let count = u32::from(request.count) as usize;
                    let jacks = self.jacks.read().unwrap();
                    if jacks.len() <= start_id || jacks.len() < start_id + count {
                        resp.code = VIRTIO_SND_S_BAD_MSG.into();
                    } else {
                        let desc_response = descriptors[2];
                        let mut buf = vec![];

                        for i in jacks.iter().skip(start_id).take(count) {
                            buf.extend_from_slice(i.as_slice());
                        }
                        desc_chain
                            .memory()
                            .write_slice(&buf, desc_response.addr())
                            .map_err(|_| Error::DescriptorWriteFailed)?;
                        used_len += desc_response.len();
                    }
                }
                ControlMessageKind::JackRemap => {
                    resp.code = VIRTIO_SND_S_NOT_SUPP.into();
                }
                ControlMessageKind::PcmInfo => {
                    if descriptors.len() != 3 {
                        log::error!("a PCM_INFO request should have three descriptors total.");
                        return Err(Error::UnexpectedDescriptorCount(descriptors.len()).into());
                    } else if !descriptors[2].is_write_only() {
                        log::error!(
                            "a PCM_INFO request should have a writeable descriptor for the info \
                             payload response after the header status response"
                        );
                        return Err(Error::UnexpectedReadableDescriptor(2).into());
                    }

                    let request = desc_chain
                        .memory()
                        .read_obj::<VirtioSoundQueryInfo>(desc_request.addr())
                        .map_err(|_| Error::DescriptorReadFailed)?;

                    let start_id = u32::from(request.start_id) as usize;
                    let count = u32::from(request.count) as usize;
                    let streams = self.streams.read().unwrap();
                    if streams.len() <= start_id || streams.len() < start_id + count {
                        resp.code = VIRTIO_SND_S_BAD_MSG.into();
                    } else {
                        let desc_response = descriptors[2];

                        let mut buf = vec![];
                        let mut p: VirtioSoundPcmInfo;

                        for s in streams
                            .iter()
                            .skip(u32::from(request.start_id) as usize)
                            .take(u32::from(request.count) as usize)
                        {
                            p = VirtioSoundPcmInfo::default();
                            p.hdr.hda_fn_nid = 0.into();
                            p.features = s.params.features;
                            p.formats = s.formats;
                            p.rates = s.rates;
                            p.direction = s.direction;
                            p.channels_min = s.channels_min;
                            p.channels_max = s.channels_max;
                            buf.extend_from_slice(p.as_slice());
                        }
                        desc_chain
                            .memory()
                            .write_slice(&buf, desc_response.addr())
                            .map_err(|_| Error::DescriptorWriteFailed)?;
                        used_len += desc_response.len();
                    }
                }
                ControlMessageKind::PcmSetParams => {
                    let request = desc_chain
                        .memory()
                        .read_obj::<VirtioSndPcmSetParams>(desc_request.addr())
                        .map_err(|_| Error::DescriptorReadFailed)?;
                    let stream_id: u32 = request.hdr.stream_id.into();

                    if stream_id as usize >= self.streams_no {
                        log::error!("{}", Error::from(StreamError::InvalidStreamId(stream_id)));
                        resp.code = VIRTIO_SND_S_BAD_MSG.into();
                    } else {
                        audio_backend
                            .read()
                            .unwrap()
                            .set_parameters(
                                stream_id,
                                ControlMessage {
                                    kind: code,
                                    code: VIRTIO_SND_S_OK,
                                    desc_chain,
                                    descriptor: desc_hdr,
                                    vring: vring.clone(),
                                },
                            )
                            .unwrap();

                        // PcmSetParams needs check valid formats/rates; the audio backend will
                        // reply when it drops the ControlMessage.
                        continue;
                    }
                }
                ControlMessageKind::PcmPrepare => {
                    let request = desc_chain
                        .memory()
                        .read_obj::<VirtioSoundPcmHeader>(desc_request.addr())
                        .map_err(|_| Error::DescriptorReadFailed)?;
                    let stream_id = request.stream_id.into();

                    if stream_id as usize >= self.streams_no {
                        log::error!("{}", Error::from(StreamError::InvalidStreamId(stream_id)));
                        resp.code = VIRTIO_SND_S_BAD_MSG.into();
                    } else {
                        audio_backend.write().unwrap().prepare(stream_id).unwrap();
                    }
                }
                ControlMessageKind::PcmRelease => {
                    let request = desc_chain
                        .memory()
                        .read_obj::<VirtioSoundPcmHeader>(desc_request.addr())
                        .map_err(|_| Error::DescriptorReadFailed)?;
                    let stream_id = request.stream_id.into();

                    if stream_id as usize >= self.streams_no {
                        log::error!("{}", Error::from(StreamError::InvalidStreamId(stream_id)));
                        resp.code = VIRTIO_SND_S_BAD_MSG.into();
                    } else {
                        audio_backend
                            .write()
                            .unwrap()
                            .release(
                                stream_id,
                                ControlMessage {
                                    kind: code,
                                    code: VIRTIO_SND_S_OK,
                                    desc_chain,
                                    descriptor: desc_hdr,
                                    vring: vring.clone(),
                                },
                            )
                            .unwrap();

                        // PcmRelease needs to flush IO messages; the audio backend will reply when
                        // it drops the ControlMessage.
                        continue;
                    }
                }
                ControlMessageKind::PcmStart => {
                    let request = desc_chain
                        .memory()
                        .read_obj::<VirtioSoundPcmHeader>(desc_request.addr())
                        .map_err(|_| Error::DescriptorReadFailed)?;
                    let stream_id = request.stream_id.into();

                    if stream_id as usize >= self.streams_no {
                        log::error!("{}", Error::from(StreamError::InvalidStreamId(stream_id)));
                        resp.code = VIRTIO_SND_S_BAD_MSG.into();
                    } else {
                        audio_backend.write().unwrap().start(stream_id).unwrap();
                    }
                }
                ControlMessageKind::PcmStop => {
                    let request = desc_chain
                        .memory()
                        .read_obj::<VirtioSoundPcmHeader>(desc_request.addr())
                        .map_err(|_| Error::DescriptorReadFailed)?;
                    let stream_id = request.stream_id.into();

                    if stream_id as usize >= self.streams_no {
                        log::error!("{}", Error::from(StreamError::InvalidStreamId(stream_id)));
                        resp.code = VIRTIO_SND_S_BAD_MSG.into();
                    } else {
                        audio_backend.write().unwrap().stop(stream_id).unwrap();
                    }
                }
            }
            log::trace!(
                "returned {} for ctrl msg {:?}",
                match u32::from(resp.code) {
                    v if v == VIRTIO_SND_S_OK => "OK",
                    v if v == VIRTIO_SND_S_BAD_MSG => "BAD_MSG",
                    v if v == VIRTIO_SND_S_NOT_SUPP => "NOT_SUPP",
                    v if v == VIRTIO_SND_S_IO_ERR => "IO_ERR",
                    _ => unreachable!(),
                },
                code
            );
            desc_chain
                .memory()
                .write_obj(resp, desc_hdr.addr())
                .map_err(|_| Error::DescriptorWriteFailed)?;
            used_len += desc_hdr.len();

            if vring.add_used(desc_chain.head_index(), used_len).is_err() {
                log::error!("Couldn't return used descriptors to the ring");
            }
            any |= true;
        }

        // In which cases can happen that we get here and any is false?
        // PCM_RELEASE and PCM_SET_PARAMS need to be handled asynchronously, therefore
        // it will be their responsibility to `signal_used_queue`.

        // Send notification if any request was processed
        if any && vring.signal_used_queue().is_err() {
            log::error!("Couldn't signal used queue");
        }

        Ok(!any)
    }

    fn process_event(&self, _vring: &VringRwLock) -> IoResult<bool> {
        log::trace!("process_event");
        Ok(false)
    }

    fn process_tx(
        &self,
        vring: &VringRwLock,
        audio_backend: &RwLock<Box<dyn AudioBackend + Send + Sync>>,
    ) -> IoResult<bool> {
        let Some(ref atomic_mem) = self.mem else {
            return Err(Error::NoMemoryConfigured.into());
        };
        let requests: Vec<SoundDescriptorChain> = vring
            .get_mut()
            .get_queue_mut()
            .iter(atomic_mem.memory())
            .map_err(|_| Error::DescriptorNotFound)?
            .collect();

        if requests.is_empty() {
            return Ok(true);
        }

        // Instead of counting descriptor chain lengths, encode the "parsing" logic in
        // an enumeration. Then, the compiler will complain about any unhandled
        // match {} cases if any part of the code is changed. This makes invalid
        // states unrepresentable in the source code.
        #[derive(Copy, Clone, PartialEq, Debug)]
        enum IoState {
            Ready,
            WaitingBufferForStreamId(u32),
            Done,
        }

        // Keep log of stream IDs to wake up, in case the guest has queued more than
        // one.
        let mut stream_ids = BTreeSet::default();

        for desc_chain in requests {
            let mut state = IoState::Ready;
            let mut buffers = vec![];
            let descriptors: Vec<_> = desc_chain.clone().collect();
            let message = Arc::new(IOMessage {
                vring: vring.clone(),
                status: VIRTIO_SND_S_OK.into(),
                latency_bytes: 0.into(),
                desc_chain: desc_chain.clone(),
                response_descriptor: descriptors.last().cloned().ok_or_else(|| {
                    log::error!("Received IO request with an empty descriptor chain.");
                    Error::UnexpectedDescriptorCount(0)
                })?,
            });
            for descriptor in &descriptors {
                match state {
                    IoState::Done => {
                        return Err(Error::UnexpectedDescriptorCount(descriptors.len()).into());
                    }
                    IoState::Ready if descriptor.is_write_only() => {
                        if descriptor.len() as usize != size_of::<VirtioSoundPcmStatus>() {
                            return Err(Error::UnexpectedDescriptorSize(
                                size_of::<VirtioSoundPcmStatus>(),
                                descriptor.len(),
                            )
                            .into());
                        }
                        state = IoState::Done;
                    }
                    IoState::WaitingBufferForStreamId(stream_id) if descriptor.is_write_only() => {
                        if descriptor.len() as usize != size_of::<VirtioSoundPcmStatus>() {
                            return Err(Error::UnexpectedDescriptorSize(
                                size_of::<VirtioSoundPcmStatus>(),
                                descriptor.len(),
                            )
                            .into());
                        }
                        let mut streams = self.streams.write().unwrap();
                        for b in std::mem::take(&mut buffers) {
                            streams[stream_id as usize].buffers.push_back(b);
                        }
                        state = IoState::Done;
                    }
                    IoState::Ready
                        if descriptor.len() as usize != size_of::<VirtioSoundPcmXfer>() =>
                    {
                        return Err(Error::UnexpectedDescriptorSize(
                            size_of::<VirtioSoundPcmXfer>(),
                            descriptor.len(),
                        )
                        .into());
                    }
                    IoState::Ready => {
                        let xfer = desc_chain
                            .memory()
                            .read_obj::<VirtioSoundPcmXfer>(descriptor.addr())
                            .map_err(|_| Error::DescriptorReadFailed)?;
                        let stream_id: u32 = xfer.stream_id.into();
                        stream_ids.insert(stream_id);

                        state = IoState::WaitingBufferForStreamId(stream_id);
                    }
                    IoState::WaitingBufferForStreamId(stream_id)
                        if descriptor.len() as usize == size_of::<VirtioSoundPcmXfer>() =>
                    {
                        return Err(Error::UnexpectedDescriptorSize(
                            u32::from(
                                self.streams.read().unwrap()[stream_id as usize]
                                    .params
                                    .buffer_bytes,
                            ) as usize,
                            descriptor.len(),
                        )
                        .into());
                    }
                    IoState::WaitingBufferForStreamId(_stream_id) => {
                        // In the case of TX/Playback:
                        //
                        // Rather than copying the content of a descriptor, buffer keeps a pointer
                        // to it. When we copy just after the request is enqueued, the guest's
                        // userspace may or may not have updated the buffer contents. Guest driver
                        // simply moves buffers from the used ring to the available ring without
                        // knowing whether the content has been updated. The device only reads the
                        // buffer from guest memory when the audio engine requires it, which is
                        // about after a period thus ensuring that the buffer is up-to-date.
                        buffers.push(Buffer::new(*descriptor, Arc::clone(&message)));
                    }
                }
            }
        }

        if !stream_ids.is_empty() {
            let b = audio_backend.write().unwrap();
            for id in stream_ids {
                b.write(id).unwrap();
            }
        }

        Ok(false)
    }

    fn process_rx(
        &self,
        _vring: &VringRwLock,
        _audio_backend: &RwLock<Box<dyn AudioBackend + Send + Sync>>,
    ) -> IoResult<bool> {
        log::trace!("process_rx");
        Ok(false)
    }
}

pub struct VhostUserSoundBackend {
    pub threads: Vec<RwLock<VhostUserSoundThread>>,
    virtio_cfg: VirtioSoundConfig,
    pub exit_event: EventFd,
    audio_backend: RwLock<Box<dyn AudioBackend + Send + Sync>>,
}

impl VhostUserSoundBackend {
    pub fn new(config: SoundConfig) -> Result<Self> {
        let streams = vec![
            Stream {
                id: 0,
                direction: VIRTIO_SND_D_OUTPUT,
                ..Stream::default()
            },
            Stream {
                id: 1,
                direction: VIRTIO_SND_D_INPUT,
                ..Stream::default()
            },
        ];
        let streams_no = streams.len();
        let streams = Arc::new(RwLock::new(streams));
        let jacks: Arc<RwLock<Vec<VirtioSoundJackInfo>>> = Arc::new(RwLock::new(Vec::new()));
        let mut positions = [VIRTIO_SND_CHMAP_NONE; VIRTIO_SND_CHMAP_MAX_SIZE];
        positions[0] = VIRTIO_SND_CHMAP_FL;
        positions[1] = VIRTIO_SND_CHMAP_FR;
        let chmaps_info: Vec<VirtioSoundChmapInfo> = vec![
            VirtioSoundChmapInfo {
                direction: VIRTIO_SND_D_OUTPUT,
                channels: 2,
                positions,
                ..VirtioSoundChmapInfo::default()
            },
            VirtioSoundChmapInfo {
                direction: VIRTIO_SND_D_INPUT,
                channels: 2,
                positions,
                ..VirtioSoundChmapInfo::default()
            },
        ];
        let chmaps: Arc<RwLock<Vec<VirtioSoundChmapInfo>>> = Arc::new(RwLock::new(chmaps_info));
        log::trace!("VhostUserSoundBackend::new(config = {:?})", &config);
        let threads = if config.multi_thread {
            vec![
                RwLock::new(VhostUserSoundThread::new(
                    chmaps.clone(),
                    jacks.clone(),
                    vec![CONTROL_QUEUE_IDX, EVENT_QUEUE_IDX],
                    streams.clone(),
                    streams_no,
                )?),
                RwLock::new(VhostUserSoundThread::new(
                    chmaps.clone(),
                    jacks.clone(),
                    vec![TX_QUEUE_IDX],
                    streams.clone(),
                    streams_no,
                )?),
                RwLock::new(VhostUserSoundThread::new(
                    chmaps.clone(),
                    jacks.clone(),
                    vec![RX_QUEUE_IDX],
                    streams.clone(),
                    streams_no,
                )?),
            ]
        } else {
            vec![RwLock::new(VhostUserSoundThread::new(
                chmaps.clone(),
                jacks.clone(),
                vec![
                    CONTROL_QUEUE_IDX,
                    EVENT_QUEUE_IDX,
                    TX_QUEUE_IDX,
                    RX_QUEUE_IDX,
                ],
                streams.clone(),
                streams_no,
            )?)]
        };

        let audio_backend = alloc_audio_backend(config.audio_backend, streams)?;

        Ok(Self {
            threads,
            virtio_cfg: VirtioSoundConfig {
                jacks: 0.into(),
                streams: 1.into(),
                chmaps: 1.into(),
            },
            exit_event: EventFd::new(EFD_NONBLOCK).map_err(Error::EventFdCreate)?,
            audio_backend: RwLock::new(audio_backend),
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
        // The linux kernel driver does no checks for queue length and fails silently if
        // a queue is filled up. In this case, adding an element to the queue
        // returns ENOSPC and the element is not queued for a later attempt and
        // is lost. `64` is a "good enough" value from our observations.
        64
    }

    fn features(&self) -> u64 {
        1 << VIRTIO_F_VERSION_1
            | 1 << VIRTIO_F_NOTIFY_ON_EMPTY
            | 1 << VIRTIO_RING_F_INDIRECT_DESC
            | 1 << VIRTIO_RING_F_EVENT_IDX
            | VhostUserVirtioFeatures::PROTOCOL_FEATURES.bits()
    }

    fn protocol_features(&self) -> VhostUserProtocolFeatures {
        VhostUserProtocolFeatures::CONFIG | VhostUserProtocolFeatures::MQ
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

        self.threads[thread_id].read().unwrap().handle_event(
            device_event,
            vrings,
            &self.audio_backend,
        )
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

#[cfg_attr(test, derive(Clone))]
pub struct ControlMessage {
    pub kind: ControlMessageKind,
    pub code: u32,
    pub desc_chain: SoundDescriptorChain,
    pub descriptor: virtio_queue::Descriptor,
    pub vring: VringRwLock,
}

impl std::fmt::Debug for ControlMessage {
    fn fmt(&self, fmt: &mut std::fmt::Formatter) -> std::fmt::Result {
        fmt.debug_struct(stringify!(ControlMessage))
            .field("kind", &self.kind)
            .field("code", &self.code)
            .finish()
    }
}

impl Drop for ControlMessage {
    fn drop(&mut self) {
        log::trace!(
            "dropping ControlMessage {:?} reply = {}",
            self.kind,
            match self.code {
                virtio_sound::VIRTIO_SND_S_OK => "VIRTIO_SND_S_OK",
                virtio_sound::VIRTIO_SND_S_BAD_MSG => "VIRTIO_SND_S_BAD_MSG",
                virtio_sound::VIRTIO_SND_S_NOT_SUPP => "VIRTIO_SND_S_NOT_SUPP",
                virtio_sound::VIRTIO_SND_S_IO_ERR => "VIRTIO_SND_S_IO_ERR",
                _ => "other",
            }
        );
        let resp = VirtioSoundHeader {
            code: self.code.into(),
        };

        if let Err(err) = self
            .desc_chain
            .memory()
            .write_obj(resp, self.descriptor.addr())
        {
            log::error!("Error::DescriptorWriteFailed: {}", err);
            return;
        }
        if self
            .vring
            .add_used(self.desc_chain.head_index(), resp.as_slice().len() as u32)
            .is_err()
        {
            log::error!("Couldn't add used");
        }
        if self.vring.signal_used_queue().is_err() {
            log::error!("Couldn't signal used queue");
        }
    }
}

#[cfg(test)]
mod tests {
    use tempfile::tempdir;
    use vm_memory::GuestAddress;

    use super::*;
    use crate::BackendType;

    const SOCKET_PATH: &str = "vsound.socket";

    #[test]
    fn test_sound_thread_success() {
        let config = SoundConfig::new(SOCKET_PATH.to_string(), false, BackendType::Null);

        let chmaps = Arc::new(RwLock::new(vec![]));
        let jacks = Arc::new(RwLock::new(vec![]));
        let queue_indexes = vec![1, 2, 3];
        let streams = vec![Stream::default()];
        let streams_no = streams.len();
        let streams = Arc::new(RwLock::new(streams));
        let thread =
            VhostUserSoundThread::new(chmaps, jacks, queue_indexes, streams.clone(), streams_no);

        assert!(thread.is_ok());
        let mut t = thread.unwrap();

        // Mock memory
        let mem = GuestMemoryAtomic::new(
            GuestMemoryMmap::<()>::from_ranges(&[(GuestAddress(0), 0x10000)]).unwrap(),
        );
        t.mem = Some(mem.clone());

        // Mock Vring for queues
        let vrings = [
            VringRwLock::new(mem.clone(), 0x1000).unwrap(),
            VringRwLock::new(mem.clone(), 0x1000).unwrap(),
        ];

        let audio_backend =
            RwLock::new(alloc_audio_backend(config.audio_backend, streams.clone()).unwrap());
        assert!(t
            .handle_event(CONTROL_QUEUE_IDX, &vrings, &audio_backend)
            .is_ok());

        let vring = VringRwLock::new(mem, 0x1000).unwrap();
        vring.set_queue_info(0x100, 0x200, 0x300).unwrap();
        vring.set_queue_ready(true);
        assert!(t.process_control(&vring, &audio_backend).is_ok());
        assert!(t.process_tx(&vring, &audio_backend).is_ok());
        assert!(t.process_rx(&vring, &audio_backend).is_ok());
    }

    #[test]
    fn test_sound_thread_failure() {
        let config = SoundConfig::new(SOCKET_PATH.to_string(), false, BackendType::Null);

        let chmaps = Arc::new(RwLock::new(vec![]));
        let jacks = Arc::new(RwLock::new(vec![]));
        let queue_indexes = vec![1, 2, 3];
        let streams = Arc::new(RwLock::new(vec![]));
        let streams_no = 0;
        let thread =
            VhostUserSoundThread::new(chmaps, jacks, queue_indexes, streams.clone(), streams_no);

        let t = thread.unwrap();
        let mem = GuestMemoryAtomic::new(
            GuestMemoryMmap::<()>::from_ranges(&[(GuestAddress(0), 0x10000)]).unwrap(),
        );

        let audio_backend =
            RwLock::new(alloc_audio_backend(config.audio_backend, streams.clone()).unwrap());

        let vring = VringRwLock::new(mem, 0x1000).unwrap();
        vring.set_queue_info(0x100, 0x200, 0x300).unwrap();
        vring.set_queue_ready(true);
        assert!(t.process_control(&vring, &audio_backend).is_err());
        assert!(t.process_tx(&vring, &audio_backend).is_err());
    }

    #[test]
    fn test_sound_backend() {
        let test_dir = tempdir().expect("Could not create a temp test directory.");
        let socket_path = test_dir.path().join(SOCKET_PATH).display().to_string();
        let config = SoundConfig::new(socket_path, false, BackendType::Null);
        let backend = VhostUserSoundBackend::new(config).expect("Could not create backend.");

        assert_eq!(backend.num_queues(), NUM_QUEUES as usize);
        assert_eq!(backend.max_queue_size(), 64);
        assert_ne!(backend.features(), 0);
        assert!(!backend.protocol_features().is_empty());
        backend.set_event_idx(false);

        // Mock memory
        let mem = GuestMemoryAtomic::new(
            GuestMemoryMmap::<()>::from_ranges(&[(GuestAddress(0), 0x10000)]).unwrap(),
        );

        // Mock Vring for queues
        let vrings = [
            VringRwLock::new(mem.clone(), 0x1000).unwrap(),
            VringRwLock::new(mem.clone(), 0x1000).unwrap(),
            VringRwLock::new(mem.clone(), 0x1000).unwrap(),
            VringRwLock::new(mem.clone(), 0x1000).unwrap(),
        ];
        vrings[CONTROL_QUEUE_IDX as usize]
            .set_queue_info(0x100, 0x200, 0x300)
            .unwrap();
        vrings[CONTROL_QUEUE_IDX as usize].set_queue_ready(true);
        vrings[EVENT_QUEUE_IDX as usize]
            .set_queue_info(0x100, 0x200, 0x300)
            .unwrap();
        vrings[EVENT_QUEUE_IDX as usize].set_queue_ready(true);
        vrings[TX_QUEUE_IDX as usize]
            .set_queue_info(0x1100, 0x1200, 0x1300)
            .unwrap();
        vrings[TX_QUEUE_IDX as usize].set_queue_ready(true);
        vrings[RX_QUEUE_IDX as usize]
            .set_queue_info(0x100, 0x200, 0x300)
            .unwrap();
        vrings[RX_QUEUE_IDX as usize].set_queue_ready(true);

        assert!(backend.update_memory(mem).is_ok());

        let queues_per_thread = backend.queues_per_thread();
        assert_eq!(queues_per_thread.len(), 1);
        assert_eq!(queues_per_thread[0], 0xf);

        let config = backend.get_config(0, 8);
        assert_eq!(config.len(), 8);

        let exit = backend.exit_event(0);
        assert!(exit.is_some());
        exit.unwrap().write(1).unwrap();

        let ret = backend.handle_event(CONTROL_QUEUE_IDX, EventSet::IN, &vrings, 0);
        assert!(ret.is_ok());
        assert!(!ret.unwrap());

        let ret = backend.handle_event(EVENT_QUEUE_IDX, EventSet::IN, &vrings, 0);
        assert!(ret.is_ok());
        assert!(!ret.unwrap());

        let ret = backend.handle_event(TX_QUEUE_IDX, EventSet::IN, &vrings, 0);
        assert!(ret.is_ok());
        assert!(!ret.unwrap());

        let ret = backend.handle_event(RX_QUEUE_IDX, EventSet::IN, &vrings, 0);
        assert!(ret.is_ok());
        assert!(!ret.unwrap());

        test_dir.close().unwrap();
    }

    #[test]
    fn test_sound_backend_failures() {
        let test_dir = tempdir().expect("Could not create a temp test directory.");

        let socket_path = test_dir
            .path()
            .join("sound_failures.socket")
            .display()
            .to_string();
        let config = SoundConfig::new(socket_path, false, BackendType::Null);
        let backend = VhostUserSoundBackend::new(config);

        let backend = backend.unwrap();

        // Mock memory
        let mem = GuestMemoryAtomic::new(
            GuestMemoryMmap::<()>::from_ranges(&[(GuestAddress(0), 0x10000)]).unwrap(),
        );

        // Mock Vring for queues
        let vrings = [
            VringRwLock::new(mem.clone(), 0x1000).unwrap(),
            VringRwLock::new(mem.clone(), 0x1000).unwrap(),
            VringRwLock::new(mem.clone(), 0x1000).unwrap(),
            VringRwLock::new(mem.clone(), 0x1000).unwrap(),
        ];

        // Update memory
        backend.update_memory(mem).unwrap();

        let config = backend.get_config(2, 8);
        assert_eq!(config.len(), 8);

        let ret = backend.handle_event(CONTROL_QUEUE_IDX, EventSet::IN, &vrings, 0);
        assert_eq!(
            ret.unwrap_err().to_string(),
            Error::DescriptorNotFound.to_string()
        );

        // Currently handles a single device event, anything higher than 0 will generate
        // an error.
        let ret = backend.handle_event(TX_QUEUE_IDX, EventSet::IN, &vrings, 0);
        assert_eq!(
            ret.unwrap_err().to_string(),
            Error::DescriptorNotFound.to_string()
        );

        // Currently handles EventSet::IN only, otherwise an error is generated.
        let ret = backend.handle_event(RX_QUEUE_IDX, EventSet::OUT, &vrings, 0);
        assert_eq!(
            ret.unwrap_err().to_string(),
            Error::HandleEventNotEpollIn.to_string()
        );

        test_dir.close().unwrap();
    }
}
