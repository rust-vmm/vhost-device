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
    ByteValued, GuestAddressSpace, GuestMemoryAtomic, GuestMemoryLoadGuard, GuestMemoryMmap, Le32,
};
use vmm_sys_util::{
    epoll::EventSet,
    eventfd::{EventFd, EFD_NONBLOCK},
};

use crate::{
    audio_backends::{alloc_audio_backend, AudioBackend},
    stream::{Error as StreamError, Request, Stream},
    virtio_sound::*,
    ControlMessageKind, Direction, Error, IOMessage, QueueIdx, Result, SoundConfig,
};

pub struct VhostUserSoundThread {
    mem: Option<GuestMemoryAtomic<GuestMemoryMmap>>,
    event_idx: bool,
    chmaps: Arc<RwLock<Vec<VirtioSoundChmapInfo>>>,
    jacks: Arc<RwLock<Vec<VirtioSoundJackInfo>>>,
    queue_indexes: Vec<QueueIdx>,
    streams: Arc<RwLock<Vec<Stream>>>,
    streams_no: usize,
}

type SoundDescriptorChain = DescriptorChain<GuestMemoryLoadGuard<GuestMemoryMmap<()>>>;

impl VhostUserSoundThread {
    pub fn new(
        chmaps: Arc<RwLock<Vec<VirtioSoundChmapInfo>>>,
        jacks: Arc<RwLock<Vec<VirtioSoundJackInfo>>>,
        mut queue_indexes: Vec<QueueIdx>,
        streams: Arc<RwLock<Vec<Stream>>>,
        streams_no: usize,
    ) -> Result<Self> {
        queue_indexes.sort_by_key(|idx| *idx as u16);

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
            queues_per_thread |= 1u64 << *idx as u16
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
    ) -> IoResult<()> {
        let vring = &vrings
            .get(device_event as usize)
            .ok_or(Error::HandleUnknownEvent(device_event))?;
        let queue_idx = self
            .queue_indexes
            .get(device_event as usize)
            .ok_or(Error::HandleUnknownEvent(device_event))?;
        if self.event_idx {
            // vm-virtio's Queue implementation only checks avail_index
            // once, so to properly support EVENT_IDX we need to keep
            // calling process_request_queue() until it stops finding
            // new requests on the queue.
            loop {
                vring.disable_notification().unwrap();
                match queue_idx {
                    QueueIdx::Control => self.process_control(vring, audio_backend),
                    QueueIdx::Event => self.process_event(vring),
                    QueueIdx::Tx => self.process_io(vring, audio_backend, Direction::Output),
                    QueueIdx::Rx => self.process_io(vring, audio_backend, Direction::Input),
                }?;
                if !vring.enable_notification().unwrap() {
                    break;
                }
            }
        } else {
            // Without EVENT_IDX, a single call is enough.
            match queue_idx {
                QueueIdx::Control => self.process_control(vring, audio_backend),
                QueueIdx::Event => self.process_event(vring),
                QueueIdx::Tx => self.process_io(vring, audio_backend, Direction::Output),
                QueueIdx::Rx => self.process_io(vring, audio_backend, Direction::Input),
            }?;
        }
        Ok(())
    }

    #[allow(clippy::cognitive_complexity)]
    fn process_control(
        &self,
        vring: &VringRwLock,
        audio_backend: &RwLock<Box<dyn AudioBackend + Send + Sync>>,
    ) -> IoResult<()> {
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
            return Ok(());
        }

        // Reply to some requests right away, and defer others to the audio backend (for
        // example PcmRelease needs to complete all I/O before replying.
        //
        // Mark `any` as true if we need to reply to any request right away so we can
        // signal the queue as used.
        let mut any = false;

        for desc_chain in requests {
            let mem = atomic_mem.memory();

            let mut reader = desc_chain
                .clone()
                .reader(&mem)
                .map_err(|_| Error::DescriptorReadFailed)?;

            let mut writer_status = desc_chain
                .clone()
                .writer(&mem)
                .map_err(|_| Error::DescriptorReadFailed)?;

            let mut writer_content = writer_status
                .split_at(size_of::<VirtioSoundHeader>())
                .map_err(|_| Error::DescriptorReadFailed)?;

            let request = reader
                .read_obj::<VirtioSoundHeader>()
                .map_err(|_| Error::DescriptorReadFailed)?;

            // Keep track of bytes that will be written in the VQ.
            let mut used_len = 0;

            let mut resp = VirtioSoundHeader {
                code: VIRTIO_SND_S_OK.into(),
            };

            let code = ControlMessageKind::try_from(request.code).map_err(Error::from)?;
            match code {
                ControlMessageKind::ChmapInfo => {
                    let request = reader
                        .read_obj::<VirtioSoundQueryInfo>()
                        .map_err(|_| Error::DescriptorReadFailed)?;

                    let start_id = u32::from(request.start_id) as usize;
                    let count = u32::from(request.count) as usize;
                    let chmaps = self.chmaps.read().unwrap();
                    if chmaps.len() <= start_id || chmaps.len() < start_id + count {
                        resp.code = VIRTIO_SND_S_BAD_MSG.into();
                    } else {
                        for i in chmaps.iter().skip(start_id).take(count) {
                            writer_content
                                .write_obj(*i)
                                .map_err(|_| Error::DescriptorWriteFailed)?;
                        }
                        drop(chmaps);
                        used_len += writer_content.bytes_written();
                    }
                }
                ControlMessageKind::JackInfo => {
                    let request = reader
                        .read_obj::<VirtioSoundQueryInfo>()
                        .map_err(|_| Error::DescriptorReadFailed)?;

                    let start_id = u32::from(request.start_id) as usize;
                    let count = u32::from(request.count) as usize;
                    let jacks = self.jacks.read().unwrap();
                    if jacks.len() <= start_id || jacks.len() < start_id + count {
                        resp.code = VIRTIO_SND_S_BAD_MSG.into();
                    } else {
                        for i in jacks.iter().skip(start_id).take(count) {
                            writer_content
                                .write_obj(*i)
                                .map_err(|_| Error::DescriptorWriteFailed)?;
                        }
                        drop(jacks);
                        used_len += writer_content.bytes_written();
                    }
                }
                ControlMessageKind::JackRemap => {
                    resp.code = VIRTIO_SND_S_NOT_SUPP.into();
                }
                ControlMessageKind::PcmInfo => {
                    let request = reader
                        .read_obj::<VirtioSoundQueryInfo>()
                        .map_err(|_| Error::DescriptorReadFailed)?;

                    let start_id = u32::from(request.start_id) as usize;
                    let count = u32::from(request.count) as usize;
                    let streams = self.streams.read().unwrap();
                    if streams.len() <= start_id || streams.len() < start_id + count {
                        resp.code = VIRTIO_SND_S_BAD_MSG.into();
                    } else {
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
                            p.direction = s.direction as u8;
                            p.channels_min = s.channels_min;
                            p.channels_max = s.channels_max;
                            writer_content
                                .write_obj(p)
                                .map_err(|_| Error::DescriptorWriteFailed)?;
                        }
                        drop(streams);
                        used_len += writer_content.bytes_written();
                    }
                }
                ControlMessageKind::PcmSetParams => {
                    let request = reader
                        .read_obj::<VirtioSndPcmSetParams>()
                        .map_err(|_| Error::DescriptorReadFailed)?;
                    let stream_id: u32 = request.hdr.stream_id.into();

                    if stream_id as usize >= self.streams_no {
                        log::error!("{}", Error::from(StreamError::InvalidStreamId(stream_id)));
                        resp.code = VIRTIO_SND_S_BAD_MSG.into();
                    } else if let Err(err) = audio_backend
                        .read()
                        .unwrap()
                        .set_parameters(stream_id, request)
                    {
                        match err {
                            Error::Stream(_) | Error::StreamWithIdNotFound(_) => {
                                resp.code = VIRTIO_SND_S_BAD_MSG.into()
                            }
                            Error::UnexpectedAudioBackendConfiguration => {
                                resp.code = VIRTIO_SND_S_NOT_SUPP.into()
                            }
                            _ => {
                                log::error!("{}", err);
                                resp.code = VIRTIO_SND_S_IO_ERR.into()
                            }
                        }
                    }
                }
                ControlMessageKind::PcmPrepare => {
                    let request = reader
                        .read_obj::<VirtioSoundPcmHeader>()
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
                    let request = reader
                        .read_obj::<VirtioSoundPcmHeader>()
                        .map_err(|_| Error::DescriptorReadFailed)?;
                    let stream_id = request.stream_id.into();

                    if stream_id as usize >= self.streams_no {
                        log::error!("{}", Error::from(StreamError::InvalidStreamId(stream_id)));
                        resp.code = VIRTIO_SND_S_BAD_MSG.into();
                    } else if let Err(err) = audio_backend.write().unwrap().release(stream_id) {
                        match err {
                            Error::Stream(_) | Error::StreamWithIdNotFound(_) => {
                                resp.code = VIRTIO_SND_S_BAD_MSG.into()
                            }
                            _ => {
                                log::error!("{}", err);
                                resp.code = VIRTIO_SND_S_IO_ERR.into()
                            }
                        }
                    }
                }
                ControlMessageKind::PcmStart => {
                    let request = reader
                        .read_obj::<VirtioSoundPcmHeader>()
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
                    let request = reader
                        .read_obj::<VirtioSoundPcmHeader>()
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
            writer_status
                .write_obj(resp)
                .map_err(|_| Error::DescriptorWriteFailed)?;

            used_len += writer_status.bytes_written();

            let used_len = match u32::try_from(used_len) {
                Ok(len) => len,
                Err(len) => {
                    log::warn!("used_len {} overflows u32", len);
                    u32::MAX
                }
            };

            if vring
                .add_used(desc_chain.head_index(), used_len as u32)
                .is_err()
            {
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

        Ok(())
    }

    fn process_event(&self, _vring: &VringRwLock) -> IoResult<()> {
        log::trace!("process_event");
        Ok(())
    }

    fn process_io(
        &self,
        vring: &VringRwLock,
        audio_backend: &RwLock<Box<dyn AudioBackend + Send + Sync>>,
        direction: Direction,
    ) -> IoResult<()> {
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
            return Ok(());
        }

        // Keep log of stream IDs to wake up, in case the guest has queued more than
        // one.
        let mut stream_ids = BTreeSet::default();

        let mem = atomic_mem.memory();

        for desc_chain in requests {
            let message = Arc::new(IOMessage {
                vring: vring.clone(),
                status: VIRTIO_SND_S_OK.into(),
                used_len: 0.into(),
                latency_bytes: 0.into(),
                desc_chain: desc_chain.clone(),
            });

            let mut reader = desc_chain
                .clone()
                .reader(&mem)
                .map_err(|_| Error::DescriptorReadFailed)?;

            let in_header: VirtioSoundPcmXfer =
                reader.read_obj().map_err(|_| Error::DescriptorReadFailed)?;

            let stream_id: u32 = in_header.stream_id.into();

            stream_ids.insert(stream_id);

            let payload_len = match direction {
                Direction::Output => reader.available_bytes() - reader.bytes_read(),
                Direction::Input => {
                    let writer = desc_chain
                        .clone()
                        .writer(&mem)
                        .map_err(|_| Error::DescriptorReadFailed)?;
                    writer.available_bytes() - size_of::<VirtioSoundPcmStatus>()
                }
            };

            self.streams.write().unwrap()[stream_id as usize]
                .requests
                .push_back(Request::new(payload_len, Arc::clone(&message), direction));
        }

        if !stream_ids.is_empty() {
            let b = audio_backend.read().unwrap();
            match direction {
                Direction::Output => {
                    for id in stream_ids {
                        b.write(id).unwrap();
                    }
                }
                Direction::Input => {
                    for id in stream_ids {
                        b.read(id).unwrap();
                    }
                }
            }
        }

        Ok(())
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
                direction: Direction::Output,
                ..Stream::default()
            },
            Stream {
                id: 1,
                direction: Direction::Input,
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
                    vec![QueueIdx::Control, QueueIdx::Event],
                    streams.clone(),
                    streams_no,
                )?),
                RwLock::new(VhostUserSoundThread::new(
                    chmaps.clone(),
                    jacks.clone(),
                    vec![QueueIdx::Tx],
                    streams.clone(),
                    streams_no,
                )?),
                RwLock::new(VhostUserSoundThread::new(
                    chmaps,
                    jacks,
                    vec![QueueIdx::Rx],
                    streams.clone(),
                    streams_no,
                )?),
            ]
        } else {
            vec![RwLock::new(VhostUserSoundThread::new(
                chmaps,
                jacks,
                vec![
                    QueueIdx::Control,
                    QueueIdx::Event,
                    QueueIdx::Tx,
                    QueueIdx::Rx,
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
                streams: Le32::from(streams_no as u32),
                chmaps: 1.into(),
                controls: 0.into(),
            },
            exit_event: EventFd::new(EFD_NONBLOCK).map_err(Error::EventFdCreate)?,
            audio_backend: RwLock::new(audio_backend),
        })
    }

    pub fn send_exit_event(&self) {
        self.exit_event.write(1).unwrap();
    }
}

impl VhostUserBackend for VhostUserSoundBackend {
    type Vring = VringRwLock;
    type Bitmap = ();

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
        (1 << VIRTIO_F_VERSION_1)
            | (1 << VIRTIO_F_NOTIFY_ON_EMPTY)
            | (1 << VIRTIO_RING_F_INDIRECT_DESC)
            | (1 << VIRTIO_RING_F_EVENT_IDX)
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
    ) -> IoResult<()> {
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

#[cfg(test)]
mod tests {
    use std::path::PathBuf;
    use tempfile::tempdir;
    use virtio_bindings::virtio_ring::VRING_DESC_F_WRITE;
    use virtio_queue::{
        desc::{split::Descriptor as SplitDescriptor, RawDescriptor},
        mock::MockSplitQueue,
    };
    use vm_memory::{
        Address, Bytes, GuestAddress, GuestAddressSpace, GuestMemoryAtomic, GuestMemoryMmap,
    };

    use super::*;
    use crate::BackendType;

    const SOCKET_PATH: &str = "vsound.socket";

    fn setup_descs(descs: &[RawDescriptor]) -> (VringRwLock, GuestMemoryAtomic<GuestMemoryMmap>) {
        let mem = GuestMemoryAtomic::new(
            GuestMemoryMmap::<()>::from_ranges(&[(GuestAddress(0), 0x1000_0000)]).unwrap(),
        );
        let mem_handle = mem.memory();

        let queue = MockSplitQueue::new(&*mem_handle, 16);

        // The `build_desc_chain` function will populate the `NEXT` related flags and
        // field
        queue.build_desc_chain(descs).unwrap();

        // Put the descriptor index 0 in the first available ring position
        mem.memory()
            .write_obj(0u16, queue.avail_addr().unchecked_add(4))
            .unwrap();

        // Set `avail_idx` to 1
        mem.memory()
            .write_obj(1u16, queue.avail_addr().unchecked_add(2))
            .unwrap();

        let vring = VringRwLock::new(mem.clone(), 16).unwrap();

        vring.set_queue_size(16);
        vring
            .set_queue_info(
                queue.desc_table_addr().0,
                queue.avail_addr().0,
                queue.used_addr().0,
            )
            .unwrap();
        vring.set_queue_ready(true);

        (vring, mem)
    }

    #[test]
    fn test_sound_thread_success() {
        crate::init_logger();
        let config = SoundConfig::new(PathBuf::from(SOCKET_PATH), false, BackendType::Null);

        let chmaps = Arc::new(RwLock::new(vec![]));
        let jacks = Arc::new(RwLock::new(vec![]));
        let queue_indexes = vec![QueueIdx::Event, QueueIdx::Tx, QueueIdx::Rx];
        let streams = vec![Stream::default()];
        let streams_no = streams.len();
        let streams = Arc::new(RwLock::new(streams));
        let thread =
            VhostUserSoundThread::new(chmaps, jacks, queue_indexes, streams.clone(), streams_no);

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
            RwLock::new(alloc_audio_backend(config.audio_backend, streams).unwrap());
        t.handle_event(CONTROL_QUEUE_IDX, &vrings, &audio_backend)
            .unwrap();

        let vring = VringRwLock::new(mem, 0x1000).unwrap();
        vring.set_queue_info(0x100, 0x200, 0x300).unwrap();
        vring.set_queue_ready(true);

        // Test control msgs with three descriptors
        let ctrl_msg_descs = [
            ControlMessageKind::PcmInfo,
            ControlMessageKind::ChmapInfo,
            ControlMessageKind::JackInfo,
        ];
        for code in ctrl_msg_descs {
            let req = VirtioSoundHeader {
                code: Le32::from(code as u32),
            };
            let addr_req = 0x10_0000;
            let descs = [
                RawDescriptor::from(SplitDescriptor::new(addr_req, 0x100, 0, 0)), // request
                RawDescriptor::from(SplitDescriptor::new(
                    0x20_0000,
                    0x100,
                    VRING_DESC_F_WRITE as u16,
                    0,
                )),
                RawDescriptor::from(SplitDescriptor::new(
                    0x20_0000,
                    0x100,
                    VRING_DESC_F_WRITE as u16,
                    0,
                )), // response
            ];

            let (vring, mem) = setup_descs(&descs);
            mem.memory()
                .write_obj(req, GuestAddress(addr_req))
                .expect("writing to succeed");
            t.mem = Some(mem.clone());
            t.process_control(&vring, &audio_backend).unwrap();
        }

        // Test control msgs with two descriptors
        let ctrl_descs = [
            ControlMessageKind::JackRemap,
            ControlMessageKind::PcmSetParams,
            ControlMessageKind::PcmPrepare,
            ControlMessageKind::PcmRelease,
            ControlMessageKind::PcmStart,
            ControlMessageKind::PcmStop,
        ];
        for code in ctrl_descs {
            let req = VirtioSoundHeader {
                code: Le32::from(code as u32),
            };
            let addr_req = 0x10_0000;
            let descs = [
                RawDescriptor::from(SplitDescriptor::new(addr_req, 0x100, 0, 0)), // request
                RawDescriptor::from(SplitDescriptor::new(
                    0x20_0000,
                    0x100,
                    VRING_DESC_F_WRITE as u16,
                    0,
                )),
            ];

            let (vring, mem) = setup_descs(&descs);
            mem.memory()
                .write_obj(req, GuestAddress(addr_req))
                .expect("writing to succeed");
            t.mem = Some(mem.clone());
            t.process_control(&vring, &audio_backend).unwrap();
        }

        t.process_io(&vring, &audio_backend, Direction::Output)
            .unwrap();
        t.process_io(&vring, &audio_backend, Direction::Input)
            .unwrap();
    }

    #[test]
    fn test_sound_thread_failure() {
        crate::init_logger();
        let config = SoundConfig::new(PathBuf::from(SOCKET_PATH), false, BackendType::Null);

        let chmaps = Arc::new(RwLock::new(vec![]));
        let jacks = Arc::new(RwLock::new(vec![]));
        let queue_indexes = vec![QueueIdx::Event, QueueIdx::Tx, QueueIdx::Rx];
        let streams = Arc::new(RwLock::new(vec![]));
        let streams_no = 0;
        let thread =
            VhostUserSoundThread::new(chmaps, jacks, queue_indexes, streams.clone(), streams_no);

        let mut t = thread.unwrap();
        let mem = GuestMemoryAtomic::new(
            GuestMemoryMmap::<()>::from_ranges(&[(GuestAddress(0), 0x10000)]).unwrap(),
        );

        let audio_backend =
            RwLock::new(alloc_audio_backend(config.audio_backend, streams).unwrap());

        let vring = VringRwLock::new(mem, 0x1000).unwrap();
        vring.set_queue_info(0x100, 0x200, 0x300).unwrap();
        vring.set_queue_ready(true);
        t.process_control(&vring, &audio_backend).unwrap_err();
        t.process_io(&vring, &audio_backend, Direction::Output)
            .unwrap_err();

        // single descriptor request shall fail
        let descs = [
            RawDescriptor::from(SplitDescriptor::new(0, 0, 0, 0)), // request
        ];
        let (vring, mem) = setup_descs(&descs);
        t.mem = Some(mem);
        t.process_control(&vring, &audio_backend).unwrap_err();

        // a request with the first descriptor write-only shall fail
        let descs = [
            RawDescriptor::from(SplitDescriptor::new(0, 0, VRING_DESC_F_WRITE as u16, 0)),
            RawDescriptor::from(SplitDescriptor::new(0, 0, VRING_DESC_F_WRITE as u16, 0)),
        ];
        let (vring, mem) = setup_descs(&descs);
        t.mem = Some(mem);
        t.process_control(&vring, &audio_backend).unwrap_err();

        // a request with the second descriptor read-only shall fail
        let descs = [
            RawDescriptor::from(SplitDescriptor::new(0, 0, 0, 0)),
            RawDescriptor::from(SplitDescriptor::new(0, 0, 0, 0)),
        ];
        let (vring, mem) = setup_descs(&descs);
        t.mem = Some(mem);
        t.process_control(&vring, &audio_backend).unwrap_err();

        // control msgs in ctrl_mgs_three_descs require three descriptors otherwise fail
        let ctrl_mgs_three_descs = [
            ControlMessageKind::PcmInfo,
            ControlMessageKind::ChmapInfo,
            ControlMessageKind::JackInfo,
        ];
        for code in ctrl_mgs_three_descs {
            let req = VirtioSoundHeader {
                code: Le32::from(code as u32),
            };
            let addr_req = 0x10_0000;
            let descs = [
                RawDescriptor::from(SplitDescriptor::new(
                    addr_req,
                    size_of::<VirtioSoundHeader>() as u32,
                    0,
                    0,
                )), // request
                RawDescriptor::from(SplitDescriptor::new(
                    0x20_0000,
                    size_of::<VirtioSoundHeader>() as u32,
                    VRING_DESC_F_WRITE as u16,
                    0,
                )), // response
            ];
            let (vring, mem) = setup_descs(&descs);
            mem.memory()
                .write_obj(req, GuestAddress(addr_req))
                .expect("writing to succeed");
            t.mem = Some(mem.clone());
            t.process_control(&vring, &audio_backend).unwrap_err();
        }
    }

    #[test]
    fn test_sound_backend() {
        crate::init_logger();
        let test_dir = tempdir().expect("Could not create a temp test directory.");
        let socket_path = test_dir.path().join(SOCKET_PATH);
        let config = SoundConfig::new(socket_path, false, BackendType::Null);
        let backend = VhostUserSoundBackend::new(config).expect("Could not create backend.");

        assert_eq!(backend.num_queues(), NUM_QUEUES as usize);
        assert_eq!(backend.max_queue_size(), 64);
        assert_ne!(backend.features(), 0);
        assert!(!backend.protocol_features().is_empty());
        for event_idx in [true, false] {
            backend.set_event_idx(event_idx);

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

            backend.update_memory(mem).unwrap();

            let queues_per_thread = backend.queues_per_thread();
            assert_eq!(queues_per_thread.len(), 1);
            assert_eq!(queues_per_thread[0], 0xf);

            let config = backend.get_config(0, 8);
            assert_eq!(config.len(), 8);

            let exit = backend.exit_event(0);
            assert!(exit.is_some());
            exit.unwrap().write(1).unwrap();

            backend
                .handle_event(CONTROL_QUEUE_IDX, EventSet::IN, &vrings, 0)
                .unwrap();
            backend
                .handle_event(EVENT_QUEUE_IDX, EventSet::IN, &vrings, 0)
                .unwrap();
            backend
                .handle_event(TX_QUEUE_IDX, EventSet::IN, &vrings, 0)
                .unwrap();
            backend
                .handle_event(RX_QUEUE_IDX, EventSet::IN, &vrings, 0)
                .unwrap();
            backend
                .handle_event(RX_QUEUE_IDX * 2, EventSet::IN, &vrings, 0)
                .unwrap_err();
        }

        test_dir.close().unwrap();
    }

    #[test]
    fn test_sound_backend_failures() {
        crate::init_logger();
        let test_dir = tempdir().expect("Could not create a temp test directory.");

        let socket_path = test_dir.path().join("sound_failures.socket");

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

        // Unknown event.
        let ret = backend.handle_event(RX_QUEUE_IDX * 2, EventSet::IN, &vrings, 0);
        assert_eq!(
            ret.unwrap_err().to_string(),
            Error::HandleUnknownEvent(RX_QUEUE_IDX * 2).to_string()
        );

        test_dir.close().unwrap();
    }
}
