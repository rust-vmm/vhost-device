// Manos Pitsidianakis <manos.pitsidianakis@linaro.org>
// Stefano Garzarella <sgarzare@redhat.com>
// SPDX-License-Identifier: Apache-2.0 or BSD-3-Clause

use std::{io::Result as IoResult, sync::RwLock, u16, u32, u64, u8};

use vhost::vhost_user::message::{VhostUserProtocolFeatures, VhostUserVirtioFeatures};
use vhost_user_backend::{VhostUserBackend, VringRwLock};
use virtio_bindings::bindings::{
    virtio_config::{VIRTIO_F_NOTIFY_ON_EMPTY, VIRTIO_F_VERSION_1},
    virtio_ring::{VIRTIO_RING_F_EVENT_IDX, VIRTIO_RING_F_INDIRECT_DESC},
};
use vm_memory::{ByteValued, GuestMemoryAtomic, GuestMemoryMmap};
use vmm_sys_util::{
    epoll::EventSet,
    eventfd::{EventFd, EFD_NONBLOCK},
};

use crate::{
    audio_backends::{alloc_audio_backend, AudioBackend},
    virtio_sound::*,
    Error, Result, SoundConfig,
};

struct VhostUserSoundThread {
    mem: Option<GuestMemoryAtomic<GuestMemoryMmap>>,
    event_idx: bool,
    queue_indexes: Vec<u16>,
}

impl VhostUserSoundThread {
    pub fn new(mut queue_indexes: Vec<u16>) -> Result<Self> {
        queue_indexes.sort();

        Ok(VhostUserSoundThread {
            event_idx: false,
            mem: None,
            queue_indexes,
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

    fn handle_event(&self, device_event: u16, vrings: &[VringRwLock]) -> IoResult<bool> {
        let vring = &vrings[device_event as usize];
        let queue_idx = self.queue_indexes[device_event as usize];

        match queue_idx {
            CONTROL_QUEUE_IDX => self.process_control(vring),
            EVENT_QUEUE_IDX => self.process_event(vring),
            TX_QUEUE_IDX => self.process_tx(vring),
            RX_QUEUE_IDX => self.process_rx(vring),
            _ => Err(Error::HandleUnknownEvent.into()),
        }
    }

    fn process_control(&self, _vring: &VringRwLock) -> IoResult<bool> {
        Ok(false)
    }

    fn process_event(&self, _vring: &VringRwLock) -> IoResult<bool> {
        Ok(false)
    }

    fn process_tx(&self, _vring: &VringRwLock) -> IoResult<bool> {
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
    _audio_backend: RwLock<Box<dyn AudioBackend + Send + Sync>>,
}

impl VhostUserSoundBackend {
    pub fn new(config: SoundConfig) -> Result<Self> {
        let threads = if config.multi_thread {
            vec![
                RwLock::new(VhostUserSoundThread::new(vec![
                    CONTROL_QUEUE_IDX,
                    EVENT_QUEUE_IDX,
                ])?),
                RwLock::new(VhostUserSoundThread::new(vec![TX_QUEUE_IDX])?),
                RwLock::new(VhostUserSoundThread::new(vec![RX_QUEUE_IDX])?),
            ]
        } else {
            vec![RwLock::new(VhostUserSoundThread::new(vec![
                CONTROL_QUEUE_IDX,
                EVENT_QUEUE_IDX,
                TX_QUEUE_IDX,
                RX_QUEUE_IDX,
            ])?)]
        };

        let audio_backend = alloc_audio_backend(config.audio_backend_name)?;

        Ok(Self {
            threads,
            virtio_cfg: VirtioSoundConfig {
                jacks: 0.into(),
                streams: 1.into(),
                chmaps: 0.into(),
            },
            exit_event: EventFd::new(EFD_NONBLOCK).map_err(Error::EventFdCreate)?,
            _audio_backend: RwLock::new(audio_backend),
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
            .handle_event(device_event, vrings)
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
