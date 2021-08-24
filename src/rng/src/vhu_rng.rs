// VIRTIO RNG Emulation via vhost-user
//
// Copyright 2021 Linaro Ltd. All Rights Reserved.
// Mathieu Poirier <mathieu.poirier@linaro.org>
//
// SPDX-License-Identifier: Apache-2.0

use libc::EFD_NONBLOCK;
use log::warn;
use std::fs::File;
use std::sync::{Arc, Mutex};
use std::thread::sleep;
use std::time::{Duration, Instant};
use std::{convert, error, fmt, io, result};
use vhost::vhost_user::message::{VhostUserProtocolFeatures, VhostUserVirtioFeatures};
use vhost_user_backend::{VhostUserBackendMut, VringRwLock, VringT};
use virtio_bindings::bindings::virtio_net::{VIRTIO_F_NOTIFY_ON_EMPTY, VIRTIO_F_VERSION_1};
use virtio_bindings::bindings::virtio_ring::{
    VIRTIO_RING_F_EVENT_IDX, VIRTIO_RING_F_INDIRECT_DESC,
};
use vm_memory::{Bytes, GuestAddressSpace, GuestMemoryAtomic, GuestMemoryMmap};
use vmm_sys_util::eventfd::EventFd;

const QUEUE_SIZE: usize = 1024;
const NUM_QUEUES: usize = 1;

type Result<T> = std::result::Result<T, VuRngError>;

#[derive(Debug)]
/// Errors related to vhost-device-rng daemon.
pub enum VuRngError {
    /// Descriptor not found
    DescriptorNotFound,
    /// Descriptor send failed
    DescriptorSendFailed,
    /// Can't create eventFd
    EventFdError,
    /// Failed to handle event other than input event.
    HandleEventNotEpollIn,
    /// Failed to handle unknown event.
    HandleEventUnknownEvent,
    /// Guest gave us a readable descriptor that protocol says to only write to.
    UnexpectedReadDescriptor,
    /// No memory configured.
    NoMemoryConfigured,
    /// Failed to access RNG source.
    UnexpectedRngSourceAccessError,
    /// Failed to read from the RNG source.
    UnexpectedRngSourceError,
    /// Previous Time value is later than current time.
    UnexpectedTimerValue,
    /// Error coming from VirtQueue
    UnexpectedVirtQueueError,
}

impl fmt::Display for VuRngError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "virtiorng_error: {:?}", self)
    }
}

impl error::Error for VuRngError {}

impl convert::From<VuRngError> for io::Error {
    fn from(e: VuRngError) -> Self {
        io::Error::new(io::ErrorKind::Other, e)
    }
}

pub struct VuRngTimerConfig {
    period_ms: u128,
    period_start: Instant,
    max_bytes: usize,
    quota_remaining: usize,
}

#[allow(dead_code)]
impl VuRngTimerConfig {
    pub fn new(period_ms: u128, max_bytes: usize) -> Self {
        VuRngTimerConfig {
            period_ms,
            period_start: Instant::now(),
            max_bytes,
            quota_remaining: max_bytes,
        }
    }
}

pub struct VuRngBackend {
    mem: Option<GuestMemoryAtomic<GuestMemoryMmap>>,
    event_idx: bool,
    timer: VuRngTimerConfig,
    random_file: Arc<Mutex<File>>,
    pub exit_event: EventFd,
}

#[allow(dead_code)]
impl VuRngBackend {
    /// Create a new virtio rng device that gets random data from /dev/urandom.
    pub fn new(
        random_file: Arc<Mutex<File>>,
        period_ms: u128,
        max_bytes: usize,
    ) -> std::result::Result<Self, std::io::Error> {
        Ok(VuRngBackend {
            mem: None,
            event_idx: false,
            random_file,
            timer: VuRngTimerConfig::new(period_ms, max_bytes),
            exit_event: EventFd::new(EFD_NONBLOCK).map_err(|_| VuRngError::EventFdError)?,
        })
    }

    pub fn process_queue(&mut self, vring: &VringRwLock) -> Result<bool> {
        // Copy the DescriptorChains to a vector.  Processing DescriptorChains
        // one by one directly from the Vring would lead to a deadlock because
        // the Vring's RwLock is taken once to access the DescriptorChains and
        // once more when vring.add_used() is called.
        let mut desc_chains: Vec<_> = vring
            .get_mut()
            .get_queue_mut()
            .iter()
            .map_err(|_| VuRngError::DescriptorNotFound)?
            .collect();

        for desc_chain in desc_chains.iter_mut() {
            let descriptor = match desc_chain.next() {
                Some(descriptor) => descriptor,
                None => continue,
            };

            let mut to_read = descriptor.len() as usize;
            let mut timer = &mut self.timer;
            let mut random_file = self
                .random_file
                .lock()
                .map_err(|_| VuRngError::UnexpectedRngSourceAccessError)?;

            if !descriptor.is_write_only() {
                return Err(VuRngError::UnexpectedReadDescriptor);
            }

            // Get the current time
            let now = Instant::now();

            // Check how much time has passed since we started the last period.
            match now.checked_duration_since(timer.period_start) {
                Some(duration) => {
                    let elapsed = duration.as_millis();

                    if elapsed >= timer.period_ms {
                        // More time has passed than a full period, reset time
                        // and quota.
                        timer.period_start = now;
                        timer.quota_remaining = timer.max_bytes;
                    } else {
                        // If we are out of bytes for the current period.  Block until
                        // the start of the next period.
                        if timer.quota_remaining == 0 {
                            let to_sleep = timer.period_ms - elapsed;

                            sleep(Duration::from_millis(to_sleep as u64));
                            timer.period_start = Instant::now();
                            timer.quota_remaining = timer.max_bytes;
                        }
                    }
                }
                None => return Err(VuRngError::UnexpectedTimerValue),
            };

            let mem = match &self.mem {
                Some(m) => m.memory(),
                None => return Err(VuRngError::NoMemoryConfigured),
            };

            if timer.quota_remaining < to_read {
                to_read = timer.quota_remaining;
            }

            let len = match mem.read_from(descriptor.addr(), &mut *random_file, to_read as usize) {
                Ok(len) => {
                    timer.quota_remaining -= len;
                    len
                }
                Err(_) => return Err(VuRngError::UnexpectedRngSourceError),
            };

            if vring.add_used(desc_chain.head_index(), len as u32).is_err() {
                warn!("Couldn't return used descriptors to the ring");
            }

            vring
                .signal_used_queue()
                .map_err(|_| VuRngError::DescriptorSendFailed)?;
        }

        Ok(true)
    }
}

/// VhostUserBackend trait methods
impl VhostUserBackendMut<VringRwLock, ()> for VuRngBackend {
    fn num_queues(&self) -> usize {
        NUM_QUEUES
    }

    fn max_queue_size(&self) -> usize {
        QUEUE_SIZE
    }

    fn features(&self) -> u64 {
        // this matches the current libvhost defaults except VHOST_F_LOG_ALL
        1 << VIRTIO_F_VERSION_1
            | 1 << VIRTIO_F_NOTIFY_ON_EMPTY
            | 1 << VIRTIO_RING_F_INDIRECT_DESC
            | 1 << VIRTIO_RING_F_EVENT_IDX
            | VhostUserVirtioFeatures::PROTOCOL_FEATURES.bits()
    }

    fn protocol_features(&self) -> VhostUserProtocolFeatures {
        VhostUserProtocolFeatures::MQ
    }

    fn set_event_idx(&mut self, enabled: bool) {
        dbg!(self.event_idx = enabled);
    }

    fn update_memory(
        &mut self,
        mem: GuestMemoryAtomic<GuestMemoryMmap>,
    ) -> result::Result<(), io::Error> {
        self.mem = Some(mem);
        Ok(())
    }

    fn handle_event(
        &mut self,
        device_event: u16,
        evset: epoll::Events,
        vrings: &[VringRwLock],
        _thread_id: usize,
    ) -> result::Result<bool, io::Error> {
        if evset != epoll::Events::EPOLLIN {
            return Err(VuRngError::HandleEventNotEpollIn.into());
        }

        match device_event {
            0 => {
                let vring = &vrings[0];

                if self.event_idx {
                    // vm-virtio's Queue implementation only checks avail_index
                    // once, so to properly support EVENT_IDX we need to keep
                    // calling process_queue() until it stops finding new
                    // requests on the queue.
                    loop {
                        if vring.disable_notification().is_err() {
                            return Err(VuRngError::UnexpectedVirtQueueError.into());
                        }

                        self.process_queue(vring)?;

                        match vring.enable_notification() {
                            Ok(enabled) => {
                                if !enabled {
                                    break;
                                }
                            }
                            Err(_) => {
                                return Err(VuRngError::UnexpectedVirtQueueError.into());
                            }
                        }
                    }
                } else {
                    // Without EVENT_IDX, a single call is enough.
                    self.process_queue(vring)?;
                }
            }

            _ => {
                dbg!("unhandled device_event:", device_event);
                return Err(VuRngError::HandleEventUnknownEvent.into());
            }
        }
        Ok(false)
    }

    fn exit_event(&self, _thread_index: usize) -> Option<EventFd> {
        Some(self.exit_event.try_clone().expect("Cloning exit eventfd"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempfile;

    #[test]
    fn verify_backend() {
        let random = tempfile().unwrap();
        let random_file = Arc::new(Mutex::new(random));
        let mut backend = VuRngBackend::new(random_file, 1000, 512).unwrap();

        assert_eq!(backend.num_queues(), NUM_QUEUES);
        assert_eq!(backend.max_queue_size(), QUEUE_SIZE);
        assert_eq!(backend.features(), 0x171000000);
        assert_eq!(backend.protocol_features(), VhostUserProtocolFeatures::MQ);

        assert_eq!(backend.queues_per_thread(), vec![0xffff_ffff]);
        assert_eq!(backend.get_config(0, 0), vec![]);

        backend.set_event_idx(true);
        assert!(backend.event_idx);
    }
}
