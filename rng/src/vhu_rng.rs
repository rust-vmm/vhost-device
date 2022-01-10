// VIRTIO RNG Emulation via vhost-user
//
// Copyright 2022 Linaro Ltd. All Rights Reserved.
// Mathieu Poirier <mathieu.poirier@linaro.org>
//
// SPDX-License-Identifier: Apache-2.0

use log::warn;
use std::io::Read;
use std::sync::{Arc, Mutex};
use std::thread::sleep;
use std::time::{Duration, Instant};
use std::{convert, io, result};

use thiserror::Error as ThisError;
use vhost::vhost_user::message::{VhostUserProtocolFeatures, VhostUserVirtioFeatures};
use vhost_user_backend::{VhostUserBackendMut, VringRwLock, VringT};
use virtio_bindings::bindings::virtio_net::{VIRTIO_F_NOTIFY_ON_EMPTY, VIRTIO_F_VERSION_1};
use virtio_bindings::bindings::virtio_ring::{
    VIRTIO_RING_F_EVENT_IDX, VIRTIO_RING_F_INDIRECT_DESC,
};
use virtio_queue::DescriptorChain;
use vm_memory::{Bytes, GuestMemoryAtomic, GuestMemoryLoadGuard, GuestMemoryMmap};
use vmm_sys_util::epoll::EventSet;
use vmm_sys_util::eventfd::{EventFd, EFD_NONBLOCK};

const QUEUE_SIZE: usize = 1024;
const NUM_QUEUES: usize = 1;

type Result<T> = std::result::Result<T, VuRngError>;
type RngDescriptorChain = DescriptorChain<GuestMemoryLoadGuard<GuestMemoryMmap<()>>>;

#[derive(Debug, PartialEq, ThisError)]
/// Errors related to vhost-device-rng daemon.
pub enum VuRngError {
    #[error("Descriptor not found")]
    DescriptorNotFound,
    #[error("Notification send failed")]
    SendNotificationFailed,
    #[error("Can't create eventFd")]
    EventFdError,
    #[error("Failed to handle event")]
    HandleEventNotEpollIn,
    #[error("Unknown device event")]
    HandleEventUnknownEvent,
    #[error("Too many descriptors: {0}")]
    UnexpectedDescriptorCount(usize),
    #[error("Unexpected Read Descriptor")]
    UnexpectedReadDescriptor,
    #[error("Failed to access RNG source")]
    UnexpectedRngSourceAccessError,
    #[error("Failed to read from the RNG source")]
    UnexpectedRngSourceError,
    #[error("Previous Time value is later than current time")]
    UnexpectedTimerValue,
    #[error("Unexpected VirtQueue error")]
    UnexpectedVirtQueueError,
}

impl convert::From<VuRngError> for io::Error {
    fn from(e: VuRngError) -> Self {
        io::Error::new(io::ErrorKind::Other, e)
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct VuRngTimerConfig {
    period_ms: u128,
    period_start: Instant,
    max_bytes: usize,
    quota_remaining: usize,
}

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

pub struct VuRngBackend<T: Read> {
    event_idx: bool,
    timer: VuRngTimerConfig,
    rng_source: Arc<Mutex<T>>,
    pub exit_event: EventFd,
}

impl<T: Read> VuRngBackend<T> {
    /// Create a new virtio rng device that gets random data from /dev/urandom.
    pub fn new(
        rng_source: Arc<Mutex<T>>,
        period_ms: u128,
        max_bytes: usize,
    ) -> std::result::Result<Self, std::io::Error> {
        Ok(VuRngBackend {
            event_idx: false,
            rng_source,
            timer: VuRngTimerConfig::new(period_ms, max_bytes),
            exit_event: EventFd::new(EFD_NONBLOCK).map_err(|_| VuRngError::EventFdError)?,
        })
    }

    pub fn process_requests(
        &mut self,
        requests: Vec<RngDescriptorChain>,
        vring: &VringRwLock,
    ) -> Result<bool> {
        if requests.is_empty() {
            return Ok(true);
        }

        for desc_chain in requests {
            let descriptors: Vec<_> = desc_chain.clone().collect();

            if descriptors.len() != 1 {
                return Err(VuRngError::UnexpectedDescriptorCount(descriptors.len()));
            }

            let descriptor = descriptors[0];
            let mut to_read = descriptor.len() as usize;
            let mut timer = &mut self.timer;

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

            if timer.quota_remaining < to_read {
                to_read = timer.quota_remaining;
            }

            let mut rng_source = self
                .rng_source
                .lock()
                .map_err(|_| VuRngError::UnexpectedRngSourceAccessError)?;

            let len = desc_chain
                .memory()
                .read_from(descriptor.addr(), &mut *rng_source, to_read as usize)
                .map_err(|_| VuRngError::UnexpectedRngSourceError)?;

            timer.quota_remaining -= len;

            if vring.add_used(desc_chain.head_index(), len as u32).is_err() {
                warn!("Couldn't return used descriptors to the ring");
            }
        }
        Ok(true)
    }

    /// Process the requests in the vring and dispatch replies
    fn process_queue(&mut self, vring: &VringRwLock) -> Result<bool> {
        let requests: Vec<_> = vring
            .get_mut()
            .get_queue_mut()
            .iter()
            .map_err(|_| VuRngError::DescriptorNotFound)?
            .collect();

        if self.process_requests(requests, vring)? {
            // Send notification once all the requests are processed
            vring
                .signal_used_queue()
                .map_err(|_| VuRngError::SendNotificationFailed)?;
        }

        Ok(true)
    }
}

/// VhostUserBackend trait methods
impl<T: 'static + Read + Sync + Send> VhostUserBackendMut<VringRwLock, ()> for VuRngBackend<T> {
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
        _mem: GuestMemoryAtomic<GuestMemoryMmap>,
    ) -> result::Result<(), io::Error> {
        Ok(())
    }

    fn handle_event(
        &mut self,
        device_event: u16,
        evset: EventSet,
        vrings: &[VringRwLock],
        _thread_id: usize,
    ) -> result::Result<bool, io::Error> {
        if evset != EventSet::IN {
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
                        vring.disable_notification().unwrap();
                        self.process_queue(vring)?;
                        if !vring.enable_notification().unwrap() {
                            break;
                        }
                    }
                } else {
                    // Without EVENT_IDX, a single call is enough.
                    self.process_queue(vring)?;
                }
            }

            _ => {
                warn!("unhandled device_event: {}", device_event);
                return Err(VuRngError::HandleEventUnknownEvent.into());
            }
        }
        Ok(false)
    }

    fn exit_event(&self, _thread_index: usize) -> Option<EventFd> {
        self.exit_event.try_clone().ok()
    }
}

