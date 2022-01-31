// VIRTIO RNG Emulation via vhost-user
//
// Copyright 2022 Linaro Ltd. All Rights Reserved.
// Mathieu Poirier <mathieu.poirier@linaro.org>
//
// SPDX-License-Identifier: Apache-2.0

use libc::EFD_NONBLOCK;
use log::warn;
use std::fs::File;
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
use vm_memory::{
    Bytes, GuestAddressSpace, GuestMemoryAtomic, GuestMemoryLoadGuard, GuestMemoryMmap,
};
use vmm_sys_util::epoll::EventSet;
use vmm_sys_util::eventfd::EventFd;

const QUEUE_SIZE: usize = 1024;
const NUM_QUEUES: usize = 1;

type Result<T> = std::result::Result<T, VuRngError>;
type RngDescriptorChain = DescriptorChain<GuestMemoryLoadGuard<GuestMemoryMmap<()>>>;

#[derive(Debug, PartialEq, ThisError)]
/// Errors related to vhost-device-rng daemon.
pub enum VuRngError {
    #[error("Descriptor not found")]
    DescriptorNotFound,
    #[error("Descriptor send failed")]
    DescriptorSendFailed,
    #[error("Can't create eventFd")]
    EventFdError,
    #[error("Failed to handle event")]
    HandleEventNotEpollIn,
    #[error("Unknown device event")]
    HandleEventUnknownEvent,
    #[error("Too many descriptors")]
    UnexpectedDescriptorCount,
    #[error("Unexpected Read Descriptor")]
    UnexpectedReadDescriptor,
    #[error("No memory configured")]
    NoMemoryConfigured,
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

pub struct VuRngBackend {
    mem: Option<GuestMemoryAtomic<GuestMemoryMmap>>,
    event_idx: bool,
    timer: VuRngTimerConfig,
    random_file: Arc<Mutex<File>>,
    pub exit_event: EventFd,
}

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

    pub fn process_requests(
        &mut self,
        requests: Vec<RngDescriptorChain>,
        vring: Option<&VringRwLock>,
    ) -> Result<bool> {
        if requests.is_empty() {
            return Ok(true);
        }

        for desc_chain in requests {
            let descriptors: Vec<_> = desc_chain.clone().collect();

            if descriptors.len() != 1 {
                return Err(VuRngError::UnexpectedDescriptorCount);
            }

            let descriptor = descriptors[0];
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

            if let Some(vring) = vring {
                if vring.add_used(desc_chain.head_index(), len as u32).is_err() {
                    warn!("Couldn't return used descriptors to the ring");
                }
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

        if self.process_requests(requests, Some(vring))? {
            // Send notification once all the requests are processed
            vring
                .signal_used_queue()
                .map_err(|_| VuRngError::DescriptorSendFailed)?;
        }

        Ok(true)
    }
}

#[cfg(test)]
impl VuRngBackend {
    // For testing purposes modify time synthetically
    pub(crate) fn time_add(&mut self, duration: Duration) {
        if let Some(t) = self.timer.period_start.checked_add(duration) {
            self.timer.period_start = t;
        }
    }

    pub(crate) fn time_sub(&mut self, duration: Duration) {
        if let Some(t) = self.timer.period_start.checked_sub(duration) {
            self.timer.period_start = t;
        }
    }

    pub(crate) fn time_now(&mut self) {
        self.timer.period_start = Instant::now();
    }

    pub(crate) fn set_quota(&mut self, quota: usize) {
        self.timer.quota_remaining = quota;
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::File;
    use tempfile::{tempdir, tempfile};

    use virtio_queue::defs::{VIRTQ_DESC_F_NEXT, VIRTQ_DESC_F_WRITE};
    use virtio_queue::{mock::MockSplitQueue, Descriptor};
    use vm_memory::{Address, GuestAddress, GuestMemoryAtomic, GuestMemoryMmap};

    fn build_desc_chain(count: u16, flags: u16) -> RngDescriptorChain {
        let mem = GuestMemoryMmap::<()>::from_ranges(&[(GuestAddress(0), 0x1000)]).unwrap();
        let vq = MockSplitQueue::new(&mem, 16);

        //Create a descriptor chain with @count descriptors.
        for i in 0..count {
            let desc_flags = if i < count - 1 {
                flags | VIRTQ_DESC_F_NEXT
            } else {
                flags & !VIRTQ_DESC_F_NEXT
            };

            let desc = Descriptor::new((0x100 * (i + 1)) as u64, 0x200, desc_flags, i + 1);
            vq.desc_table().store(i, desc);
        }

        // Put the descriptor index 0 in the first available ring position.
        mem.write_obj(0u16, vq.avail_addr().unchecked_add(4))
            .unwrap();

        // Set `avail_idx` to 1.
        mem.write_obj(1u16, vq.avail_addr().unchecked_add(2))
            .unwrap();

        // Create descriptor chain from pre-filled memory
        vq.create_queue(GuestMemoryAtomic::<GuestMemoryMmap>::new(mem.clone()))
            .iter()
            .unwrap()
            .next()
            .unwrap()
    }

    #[test]
    fn verify_chain_descriptors() {
        let random = tempfile().unwrap();
        let random_file = Arc::new(Mutex::new(random));
        let mut backend = VuRngBackend::new(random_file, 1000, 512).unwrap();

        // The guest driver is supposed to send us only unchained descriptors
        let desc_chain = build_desc_chain(4, VIRTQ_DESC_F_WRITE);
        assert_eq!(
            backend
                .process_requests(vec![desc_chain], None)
                .unwrap_err(),
            VuRngError::UnexpectedDescriptorCount
        );

        // The guest driver is supposed to send us only write descriptors
        let desc_chain = build_desc_chain(1, 0);
        assert_eq!(
            backend
                .process_requests(vec![desc_chain], None)
                .unwrap_err(),
            VuRngError::UnexpectedReadDescriptor
        );
    }

    #[test]
    fn verify_timer() {
        let random = tempfile().unwrap();
        let random_file = Arc::new(Mutex::new(random));
        let mut backend = VuRngBackend::new(random_file, 1000, 512).unwrap();

        // Artificial memory
        let mem = GuestMemoryAtomic::new(
            GuestMemoryMmap::<()>::from_ranges(&[(GuestAddress(0), 0x1000)]).unwrap(),
        );

        // Artificial Vring
        let vring = VringRwLock::new(mem.clone(), 0x1000);

        // Artifically set the memory to avoid a VuRngError::NoMemoryConfigured error
        backend.update_memory(mem).unwrap();

        // Artificially set the period start time 5 seconds in the future
        backend.time_add(Duration::from_secs(5));

        // Checking for a start time in the future throws a VuRngError::UnexpectedTimerValue
        assert_eq!(
            backend
                .process_requests(vec![build_desc_chain(1, VIRTQ_DESC_F_WRITE)], Some(&vring))
                .unwrap_err(),
            VuRngError::UnexpectedTimerValue
        );

        // Artificially set the period start time to 10 second.  This will simulate a
        // condition where the the period has been exeeded and for the quota to be reset
        // to its maximum value.
        backend.time_sub(Duration::from_secs(10));
        assert!(backend
            .process_requests(vec![build_desc_chain(1, VIRTQ_DESC_F_WRITE)], Some(&vring))
            .unwrap());

        // Reset time to right now and set remaining quota to 0.  This will simulate a
        // condition where the quota for a period has been exceeded and force the execution
        // thread to wait for the start of the next period before serving requets.
        backend.time_now();
        backend.set_quota(0);
        assert!(backend
            .process_requests(vec![build_desc_chain(1, VIRTQ_DESC_F_WRITE)], Some(&vring))
            .unwrap());
    }

    #[test]
    fn verify_file_access() {
        let dir = tempdir().unwrap();
        let file_path = dir.path().join("foo.txt");
        let random_file = Arc::new(Mutex::new(File::create(file_path).unwrap()));
        let mut backend = VuRngBackend::new(random_file, 1000, 512).unwrap();

        // Artificial memory
        let mem = GuestMemoryAtomic::new(
            GuestMemoryMmap::<()>::from_ranges(&[(GuestAddress(0), 0x1000)]).unwrap(),
        );

        // Artificial Vring
        let vring = VringRwLock::new(mem.clone(), 0x1000);

        // Artifically set the memory to avoid a VuRngError::NoMemoryConfigured error
        backend.update_memory(mem).unwrap();

        // Reading from an empty file will throw a VuRngError::UnexpectedRngSourceError.
        assert_eq!(
            backend
                .process_requests(vec![build_desc_chain(1, VIRTQ_DESC_F_WRITE)], Some(&vring))
                .unwrap_err(),
            VuRngError::UnexpectedRngSourceError
        );
    }

    #[test]
    fn verify_handle_event() {
        let random = tempfile().unwrap();
        let random_file = Arc::new(Mutex::new(random));
        let mut backend = VuRngBackend::new(random_file, 1000, 512).unwrap();
        // Artificial memory
        let mem = GuestMemoryAtomic::new(
            GuestMemoryMmap::<()>::from_ranges(&[(GuestAddress(0), 0x1000)]).unwrap(),
        );

        // Artificial Vring
        let vring = VringRwLock::new(mem, 0x1000);

        // Currently handles EventSet::IN only, otherwise an error is generated.
        assert_eq!(
            backend
                .handle_event(0, EventSet::OUT, &[vring.clone()], 0)
                .unwrap_err()
                .kind(),
            io::ErrorKind::Other
        );

        // Currently handles a single device event, anything higher than 0 will generate
        // an error.
        assert_eq!(
            backend
                .handle_event(1, EventSet::IN, &[vring.clone()], 0)
                .unwrap_err()
                .kind(),
            io::ErrorKind::Other
        );

        // backend.event_idx is set to false by default, which will call backend.process_queue()
        // a single time.  Since there is no descriptor in the vring backend.process_requests()
        // will return immediately.
        backend
            .handle_event(0, EventSet::IN, &[vring.clone()], 0)
            .unwrap();

        // Set backend.event_idx to true in order to call backend.process_queue() multiple time
        backend.set_event_idx(true);
        backend.handle_event(0, EventSet::IN, &[vring], 0).unwrap();
    }

    #[test]
    fn verify_backend() {
        let random = tempfile().unwrap();
        let random_file = Arc::new(Mutex::new(random));
        let mut backend = VuRngBackend::new(random_file, 1000, 512).unwrap();
        // Artificial memory
        let mem = GuestMemoryAtomic::new(
            GuestMemoryMmap::<()>::from_ranges(&[(GuestAddress(0), 0x1000)]).unwrap(),
        );

        // Artificial Vring
        let vring = VringRwLock::new(mem.clone(), 0x1000);

        // Empty descriptor chain should be ignored
        assert!(backend
            .process_requests(Vec::<RngDescriptorChain>::new(), Some(&vring))
            .unwrap());

        // The descriptor type and count are correct but no memory is configured, something
        // that needs to generate a VuRngError::NoMemoryConfigured error.
        let desc_chain = build_desc_chain(1, VIRTQ_DESC_F_WRITE);
        assert_eq!(
            backend
                .process_requests(vec![desc_chain], Some(&vring))
                .unwrap_err(),
            VuRngError::NoMemoryConfigured
        );

        // Artificially set the memory to avoid a VuRngError::NoMemoryConfigured error
        backend.update_memory(mem).unwrap();

        // The capacity of descriptors is 512 byte as set in build_desc_chain().  Set the
        // quota value to half of that to simulate a condition where there is less antropy
        // available than the capacity of the descriptor buffer.
        backend.set_quota(0x100);
        assert!(backend
            .process_requests(vec![build_desc_chain(1, VIRTQ_DESC_F_WRITE)], Some(&vring))
            .unwrap());

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