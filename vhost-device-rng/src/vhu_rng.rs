// VIRTIO RNG Emulation via vhost-user
//
// Copyright 2022 Linaro Ltd. All Rights Reserved.
// Mathieu Poirier <mathieu.poirier@linaro.org>
//
// SPDX-License-Identifier: Apache-2.0 or BSD-3-Clause

use log::warn;
use std::sync::{Arc, Mutex};
use std::thread::sleep;
use std::time::{Duration, Instant};
use std::{convert, io, result};

use thiserror::Error as ThisError;
use vhost::vhost_user::message::{VhostUserProtocolFeatures, VhostUserVirtioFeatures};
use vhost_user_backend::{VhostUserBackendMut, VringRwLock, VringT};
use virtio_bindings::bindings::virtio_config::{VIRTIO_F_NOTIFY_ON_EMPTY, VIRTIO_F_VERSION_1};
use virtio_bindings::bindings::virtio_ring::{
    VIRTIO_RING_F_EVENT_IDX, VIRTIO_RING_F_INDIRECT_DESC,
};
use virtio_queue::{DescriptorChain, QueueOwnedT};
use vm_memory::{
    GuestAddressSpace, GuestMemory, GuestMemoryAtomic, GuestMemoryLoadGuard, GuestMemoryMmap,
    ReadVolatile,
};
use vmm_sys_util::epoll::EventSet;
use vmm_sys_util::eventfd::{EventFd, EFD_NONBLOCK};

const QUEUE_SIZE: usize = 1024;
const NUM_QUEUES: usize = 1;

type Result<T> = std::result::Result<T, VuRngError>;
type RngDescriptorChain = DescriptorChain<GuestMemoryLoadGuard<GuestMemoryMmap<()>>>;

#[derive(Debug, Eq, PartialEq, ThisError)]
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
}

impl convert::From<VuRngError> for io::Error {
    fn from(e: VuRngError) -> Self {
        Self::new(io::ErrorKind::Other, e)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VuRngTimerConfig {
    period_ms: u128,
    period_start: Instant,
    max_bytes: usize,
    quota_remaining: usize,
}

impl VuRngTimerConfig {
    pub fn new(period_ms: u128, max_bytes: usize) -> Self {
        Self {
            period_ms,
            period_start: Instant::now(),
            max_bytes,
            quota_remaining: max_bytes,
        }
    }
}

pub struct VuRngBackend<T: ReadVolatile> {
    event_idx: bool,
    timer: VuRngTimerConfig,
    rng_source: Arc<Mutex<T>>,
    pub exit_event: EventFd,
    mem: Option<GuestMemoryAtomic<GuestMemoryMmap>>,
}

impl<T: ReadVolatile> VuRngBackend<T> {
    /// Create a new virtio rng device that gets random data from /dev/urandom.
    pub fn new(
        rng_source: Arc<Mutex<T>>,
        period_ms: u128,
        max_bytes: usize,
    ) -> std::result::Result<Self, std::io::Error> {
        Ok(Self {
            event_idx: false,
            rng_source,
            timer: VuRngTimerConfig::new(period_ms, max_bytes),
            exit_event: EventFd::new(EFD_NONBLOCK).map_err(|_| VuRngError::EventFdError)?,
            mem: None,
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
            let timer = &mut self.timer;

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
                .read_volatile_from(descriptor.addr(), &mut *rng_source, to_read)
                .map_err(|_| VuRngError::UnexpectedRngSourceError)?;

            timer.quota_remaining -= len;

            if vring.add_used(desc_chain.head_index(), len as u32).is_err() {
                warn!("Couldn't return used descriptors to the ring");
            }
        }
        Ok(true)
    }

    /// Process the requests in the vring and dispatch replies
    fn process_queue(&mut self, vring: &VringRwLock) -> Result<()> {
        let requests: Vec<_> = vring
            .get_mut()
            .get_queue_mut()
            .iter(self.mem.as_ref().unwrap().memory())
            .map_err(|_| VuRngError::DescriptorNotFound)?
            .collect();

        if self.process_requests(requests, vring)? {
            // Send notification once all the requests are processed
            vring
                .signal_used_queue()
                .map_err(|_| VuRngError::SendNotificationFailed)?;
        }

        Ok(())
    }
}

/// VhostUserBackend trait methods
impl<T: 'static + ReadVolatile + Sync + Send> VhostUserBackendMut for VuRngBackend<T> {
    type Vring = VringRwLock;
    type Bitmap = ();

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
        self.event_idx = enabled;
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
    ) -> result::Result<(), io::Error> {
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
        Ok(())
    }

    fn exit_event(&self, _thread_index: usize) -> Option<EventFd> {
        self.exit_event.try_clone().ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::ErrorKind;

    use virtio_bindings::bindings::virtio_ring::{VRING_DESC_F_NEXT, VRING_DESC_F_WRITE};
    use virtio_queue::{mock::MockSplitQueue, Descriptor, Queue};
    use vm_memory::{Address, Bytes, GuestAddress, GuestMemoryAtomic, GuestMemoryMmap};

    // Add VuRngBackend accessor to artificially manipulate internal fields
    impl<T: ReadVolatile> VuRngBackend<T> {
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

    // Create a mock RNG source for testing purposes
    #[derive(Clone, Debug, PartialEq)]
    struct MockRng {
        permission_denied: bool,
    }

    impl MockRng {
        const fn new(permission_denied: bool) -> Self {
            Self { permission_denied }
        }
    }

    impl ReadVolatile for MockRng {
        fn read_volatile<B: vm_memory::bitmap::BitmapSlice>(
            &mut self,
            buf: &mut vm_memory::VolatileSlice<B>,
        ) -> result::Result<usize, vm_memory::VolatileMemoryError> {
            match self.permission_denied {
                true => Err(vm_memory::VolatileMemoryError::IOError(
                    std::io::Error::from(ErrorKind::PermissionDenied),
                )),
                false => {
                    buf.write_obj(rand::random::<u8>(), 0)?;
                    Ok(1)
                }
            }
        }
    }

    fn build_desc_chain(count: u16, flags: u16) -> RngDescriptorChain {
        let mem = &GuestMemoryMmap::<()>::from_ranges(&[(GuestAddress(0), 0x1000)]).unwrap();
        let vq = MockSplitQueue::new(mem, 16);

        //Create a descriptor chain with @count descriptors.
        for i in 0..count {
            let desc_flags = if i < count - 1 {
                flags | VRING_DESC_F_NEXT as u16
            } else {
                flags & !VRING_DESC_F_NEXT as u16
            };

            let desc = Descriptor::new(u64::from(0x100 * (i + 1)), 0x200, desc_flags, i + 1);
            vq.desc_table().store(i, desc).unwrap();
        }

        // Put the descriptor index 0 in the first available ring position.
        mem.write_obj(0u16, vq.avail_addr().unchecked_add(4))
            .unwrap();

        // Set `avail_idx` to 1.
        mem.write_obj(1u16, vq.avail_addr().unchecked_add(2))
            .unwrap();

        // Create descriptor chain from pre-filled memory
        vq.create_queue::<Queue>()
            .unwrap()
            .iter(GuestMemoryAtomic::new(mem.clone()).memory())
            .unwrap()
            .next()
            .unwrap()
    }

    #[test]
    fn verify_chain_descriptors() {
        let random_source = Arc::new(Mutex::new(MockRng::new(false)));
        let mut backend = VuRngBackend::new(random_source, 1000, 512).unwrap();
        // Any number of descriptor higher than 1 will generate an error
        let count = 4;

        // Artificial memory
        let mem = GuestMemoryAtomic::new(
            GuestMemoryMmap::<()>::from_ranges(&[(GuestAddress(0), 0x1000)]).unwrap(),
        );

        // Artificial Vring
        let vring = VringRwLock::new(mem, 0x1000).unwrap();

        // The guest driver is supposed to send us only unchained descriptors
        let desc_chain = build_desc_chain(count, VRING_DESC_F_WRITE as u16);
        assert_eq!(
            backend
                .process_requests(vec![desc_chain], &vring)
                .unwrap_err(),
            VuRngError::UnexpectedDescriptorCount(count as usize)
        );

        // The guest driver is supposed to send us only write descriptors
        let desc_chain = build_desc_chain(1, 0);
        assert_eq!(
            backend
                .process_requests(vec![desc_chain], &vring)
                .unwrap_err(),
            VuRngError::UnexpectedReadDescriptor
        );
    }

    #[test]
    fn verify_timer() {
        let random_source = Arc::new(Mutex::new(MockRng::new(false)));
        let mut backend = VuRngBackend::new(random_source, 1000, 512).unwrap();

        // Artificial memory
        let mem = GuestMemoryAtomic::new(
            GuestMemoryMmap::<()>::from_ranges(&[(GuestAddress(0), 0x1000)]).unwrap(),
        );

        // Artificial Vring
        let vring = VringRwLock::new(mem, 0x1000).unwrap();

        // Artificially set the period start time 5 seconds in the future
        backend.time_add(Duration::from_secs(5));

        // Checking for a start time in the future throws a VuRngError::UnexpectedTimerValue
        assert_eq!(
            backend
                .process_requests(vec![build_desc_chain(1, VRING_DESC_F_WRITE as u16)], &vring)
                .unwrap_err(),
            VuRngError::UnexpectedTimerValue
        );

        // Artificially set the period start time to 10 second.  This will simulate a
        // condition where the the period has been exeeded and for the quota to be reset
        // to its maximum value.
        backend.time_sub(Duration::from_secs(10));
        assert!(backend
            .process_requests(vec![build_desc_chain(1, VRING_DESC_F_WRITE as u16)], &vring)
            .unwrap());

        // Reset time to right now and set remaining quota to 0.  This will simulate a
        // condition where the quota for a period has been exceeded and force the execution
        // thread to wait for the start of the next period before serving requets.
        backend.time_now();
        backend.set_quota(0);
        assert!(backend
            .process_requests(vec![build_desc_chain(1, VRING_DESC_F_WRITE as u16)], &vring)
            .unwrap());
    }

    #[test]
    fn verify_file_access() {
        // Crate a mock RNG source that can't be accessed.
        let random_source = Arc::new(Mutex::new(MockRng::new(true)));
        let mut backend = VuRngBackend::new(random_source, 1000, 512).unwrap();

        // Artificial memory
        let mem = GuestMemoryAtomic::new(
            GuestMemoryMmap::<()>::from_ranges(&[(GuestAddress(0), 0x1000)]).unwrap(),
        );

        // Artificial Vring
        let vring = VringRwLock::new(mem, 0x1000).unwrap();

        // Any type of error while reading an RNG source will throw a VuRngError::UnexpectedRngSourceError.
        assert_eq!(
            backend
                .process_requests(vec![build_desc_chain(1, VRING_DESC_F_WRITE as u16)], &vring)
                .unwrap_err(),
            VuRngError::UnexpectedRngSourceError
        );
    }

    #[test]
    fn verify_handle_event() {
        let random_source = Arc::new(Mutex::new(MockRng::new(false)));
        let mut backend = VuRngBackend::new(random_source, 1000, 512).unwrap();

        // Artificial memory
        let mem = GuestMemoryAtomic::new(
            GuestMemoryMmap::<()>::from_ranges(&[(GuestAddress(0), 0x1000)]).unwrap(),
        );

        // Update memory
        backend.update_memory(mem.clone()).unwrap();

        // Artificial Vring
        let vring = VringRwLock::new(mem, 0x1000).unwrap();
        vring.set_queue_info(0x100, 0x200, 0x300).unwrap();
        vring.set_queue_ready(true);

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
        let random_source = Arc::new(Mutex::new(MockRng::new(false)));
        let mut backend = VuRngBackend::new(random_source, 1000, 512).unwrap();

        // Artificial memory
        let mem = GuestMemoryAtomic::new(
            GuestMemoryMmap::<()>::from_ranges(&[(GuestAddress(0), 0x1000)]).unwrap(),
        );

        // Artificial Vring
        let vring = VringRwLock::new(mem.clone(), 0x1000).unwrap();

        // Empty descriptor chain should be ignored
        assert!(backend
            .process_requests(Vec::<RngDescriptorChain>::new(), &vring)
            .unwrap());

        // The capacity of descriptors is 512 byte as set in build_desc_chain().  Set the
        // quota value to half of that to simulate a condition where there is less antropy
        // available than the capacity of the descriptor buffer.
        backend.set_quota(0x100);
        assert!(backend
            .process_requests(vec![build_desc_chain(1, VRING_DESC_F_WRITE as u16)], &vring)
            .unwrap());

        assert_eq!(backend.num_queues(), NUM_QUEUES);
        assert_eq!(backend.max_queue_size(), QUEUE_SIZE);
        assert_eq!(backend.features(), 0x171000000);
        assert_eq!(backend.protocol_features(), VhostUserProtocolFeatures::MQ);

        assert_eq!(backend.queues_per_thread(), vec![0xffff_ffff]);
        assert_eq!(backend.get_config(0, 0), vec![]);
        backend.update_memory(mem).unwrap();

        backend.set_event_idx(true);
        assert!(backend.event_idx);
    }
}
