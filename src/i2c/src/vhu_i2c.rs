// vhost device i2c
//
// Copyright 2021 Linaro Ltd. All Rights Reserved.
//          Viresh Kumar <viresh.kumar@linaro.org>
//
// SPDX-License-Identifier: Apache-2.0

use crate::i2c::*;
use std::sync::{Arc, RwLock};
use std::{convert, error, fmt, io};
use vhost::vhost_user::message::{VhostUserProtocolFeatures, VhostUserVirtioFeatures};
use vhost_user_backend::{VhostUserBackend, Vring};
use virtio_bindings::bindings::virtio_net::{VIRTIO_F_NOTIFY_ON_EMPTY, VIRTIO_F_VERSION_1};
use virtio_bindings::bindings::virtio_ring::{
    VIRTIO_RING_F_EVENT_IDX, VIRTIO_RING_F_INDIRECT_DESC,
};
use vm_memory::{GuestMemoryAtomic, GuestMemoryMmap};
use vmm_sys_util::eventfd::{EventFd, EFD_NONBLOCK};

const QUEUE_SIZE: usize = 1024;
const NUM_QUEUES: usize = 1;

type Result<T> = std::result::Result<T, Error>;
type VhostUserBackendResult<T> = std::result::Result<T, std::io::Error>;

#[derive(Debug)]
/// Errors related to vhost-device-i2c daemon.
pub enum Error {
    /// Failed to handle event other than input event.
    HandleEventNotEpollIn,
    /// Failed to handle unknown event.
    HandleEventUnknownEvent,
}
impl error::Error for Error {}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "vhost-device-i2c error: {:?}", self)
    }
}

impl convert::From<Error> for io::Error {
    fn from(e: Error) -> Self {
        io::Error::new(io::ErrorKind::Other, e)
    }
}

pub struct VhostUserI2cBackend<A: I2cAdapterTrait> {
    i2c_map: Arc<I2cMap<A>>,
    event_idx: bool,
    mem: Option<GuestMemoryAtomic<GuestMemoryMmap>>,
    pub exit_event: EventFd,
}

impl<A: I2cAdapterTrait> VhostUserI2cBackend<A> {
    pub fn new(i2c_map: Arc<I2cMap<A>>) -> Result<Self> {
        Ok(VhostUserI2cBackend {
            i2c_map,
            event_idx: false,
            mem: None,
            exit_event: EventFd::new(EFD_NONBLOCK).expect("Creating exit eventfd"),
        })
    }

    /// Process the messages in the vring and dispatch replies
    fn process_queue(&self, _vring: &mut Vring) -> Result<bool> {
        Ok(true)
    }
}

/// VhostUserBackend trait methods
impl<A: I2cAdapterTrait> VhostUserBackend for VhostUserI2cBackend<A> {
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
    ) -> VhostUserBackendResult<()> {
        self.mem = Some(mem);
        Ok(())
    }

    fn handle_event(
        &self,
        device_event: u16,
        evset: epoll::Events,
        vrings: &[Arc<RwLock<Vring>>],
        _thread_id: usize,
    ) -> VhostUserBackendResult<bool> {
        if evset != epoll::Events::EPOLLIN {
            return Err(Error::HandleEventNotEpollIn.into());
        }

        match device_event {
            0 => {
                let mut vring = vrings[0].write().unwrap();

                if self.event_idx {
                    // vm-virtio's Queue implementation only checks avail_index
                    // once, so to properly support EVENT_IDX we need to keep
                    // calling process_queue() until it stops finding new
                    // requests on the queue.
                    loop {
                        vring.mut_queue().disable_notification().unwrap();
                        self.process_queue(&mut vring)?;
                        if !vring.mut_queue().enable_notification().unwrap() {
                            break;
                        }
                    }
                } else {
                    // Without EVENT_IDX, a single call is enough.
                    self.process_queue(&mut vring)?;
                }
            }

            _ => {
                dbg!("unhandled device_event:", device_event);
                return Err(Error::HandleEventUnknownEvent.into());
            }
        }
        Ok(false)
    }

    fn exit_event(&self, _thread_index: usize) -> Option<(EventFd, Option<u16>)> {
        Some((
            self.exit_event.try_clone().expect("Cloning exit eventfd"),
            None,
        ))
    }
}
