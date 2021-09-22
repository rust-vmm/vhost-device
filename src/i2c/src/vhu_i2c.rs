// vhost device i2c
//
// Copyright 2021 Linaro Ltd. All Rights Reserved.
//          Viresh Kumar <viresh.kumar@linaro.org>
//
// SPDX-License-Identifier: Apache-2.0

use crate::i2c::*;
use std::mem::size_of;
use std::sync::Arc;
use std::{convert, error, fmt, io};
use vhost::vhost_user::message::{VhostUserProtocolFeatures, VhostUserVirtioFeatures};
use vhost_user_backend::{VhostUserBackendMut, VringRwLock, VringT};
use virtio_bindings::bindings::virtio_net::{VIRTIO_F_NOTIFY_ON_EMPTY, VIRTIO_F_VERSION_1};
use virtio_bindings::bindings::virtio_ring::{
    VIRTIO_RING_F_EVENT_IDX, VIRTIO_RING_F_INDIRECT_DESC,
};
use vm_memory::{ByteValued, Bytes, GuestMemoryAtomic, GuestMemoryMmap, Le16, Le32};
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
    /// Guest gave us a write only descriptor that protocol says to read from.
    UnexpectedWriteOnlyDescriptor,
    /// Guest gave us a readable descriptor that protocol says to only write to.
    UnexpectedReadDescriptor,
    /// Invalid descriptor count
    UnexpectedDescriptorCount,
    /// Invalid descriptor
    UnexpectedDescriptorSize,
    /// Descriptor not found
    DescriptorNotFound,
    /// Descriptor read failed
    DescriptorReadFailed,
    /// Descriptor write failed
    DescriptorWriteFailed,
    /// Descriptor send failed
    DescriptorSendFailed,
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

/// I2C definitions from Virtio Spec

/// The final status written by the device
const VIRTIO_I2C_MSG_OK: u8 = 0;
const VIRTIO_I2C_MSG_ERR: u8 = 1;

#[derive(Copy, Clone, Default)]
#[repr(C)]
struct VirtioI2cOutHdr {
    addr: Le16,
    padding: Le16,
    flags: Le32,
}
unsafe impl ByteValued for VirtioI2cOutHdr {}

#[derive(Copy, Clone, Default)]
#[repr(C)]
struct VirtioI2cInHdr {
    status: u8,
}
unsafe impl ByteValued for VirtioI2cInHdr {}

pub struct VhostUserI2cBackend<D: I2cDevice> {
    i2c_map: Arc<I2cMap<D>>,
    event_idx: bool,
    mem: Option<GuestMemoryAtomic<GuestMemoryMmap>>,
    pub exit_event: EventFd,
}

impl<D: I2cDevice> VhostUserI2cBackend<D> {
    pub fn new(i2c_map: Arc<I2cMap<D>>) -> Result<Self> {
        Ok(VhostUserI2cBackend {
            i2c_map,
            event_idx: false,
            mem: None,
            exit_event: EventFd::new(EFD_NONBLOCK).expect("Creating exit eventfd"),
        })
    }

    /// Process the requests in the vring and dispatch replies
    fn process_queue(&self, vring: &VringRwLock) -> Result<bool> {
        let mut reqs: Vec<I2cReq> = Vec::new();

        let requests: Vec<_> = vring
            .get_mut()
            .get_queue_mut()
            .iter()
            .map_err(|_| Error::DescriptorNotFound)?
            .collect();

        if requests.is_empty() {
            return Ok(true);
        }

        // Iterate over each I2C request and push it to "reqs" vector.
        for desc_chain in requests.clone() {
            let descriptors: Vec<_> = desc_chain.clone().collect();

            if descriptors.len() != 3 {
                return Err(Error::UnexpectedDescriptorCount);
            }

            let desc_out_hdr = descriptors[0];
            if desc_out_hdr.is_write_only() {
                return Err(Error::UnexpectedWriteOnlyDescriptor);
            }

            if desc_out_hdr.len() as usize != size_of::<VirtioI2cOutHdr>() {
                return Err(Error::UnexpectedDescriptorSize);
            }

            let desc_buf = descriptors[1];
            if desc_buf.len() == 0 {
                return Err(Error::UnexpectedDescriptorSize);
            }

            let desc_in_hdr = descriptors[2];
            if !desc_in_hdr.is_write_only() {
                return Err(Error::UnexpectedReadDescriptor);
            }

            if desc_in_hdr.len() as usize != size_of::<u8>() {
                return Err(Error::UnexpectedDescriptorSize);
            }

            let mut buf: Vec<u8> = vec![0; desc_buf.len() as usize];

            let mut flags: u16 = 0;

            if desc_buf.is_write_only() {
                flags = I2C_M_RD;
            } else {
                desc_chain
                    .memory()
                    .read(&mut buf, desc_buf.addr())
                    .map_err(|_| Error::DescriptorReadFailed)?;
            }

            let out_hdr = desc_chain
                .memory()
                .read_obj::<VirtioI2cOutHdr>(desc_out_hdr.addr())
                .map_err(|_| Error::DescriptorReadFailed)?;

            reqs.push(I2cReq {
                addr: out_hdr.addr.to_native() >> 1,
                flags,
                len: desc_buf.len() as u16,
                buf,
            });
        }

        let in_hdr = {
            VirtioI2cInHdr {
                status: match self.i2c_map.transfer(&mut reqs) {
                    Ok(()) => VIRTIO_I2C_MSG_OK,
                    Err(_) => VIRTIO_I2C_MSG_ERR,
                },
            }
        };

        for desc_chain in requests {
            let descriptors: Vec<_> = desc_chain.clone().collect();
            let desc_buf = descriptors[1];
            let desc_in_hdr = descriptors[2];
            let mut len = size_of::<VirtioI2cInHdr>() as u32;

            // Write the data read from the I2C device
            if desc_buf.is_write_only() {
                desc_chain
                    .memory()
                    .write(&reqs.remove(0).buf, desc_buf.addr())
                    .map_err(|_| Error::DescriptorWriteFailed)?;
            }

            // Write the transfer status
            desc_chain
                .memory()
                .write_obj::<VirtioI2cInHdr>(in_hdr, desc_in_hdr.addr())
                .map_err(|_| Error::DescriptorWriteFailed)?;

            if in_hdr.status == VIRTIO_I2C_MSG_OK {
                len += desc_buf.len();
            }

            if vring.add_used(desc_chain.head_index(), len).is_err() {
                println!("Couldn't return used descriptors to the ring");
            }
        }

        // Send notification once all the requests are processed
        vring
            .signal_used_queue()
            .map_err(|_| Error::DescriptorSendFailed)?;
        Ok(true)
    }
}

/// VhostUserBackendMut trait methods
impl<D: 'static + I2cDevice + Sync + Send> VhostUserBackendMut<VringRwLock, ()>
    for VhostUserI2cBackend<D>
{
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
        &mut self,
        device_event: u16,
        evset: epoll::Events,
        vrings: &[VringRwLock],
        _thread_id: usize,
    ) -> VhostUserBackendResult<bool> {
        if evset != epoll::Events::EPOLLIN {
            return Err(Error::HandleEventNotEpollIn.into());
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
                dbg!("unhandled device_event:", device_event);
                return Err(Error::HandleEventUnknownEvent.into());
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
    use crate::i2c::tests::DummyDevice;
    use std::convert::TryFrom;

    #[test]
    fn verify_backend() {
        let device_config = AdapterConfig::try_from("1:4,2:32:21,5:10:23").unwrap();
        let i2c_map: I2cMap<DummyDevice> = I2cMap::new(&device_config).unwrap();
        let mut backend = VhostUserI2cBackend::new(Arc::new(i2c_map)).unwrap();

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
