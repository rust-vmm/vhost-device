// vhost device i2c
//
// Copyright 2021 Linaro Ltd. All Rights Reserved.
//          Viresh Kumar <viresh.kumar@linaro.org>
//
// SPDX-License-Identifier: Apache-2.0 or BSD-3-Clause

use log::warn;
use std::mem::size_of;
use std::sync::Arc;
use std::{
    convert,
    io::{self, Result as IoResult},
};

use thiserror::Error as ThisError;
use vhost::vhost_user::message::{VhostUserProtocolFeatures, VhostUserVirtioFeatures};
use vhost_user_backend::{VhostUserBackendMut, VringRwLock, VringT};
use virtio_bindings::bindings::virtio_config::{VIRTIO_F_NOTIFY_ON_EMPTY, VIRTIO_F_VERSION_1};
use virtio_bindings::bindings::virtio_ring::{
    VIRTIO_RING_F_EVENT_IDX, VIRTIO_RING_F_INDIRECT_DESC,
};
use virtio_queue::{DescriptorChain, QueueOwnedT};
use vm_memory::{
    ByteValued, Bytes, GuestAddressSpace, GuestMemoryAtomic, GuestMemoryLoadGuard, GuestMemoryMmap,
    Le16, Le32,
};
use vmm_sys_util::epoll::EventSet;
use vmm_sys_util::eventfd::{EventFd, EFD_NONBLOCK};

use crate::i2c::*;

/// Virtio I2C Feature bits
const VIRTIO_I2C_F_ZERO_LENGTH_REQUEST: u16 = 0;

const QUEUE_SIZE: usize = 1024;
const NUM_QUEUES: usize = 1;

type Result<T> = std::result::Result<T, Error>;

#[derive(Copy, Clone, Debug, Eq, PartialEq, ThisError)]
/// Errors related to vhost-device-i2c daemon.
pub enum Error {
    #[error("Failed to handle event, didn't match EPOLLIN")]
    HandleEventNotEpollIn,
    #[error("Failed to handle unknown event")]
    HandleEventUnknown,
    #[error("Received unexpected write only descriptor at index {0}")]
    UnexpectedWriteOnlyDescriptor(usize),
    #[error("Received unexpected readable descriptor at index {0}")]
    UnexpectedReadableDescriptor(usize),
    #[error("Invalid descriptor count {0}")]
    UnexpectedDescriptorCount(usize),
    #[error("Invalid descriptor size, expected: {0}, found: {1}")]
    UnexpectedDescriptorSize(usize, u32),
    #[error("Descriptor not found")]
    DescriptorNotFound,
    #[error("Descriptor read failed")]
    DescriptorReadFailed,
    #[error("Descriptor write failed")]
    DescriptorWriteFailed,
    #[error("Failed to send notification")]
    NotificationFailed,
    #[error("Failed to create new EventFd")]
    EventFdFailed,
}

impl convert::From<Error> for io::Error {
    fn from(e: Error) -> Self {
        Self::new(io::ErrorKind::Other, e)
    }
}

// I2C definitions from Virtio Spec

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
// SAFETY: The layout of the structure is fixed and can be initialized by
// reading its content from byte array.
unsafe impl ByteValued for VirtioI2cOutHdr {}

/// VirtioI2cOutHdr Flags
const VIRTIO_I2C_FLAGS_M_RD: u32 = 1 << 1;

#[derive(Copy, Clone, Default)]
#[repr(C)]
struct VirtioI2cInHdr {
    status: u8,
}
// SAFETY: The layout of the structure is fixed and can be initialized by
// reading its content from byte array.
unsafe impl ByteValued for VirtioI2cInHdr {}

pub struct VhostUserI2cBackend<D: I2cDevice> {
    i2c_map: Arc<I2cMap<D>>,
    event_idx: bool,
    pub exit_event: EventFd,
    mem: Option<GuestMemoryLoadGuard<GuestMemoryMmap>>,
}

type I2cDescriptorChain = DescriptorChain<GuestMemoryLoadGuard<GuestMemoryMmap<()>>>;

impl<D: I2cDevice> VhostUserI2cBackend<D> {
    pub fn new(i2c_map: Arc<I2cMap<D>>) -> Result<Self> {
        Ok(Self {
            i2c_map,
            event_idx: false,
            exit_event: EventFd::new(EFD_NONBLOCK).map_err(|_| Error::EventFdFailed)?,
            mem: None,
        })
    }

    /// Process the requests in the vring and dispatch replies
    fn process_requests(
        &self,
        requests: Vec<I2cDescriptorChain>,
        vring: &VringRwLock,
    ) -> Result<bool> {
        let mut reqs: Vec<I2cReq> = Vec::new();

        if requests.is_empty() {
            return Ok(true);
        }

        // Iterate over each I2C request and push it to "reqs" vector.
        for desc_chain in requests.clone() {
            let descriptors: Vec<_> = desc_chain.clone().collect();

            if (descriptors.len() != 2) && (descriptors.len() != 3) {
                return Err(Error::UnexpectedDescriptorCount(descriptors.len()));
            }

            let desc_out_hdr = descriptors[0];

            if desc_out_hdr.is_write_only() {
                return Err(Error::UnexpectedWriteOnlyDescriptor(0));
            }

            if desc_out_hdr.len() as usize != size_of::<VirtioI2cOutHdr>() {
                return Err(Error::UnexpectedDescriptorSize(
                    size_of::<VirtioI2cOutHdr>(),
                    desc_out_hdr.len(),
                ));
            }

            let out_hdr = desc_chain
                .memory()
                .read_obj::<VirtioI2cOutHdr>(desc_out_hdr.addr())
                .map_err(|_| Error::DescriptorReadFailed)?;

            let flags = match out_hdr.flags.to_native() & VIRTIO_I2C_FLAGS_M_RD {
                VIRTIO_I2C_FLAGS_M_RD => I2C_M_RD,
                _ => 0,
            };

            let desc_in_hdr = descriptors[descriptors.len() - 1];
            if !desc_in_hdr.is_write_only() {
                return Err(Error::UnexpectedReadableDescriptor(descriptors.len() - 1));
            }

            if desc_in_hdr.len() as usize != size_of::<u8>() {
                return Err(Error::UnexpectedDescriptorSize(
                    size_of::<u8>(),
                    desc_in_hdr.len(),
                ));
            }

            let (buf, len) = match descriptors.len() {
                // Buffer is available
                3 => {
                    let desc_buf = descriptors[1];
                    let len = desc_buf.len();

                    if len == 0 {
                        return Err(Error::UnexpectedDescriptorSize(1, len));
                    }
                    let mut buf = vec![0; len as usize];

                    if flags != I2C_M_RD {
                        if desc_buf.is_write_only() {
                            return Err(Error::UnexpectedWriteOnlyDescriptor(1));
                        }

                        desc_chain
                            .memory()
                            .read(&mut buf, desc_buf.addr())
                            .map_err(|_| Error::DescriptorReadFailed)?;
                    } else if !desc_buf.is_write_only() {
                        return Err(Error::UnexpectedReadableDescriptor(1));
                    }

                    (buf, len)
                }

                _ => (Vec::<u8>::new(), 0),
            };

            reqs.push(I2cReq {
                addr: out_hdr.addr.to_native() >> 1,
                flags,
                len: len as u16,
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

        for (i, desc_chain) in requests.iter().enumerate() {
            let descriptors: Vec<_> = desc_chain.clone().collect();
            let desc_in_hdr = descriptors[descriptors.len() - 1];
            let mut len = size_of::<VirtioI2cInHdr>() as u32;

            if descriptors.len() == 3 {
                let desc_buf = descriptors[1];

                // Write the data read from the I2C device
                if reqs[i].flags == I2C_M_RD {
                    desc_chain
                        .memory()
                        .write(&reqs[i].buf, desc_buf.addr())
                        .map_err(|_| Error::DescriptorWriteFailed)?;
                }

                if in_hdr.status == VIRTIO_I2C_MSG_OK {
                    len += desc_buf.len();
                }
            }

            // Write the transfer status
            desc_chain
                .memory()
                .write_obj::<VirtioI2cInHdr>(in_hdr, desc_in_hdr.addr())
                .map_err(|_| Error::DescriptorWriteFailed)?;

            if vring.add_used(desc_chain.head_index(), len).is_err() {
                warn!("Couldn't return used descriptors to the ring");
            }
        }

        Ok(true)
    }

    /// Process the requests in the vring and dispatch replies
    fn process_queue(&self, vring: &VringRwLock) -> Result<()> {
        let requests: Vec<_> = vring
            .get_mut()
            .get_queue_mut()
            .iter(self.mem.as_ref().unwrap().clone())
            .map_err(|_| Error::DescriptorNotFound)?
            .collect();

        if self.process_requests(requests, vring)? {
            // Send notification once all the requests are processed
            vring
                .signal_used_queue()
                .map_err(|_| Error::NotificationFailed)?;
        }

        Ok(())
    }
}

/// VhostUserBackendMut trait methods
impl<D: 'static + I2cDevice + Sync + Send> VhostUserBackendMut for VhostUserI2cBackend<D> {
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
            | 1 << VIRTIO_I2C_F_ZERO_LENGTH_REQUEST
            | VhostUserVirtioFeatures::PROTOCOL_FEATURES.bits()
    }

    fn protocol_features(&self) -> VhostUserProtocolFeatures {
        VhostUserProtocolFeatures::MQ
    }

    fn set_event_idx(&mut self, enabled: bool) {
        self.event_idx = enabled;
    }

    fn update_memory(&mut self, mem: GuestMemoryAtomic<GuestMemoryMmap>) -> IoResult<()> {
        self.mem = Some(mem.memory());
        Ok(())
    }

    fn handle_event(
        &mut self,
        device_event: u16,
        evset: EventSet,
        vrings: &[VringRwLock],
        _thread_id: usize,
    ) -> IoResult<()> {
        if evset != EventSet::IN {
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
                warn!("unhandled device_event: {}", device_event);
                return Err(Error::HandleEventUnknown.into());
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
    use virtio_bindings::bindings::virtio_ring::{VRING_DESC_F_NEXT, VRING_DESC_F_WRITE};
    use virtio_queue::{mock::MockSplitQueue, Descriptor, Queue};
    use vm_memory::{Address, GuestAddress, GuestMemoryAtomic, GuestMemoryMmap};

    use super::Error;
    use super::*;
    use crate::i2c::tests::{update_rdwr_buf, verify_rdwr_buf, DummyDevice};
    use crate::AdapterConfig;

    // Prepares a single chain of descriptors
    fn prepare_desc_chain(
        start_addr: GuestAddress,
        buf: &mut [u8],
        flag: u32,
        client_addr: u16,
    ) -> I2cDescriptorChain {
        let mem = &GuestMemoryMmap::<()>::from_ranges(&[(start_addr, 0x1000)]).unwrap();
        let vq = MockSplitQueue::new(mem, 16);
        let mut next_addr = vq.desc_table().total_size() + 0x100;
        let mut index = 0;

        // Out header descriptor
        let out_hdr = VirtioI2cOutHdr {
            addr: From::from(client_addr << 1),
            padding: From::from(0x0),
            flags: From::from(flag),
        };

        let desc_out = Descriptor::new(
            next_addr,
            size_of::<VirtioI2cOutHdr>() as u32,
            VRING_DESC_F_NEXT as u16,
            index + 1,
        );

        mem.write_obj::<VirtioI2cOutHdr>(out_hdr, desc_out.addr())
            .unwrap();
        vq.desc_table().store(index, desc_out).unwrap();
        next_addr += u64::from(desc_out.len());
        index += 1;

        // Buf descriptor: optional
        if !buf.is_empty() {
            // Set buffer is write-only or not
            let flag = if (flag & VIRTIO_I2C_FLAGS_M_RD) == 0 {
                update_rdwr_buf(buf);
                0
            } else {
                VRING_DESC_F_WRITE
            };

            let desc_buf = Descriptor::new(
                next_addr,
                buf.len() as u32,
                (flag | VRING_DESC_F_NEXT) as u16,
                index + 1,
            );
            mem.write(buf, desc_buf.addr()).unwrap();
            vq.desc_table().store(index, desc_buf).unwrap();
            next_addr += u64::from(desc_buf.len());
            index += 1;
        }

        // In response descriptor
        let desc_in = Descriptor::new(
            next_addr,
            size_of::<u8>() as u32,
            VRING_DESC_F_WRITE as u16,
            0,
        );
        vq.desc_table().store(index, desc_in).unwrap();

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

    // Validate descriptor chains after processing them, checks pass/failure of
    // operation and the value of the buffers updated by the `DummyDevice`.
    fn validate_desc_chains(desc_chains: Vec<I2cDescriptorChain>, status: u8) {
        for desc_chain in desc_chains {
            let descriptors: Vec<_> = desc_chain.clone().collect();

            let in_hdr = desc_chain
                .memory()
                .read_obj::<VirtioI2cInHdr>(descriptors[descriptors.len() - 1].addr())
                .unwrap();

            // Operation result should match expected status.
            assert_eq!(in_hdr.status, status);

            let out_hdr = desc_chain
                .memory()
                .read_obj::<VirtioI2cOutHdr>(descriptors[0].addr())
                .unwrap();

            if (out_hdr.flags.to_native() & VIRTIO_I2C_FLAGS_M_RD) != 0 && descriptors.len() == 3 {
                let mut buf = vec![0; descriptors[1].len() as usize];
                desc_chain
                    .memory()
                    .read(&mut buf, descriptors[1].addr())
                    .unwrap();

                // Verify the content of the read-buffer
                verify_rdwr_buf(&buf);
            }
        }
    }

    // Prepares list of dummy descriptors, their content isn't significant
    fn prepare_desc_chain_dummy(
        addr: Option<Vec<u64>>,
        flags: Vec<u16>,
        len: Vec<u32>,
    ) -> I2cDescriptorChain {
        let mem = &GuestMemoryMmap::<()>::from_ranges(&[(GuestAddress(0), 0x1000)]).unwrap();
        let vq = MockSplitQueue::new(mem, 16);

        for (i, flag) in flags.iter().enumerate() {
            let mut f: u16 = if i == flags.len() - 1 {
                0
            } else {
                VRING_DESC_F_NEXT as u16
            };
            f |= flag;

            let offset = addr.as_ref().map_or(0x100_u64, |addr| addr[i]);
            let desc = Descriptor::new(offset, len[i], f, (i + 1) as u16);
            vq.desc_table().store(i as u16, desc).unwrap();
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
    fn process_requests_success() {
        let device_config = AdapterConfig::try_from("1:4,2:32:21,5:10:23").unwrap();
        let i2c_map = I2cMap::<DummyDevice>::new(&device_config).unwrap();
        let backend = VhostUserI2cBackend::new(Arc::new(i2c_map)).unwrap();
        let mem = GuestMemoryAtomic::new(
            GuestMemoryMmap::<()>::from_ranges(&[(GuestAddress(0), 0x1000)]).unwrap(),
        );
        let vring = VringRwLock::new(mem, 0x1000).unwrap();

        // Descriptor chain size zero, shouldn't fail
        backend
            .process_requests(Vec::<I2cDescriptorChain>::new(), &vring)
            .unwrap();

        // Valid single read descriptor
        let mut buf: Vec<u8> = vec![0; 30];
        let desc_chain = prepare_desc_chain(GuestAddress(0), &mut buf, VIRTIO_I2C_FLAGS_M_RD, 4);
        let desc_chains = vec![desc_chain];

        backend
            .process_requests(desc_chains.clone(), &vring)
            .unwrap();
        validate_desc_chains(desc_chains, VIRTIO_I2C_MSG_OK);

        // Valid single write descriptor
        let mut buf: Vec<u8> = vec![0; 30];
        let desc_chain = prepare_desc_chain(GuestAddress(0), &mut buf, 0, 4);
        let desc_chains = vec![desc_chain];

        backend
            .process_requests(desc_chains.clone(), &vring)
            .unwrap();
        validate_desc_chains(desc_chains, VIRTIO_I2C_MSG_OK);

        // Valid mixed read-write descriptors
        let mut buf: Vec<Vec<u8>> = vec![vec![0; 30]; 6];
        let desc_chains = vec![
            // Write
            prepare_desc_chain(GuestAddress(0), &mut buf[0], 0, 4),
            // Read
            prepare_desc_chain(GuestAddress(0), &mut buf[1], VIRTIO_I2C_FLAGS_M_RD, 4),
            // Write
            prepare_desc_chain(GuestAddress(0), &mut buf[2], 0, 4),
            // Read
            prepare_desc_chain(GuestAddress(0), &mut buf[3], VIRTIO_I2C_FLAGS_M_RD, 4),
            // Write
            prepare_desc_chain(GuestAddress(0), &mut buf[4], 0, 4),
            // Read
            prepare_desc_chain(GuestAddress(0), &mut buf[5], VIRTIO_I2C_FLAGS_M_RD, 4),
        ];

        backend
            .process_requests(desc_chains.clone(), &vring)
            .unwrap();
        validate_desc_chains(desc_chains, VIRTIO_I2C_MSG_OK);
    }

    #[test]
    fn process_requests_failure() {
        let device_config = AdapterConfig::try_from("1:4,2:32:21,5:10:23").unwrap();
        let i2c_map = I2cMap::<DummyDevice>::new(&device_config).unwrap();
        let backend = VhostUserI2cBackend::new(Arc::new(i2c_map)).unwrap();
        let mem = GuestMemoryAtomic::new(
            GuestMemoryMmap::<()>::from_ranges(&[(GuestAddress(0), 0x1000)]).unwrap(),
        );
        let vring = VringRwLock::new(mem, 0x1000).unwrap();

        // One descriptors
        let flags: Vec<u16> = vec![0];
        let len: Vec<u32> = vec![0];
        let desc_chain = prepare_desc_chain_dummy(None, flags, len);
        assert_eq!(
            backend
                .process_requests(vec![desc_chain], &vring)
                .unwrap_err(),
            Error::UnexpectedDescriptorCount(1)
        );

        // Four descriptors
        let flags: Vec<u16> = vec![0, 0, 0, 0];
        let len: Vec<u32> = vec![0, 0, 0, 0];
        let desc_chain = prepare_desc_chain_dummy(None, flags, len);
        assert_eq!(
            backend
                .process_requests(vec![desc_chain], &vring)
                .unwrap_err(),
            Error::UnexpectedDescriptorCount(4)
        );

        // Write only out hdr
        let flags: Vec<u16> = vec![VRING_DESC_F_WRITE as u16, 0, VRING_DESC_F_WRITE as u16];
        let len: Vec<u32> = vec![
            size_of::<VirtioI2cOutHdr>() as u32,
            1,
            size_of::<u8>() as u32,
        ];
        let desc_chain = prepare_desc_chain_dummy(None, flags, len);
        assert_eq!(
            backend
                .process_requests(vec![desc_chain], &vring)
                .unwrap_err(),
            Error::UnexpectedWriteOnlyDescriptor(0)
        );

        // Invalid out hdr length
        let flags: Vec<u16> = vec![0, 0, VRING_DESC_F_WRITE as u16];
        let len: Vec<u32> = vec![100, 1, size_of::<u8>() as u32];
        let desc_chain = prepare_desc_chain_dummy(None, flags, len);
        assert_eq!(
            backend
                .process_requests(vec![desc_chain], &vring)
                .unwrap_err(),
            Error::UnexpectedDescriptorSize(size_of::<VirtioI2cOutHdr>(), 100)
        );

        // Invalid out hdr address
        let addr: Vec<u64> = vec![0x10000, 0, 0];
        let flags: Vec<u16> = vec![0, 0, VRING_DESC_F_WRITE as u16];
        let len: Vec<u32> = vec![
            size_of::<VirtioI2cOutHdr>() as u32,
            1,
            size_of::<u8>() as u32,
        ];
        let desc_chain = prepare_desc_chain_dummy(Some(addr), flags, len);
        assert_eq!(
            backend
                .process_requests(vec![desc_chain], &vring)
                .unwrap_err(),
            Error::DescriptorReadFailed
        );

        // Read only in hdr
        let flags: Vec<u16> = vec![0, 0, 0];
        let len: Vec<u32> = vec![
            size_of::<VirtioI2cOutHdr>() as u32,
            1,
            size_of::<u8>() as u32,
        ];
        let desc_chain = prepare_desc_chain_dummy(None, flags, len);
        assert_eq!(
            backend
                .process_requests(vec![desc_chain], &vring)
                .unwrap_err(),
            Error::UnexpectedReadableDescriptor(2)
        );

        // Invalid in hdr length
        let flags: Vec<u16> = vec![0, 0, VRING_DESC_F_WRITE as u16];
        let len: Vec<u32> = vec![size_of::<VirtioI2cOutHdr>() as u32, 1, 100];
        let desc_chain = prepare_desc_chain_dummy(None, flags, len);
        assert_eq!(
            backend
                .process_requests(vec![desc_chain], &vring)
                .unwrap_err(),
            Error::UnexpectedDescriptorSize(size_of::<u8>(), 100)
        );

        // Invalid in hdr address
        let addr: Vec<u64> = vec![0, 0, 0x10000];
        let flags: Vec<u16> = vec![0, 0, VRING_DESC_F_WRITE as u16];
        let len: Vec<u32> = vec![
            size_of::<VirtioI2cOutHdr>() as u32,
            1,
            size_of::<u8>() as u32,
        ];
        let desc_chain = prepare_desc_chain_dummy(Some(addr), flags, len);
        assert_eq!(
            backend
                .process_requests(vec![desc_chain], &vring)
                .unwrap_err(),
            Error::DescriptorWriteFailed
        );

        // Invalid buf length
        let flags: Vec<u16> = vec![0, 0, VRING_DESC_F_WRITE as u16];
        let len: Vec<u32> = vec![
            size_of::<VirtioI2cOutHdr>() as u32,
            0,
            size_of::<u8>() as u32,
        ];
        let desc_chain = prepare_desc_chain_dummy(None, flags, len);
        assert_eq!(
            backend
                .process_requests(vec![desc_chain], &vring)
                .unwrap_err(),
            Error::UnexpectedDescriptorSize(1, 0)
        );

        // Invalid buf address
        let addr: Vec<u64> = vec![0, 0x10000, 0];
        let flags: Vec<u16> = vec![0, 0, VRING_DESC_F_WRITE as u16];
        let len: Vec<u32> = vec![
            size_of::<VirtioI2cOutHdr>() as u32,
            1,
            size_of::<u8>() as u32,
        ];
        let desc_chain = prepare_desc_chain_dummy(Some(addr), flags, len);
        assert_eq!(
            backend
                .process_requests(vec![desc_chain], &vring)
                .unwrap_err(),
            Error::DescriptorReadFailed
        );

        // Write only buf for write operation
        let flags: Vec<u16> = vec![0, VRING_DESC_F_WRITE as u16, VRING_DESC_F_WRITE as u16];
        let len: Vec<u32> = vec![
            size_of::<VirtioI2cOutHdr>() as u32,
            10,
            size_of::<u8>() as u32,
        ];
        let desc_chain = prepare_desc_chain_dummy(None, flags, len);
        assert_eq!(
            backend
                .process_requests(vec![desc_chain], &vring)
                .unwrap_err(),
            Error::UnexpectedWriteOnlyDescriptor(1)
        );

        // Missing buffer for I2C rdwr transfer
        let mut buf = Vec::<u8>::new();
        let desc_chain = prepare_desc_chain(GuestAddress(0), &mut buf, VIRTIO_I2C_FLAGS_M_RD, 4);
        let desc_chains = vec![desc_chain];

        backend
            .process_requests(desc_chains.clone(), &vring)
            .unwrap();
        validate_desc_chains(desc_chains, VIRTIO_I2C_MSG_ERR);
    }

    #[test]
    fn verify_backend() {
        let device_config = AdapterConfig::try_from("1:4,2:32:21,5:10:23").unwrap();
        let i2c_map: I2cMap<DummyDevice> = I2cMap::new(&device_config).unwrap();
        let mut backend = VhostUserI2cBackend::new(Arc::new(i2c_map)).unwrap();

        assert_eq!(backend.num_queues(), NUM_QUEUES);
        assert_eq!(backend.max_queue_size(), QUEUE_SIZE);
        assert_eq!(backend.features(), 0x171000001);
        assert_eq!(backend.protocol_features(), VhostUserProtocolFeatures::MQ);

        assert_eq!(backend.queues_per_thread(), vec![0xffff_ffff]);
        assert_eq!(backend.get_config(0, 0), vec![]);

        backend.set_event_idx(true);
        assert!(backend.event_idx);

        assert!(backend.exit_event(0).is_some());

        let mem = GuestMemoryAtomic::new(
            GuestMemoryMmap::<()>::from_ranges(&[(GuestAddress(0), 0x1000)]).unwrap(),
        );
        backend.update_memory(mem.clone()).unwrap();

        let vring = VringRwLock::new(mem, 0x1000).unwrap();
        vring.set_queue_info(0x100, 0x200, 0x300).unwrap();
        vring.set_queue_ready(true);

        assert_eq!(
            backend
                .handle_event(0, EventSet::OUT, &[vring.clone()], 0)
                .unwrap_err()
                .kind(),
            io::ErrorKind::Other
        );

        assert_eq!(
            backend
                .handle_event(1, EventSet::IN, &[vring.clone()], 0)
                .unwrap_err()
                .kind(),
            io::ErrorKind::Other
        );

        // Hit the loop part
        backend.set_event_idx(true);
        backend
            .handle_event(0, EventSet::IN, &[vring.clone()], 0)
            .unwrap();

        // Hit the non-loop part
        backend.set_event_idx(false);
        backend.handle_event(0, EventSet::IN, &[vring], 0).unwrap();
    }
}
