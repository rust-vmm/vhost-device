// vhost device spi
//
// Copyright (c) 2024 Qualcomm Innovation Center, Inc. All rights reserved.
//          Haixu Cui <quic_haixcui@quicinc.com>
//
// SPDX-License-Identifier: Apache-2.0 or BSD-3-Clause

use std::{
    cmp::Ordering,
    convert::From,
    io::{self, Read, Result as IoResult, Write},
    mem::size_of,
    sync::Arc,
};

use log::warn;
use thiserror::Error as ThisError;
use vhost::vhost_user::message::{VhostUserProtocolFeatures, VhostUserVirtioFeatures};
use vhost_user_backend::{VhostUserBackendMut, VringRwLock, VringT};
use virtio_bindings::bindings::virtio_config::{VIRTIO_F_NOTIFY_ON_EMPTY, VIRTIO_F_VERSION_1};
use virtio_bindings::bindings::virtio_ring::{
    VIRTIO_RING_F_EVENT_IDX, VIRTIO_RING_F_INDIRECT_DESC,
};
use virtio_queue::DescriptorChain;
use virtio_queue::QueueOwnedT;
use vm_memory::{
    ByteValued, GuestAddressSpace, GuestMemoryAtomic, GuestMemoryLoadGuard, GuestMemoryMmap, Le32,
};
use vmm_sys_util::epoll::EventSet;
use vmm_sys_util::eventfd::{EventFd, EFD_NONBLOCK};

use crate::spi::*;

const QUEUE_SIZE: usize = 1024;
const NUM_QUEUES: usize = 1;

type Result<T> = std::result::Result<T, Error>;

#[derive(Copy, Clone, Debug, Eq, PartialEq, ThisError)]
/// Errors related to vhost-device-spi daemon.
pub enum Error {
    #[error("TX length  {0} and RX length {1} don't match")]
    TxRxTrnasLenNotEqual(u32, u32),
    #[error("TX length and RX length are both zero")]
    TransZeroLength,
    #[error("Failed to handle event, didn't match EPOLLIN")]
    HandleEventNotEpollIn,
    #[error("Failed to handle unknown event {0}")]
    HandleEventUnknown(u16),
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
    #[error("No memory configured")]
    NoMemoryConfigured,
}

impl From<Error> for io::Error {
    fn from(e: Error) -> Self {
        Self::new(io::ErrorKind::Other, e)
    }
}

/// The final status written by the device
#[derive(Clone, Copy, Debug)]
#[repr(u8)]
enum ResponseStatus {
    #[doc(alias = "VIRTIO_SPI_TRANS_OK")]
    TransOk = 0,
    #[doc(alias = "VIRTIO_SPI_PARAM_ERR")]
    ParamErr = 1,
    #[doc(alias = "VIRTIO_SPI_TRANS_ERR")]
    TransErr = 2,
}

#[derive(Copy, Clone, Default, Debug)]
#[repr(C)]
struct VirtioSpiTransferHead {
    chip_select_id: u8,
    bits_per_word: u8,
    cs_change: u8,
    tx_nbits: u8,
    rx_nbits: u8,
    reserved1: u8,
    reserved2: u8,
    reserved3: u8,
    mode: Le32,
    freq: Le32,
    word_delay_ns: Le32,
    cs_setup_ns: Le32,
    cs_delay_hold_ns: Le32,
    cs_change_delay_inactive_ns: Le32,
}
// SAFETY: The layout of the structure is fixed and can be initialized by
// reading its content from byte array.
unsafe impl ByteValued for VirtioSpiTransferHead {}

#[derive(Copy, Clone, Default)]
#[repr(C)]
struct VirtioSpiTransferResult {
    status: u8,
}
// SAFETY: The layout of the structure is fixed and can be initialized by
// reading its content from byte array.
unsafe impl ByteValued for VirtioSpiTransferResult {}

/// Virtio SPI Configuration
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
#[repr(C)]
pub struct VirtioSpiConfig {
    pub(crate) cs_max_number: u8,
    pub(crate) cs_change_supported: u8,
    pub(crate) tx_nbits_supported: u8,
    pub(crate) rx_nbits_supported: u8,
    pub(crate) bits_per_word_mask: Le32,
    pub(crate) mode_func_supported: Le32,
    pub(crate) max_freq_hz: Le32,
    pub(crate) max_word_delay_ns: Le32,
    pub(crate) max_cs_setup_ns: Le32,
    pub(crate) max_cs_hold_ns: Le32,
    pub(crate) max_cs_inactive_ns: Le32,
}

// SAFETY: The layout of the structure is fixed and can be initialized by
// reading its content from byte array.
unsafe impl ByteValued for VirtioSpiConfig {}

pub struct VhostUserSpiBackend<D: SpiDevice> {
    spi_ctrl: Arc<SpiController<D>>,
    event_idx: bool,
    pub exit_event: EventFd,
    mem: Option<GuestMemoryAtomic<GuestMemoryMmap>>,
}

type SpiDescriptorChain = DescriptorChain<GuestMemoryLoadGuard<GuestMemoryMmap<()>>>;

impl<D: SpiDevice> VhostUserSpiBackend<D> {
    pub fn new(spi_ctrl: Arc<SpiController<D>>) -> Result<Self> {
        Ok(Self {
            spi_ctrl,
            event_idx: false,
            exit_event: EventFd::new(EFD_NONBLOCK).map_err(|_| Error::EventFdFailed)?,
            mem: None,
        })
    }

    /// Process the requests in the vring and dispatch replies
    fn process_requests(
        &self,
        requests: Vec<SpiDescriptorChain>,
        vring: &VringRwLock,
    ) -> Result<bool> {
        let mut reqs: Vec<SpiTransReq> = Vec::new();

        let Some(ref atomic_mem) = self.mem else {
            return Err(Error::NoMemoryConfigured);
        };

        if requests.is_empty() {
            return Ok(true);
        }

        // Iterate over each SPI request.
        for desc_chain in requests.clone() {
            let mem = atomic_mem.memory();
            let mut tx_buf: Vec<u8>;
            let mut trans_len: u32 = 0;

            let mut reader = desc_chain
                .clone()
                .reader(&mem)
                .map_err(|_| Error::DescriptorReadFailed)?;

            let writter = desc_chain
                .clone()
                .writer(&mem)
                .map_err(|_| Error::DescriptorReadFailed)?;

            match reader
                .available_bytes()
                .cmp(&size_of::<VirtioSpiTransferHead>())
            {
                Ordering::Less => {
                    return Err(Error::UnexpectedDescriptorSize(
                        size_of::<VirtioSpiTransferHead>(),
                        reader.available_bytes() as u32,
                    ));
                }
                Ordering::Equal => {
                    tx_buf = Vec::new();
                }
                Ordering::Greater => {
                    trans_len =
                        (reader.available_bytes() - size_of::<VirtioSpiTransferHead>()) as u32;
                    let mut reader_content = reader
                        .split_at(size_of::<VirtioSpiTransferHead>())
                        .map_err(|_| Error::DescriptorReadFailed)?;

                    tx_buf = vec![0; trans_len as usize];

                    trans_len = reader_content
                        .read(&mut tx_buf)
                        .map_err(|_| Error::DescriptorReadFailed)?
                        as u32;
                }
            }

            let rx_buf: Vec<u8> = match writter.available_bytes().cmp(&size_of::<u8>()) {
                Ordering::Less => {
                    return Err(Error::UnexpectedDescriptorSize(
                        size_of::<u8>(),
                        writter.available_bytes() as u32,
                    ));
                }
                Ordering::Equal => Vec::new(),
                Ordering::Greater => {
                    if trans_len != 0
                        && trans_len != (writter.available_bytes() - size_of::<u8>()) as u32
                    {
                        return Err(Error::TxRxTrnasLenNotEqual(
                            trans_len,
                            (writter.available_bytes() - size_of::<u8>()) as u32,
                        ));
                    } else if trans_len == 0 {
                        trans_len = (writter.available_bytes() - size_of::<u8>()) as u32;
                    }
                    vec![0; trans_len as usize]
                }
            };

            if trans_len == 0 {
                return Err(Error::TransZeroLength);
            }

            let out_hdr = reader
                .read_obj::<VirtioSpiTransferHead>()
                .map_err(|_| Error::DescriptorReadFailed)?;

            reqs.push(SpiTransReq {
                tx_buf,
                rx_buf,
                trans_len,
                speed_hz: out_hdr.freq.to_native(),
                delay_usecs: (out_hdr.cs_delay_hold_ns.to_native() / 1000) as u16,
                bits_per_word: out_hdr.bits_per_word,
                cs_change: out_hdr.cs_change,
                tx_nbits: out_hdr.tx_nbits,
                rx_nbits: out_hdr.rx_nbits,
                word_delay_usecs: (out_hdr.word_delay_ns.to_native() / 1000) as u8,
                mode: out_hdr.mode.to_native(),
                cs_id: out_hdr.chip_select_id,
            });
        }

        let mut req_param_stat = Vec::with_capacity(requests.len());

        if !self
            .spi_ctrl
            .check_trans_params(&mut reqs, &mut req_param_stat)
        {
            for (i, desc_chain) in requests.iter().enumerate() {
                let mut len = size_of::<VirtioSpiTransferResult>() as u32;
                let mem = atomic_mem.memory();
                let req_param_valid = match req_param_stat[i] {
                    true => VirtioSpiTransferResult {
                        status: ResponseStatus::TransOk as u8,
                    },
                    _ => VirtioSpiTransferResult {
                        status: ResponseStatus::ParamErr as u8,
                    },
                };

                let mut writter = desc_chain
                    .clone()
                    .writer(&mem)
                    .map_err(|_| Error::DescriptorReadFailed)?;

                if writter.available_bytes() > size_of::<u8>() {
                    let rx_len = (writter.available_bytes() - size_of::<u8>()) as u32;
                    let mut writter_status = writter
                        .split_at(rx_len as usize)
                        .map_err(|_| Error::DescriptorReadFailed)?;

                    writter_status
                        .write_obj(req_param_valid)
                        .map_err(|_| Error::DescriptorWriteFailed)?;

                    len += rx_len;
                } else {
                    writter
                        .write_obj(req_param_valid)
                        .map_err(|_| Error::DescriptorWriteFailed)?;
                }

                // Write the transfer status
                if vring.add_used(desc_chain.head_index(), len).is_err() {
                    warn!("Couldn't return used descriptors to the ring");
                }
            }
        } else {
            match self.spi_ctrl.transfer(&mut reqs) {
                Ok(()) => {
                    let in_hdr = VirtioSpiTransferResult {
                        status: ResponseStatus::TransOk as u8,
                    };
                    for (desc_chain, req) in requests.iter().zip(reqs.iter()) {
                        let mut len = size_of::<VirtioSpiTransferResult>() as u32;
                        let mem = atomic_mem.memory();

                        let mut writter = desc_chain
                            .clone()
                            .writer(&mem)
                            .map_err(|_| Error::DescriptorReadFailed)?;

                        if writter.available_bytes() > size_of::<u8>() {
                            let rx_len = (writter.available_bytes() - size_of::<u8>()) as u32;
                            let mut writter_status = writter
                                .split_at(rx_len as usize)
                                .map_err(|_| Error::DescriptorReadFailed)?;

                            writter_status
                                .write_obj(in_hdr)
                                .map_err(|_| Error::DescriptorWriteFailed)?;

                            writter
                                .write(&req.rx_buf)
                                .map_err(|_| Error::DescriptorWriteFailed)?;

                            len += rx_len;
                        } else {
                            writter
                                .write_obj(in_hdr)
                                .map_err(|_| Error::DescriptorWriteFailed)?;
                        }

                        // Write the transfer status
                        if vring.add_used(desc_chain.head_index(), len).is_err() {
                            warn!("Couldn't return used descriptors to the ring");
                        }
                    }
                }
                Err(_) => {
                    let in_hdr = VirtioSpiTransferResult {
                        status: ResponseStatus::TransErr as u8,
                    };

                    for desc_chain in requests {
                        let len = size_of::<VirtioSpiTransferResult>() as u32;
                        let mem = atomic_mem.memory();

                        let mut writter = desc_chain
                            .clone()
                            .writer(&mem)
                            .map_err(|_| Error::DescriptorReadFailed)?;

                        writter
                            .write_obj(in_hdr)
                            .map_err(|_| Error::DescriptorWriteFailed)?;

                        // Write the transfer status
                        if vring.add_used(desc_chain.head_index(), len).is_err() {
                            warn!("Couldn't return used descriptors to the ring");
                        }
                    }
                }
            }
        }

        Ok(true)
    }

    /// Process the requests in the vring and dispatch replies
    fn process_queue(&self, vring: &VringRwLock) -> Result<()> {
        let Some(ref atomic_mem) = self.mem else {
            return Err(Error::NoMemoryConfigured);
        };
        let requests: Vec<_> = vring
            .get_mut()
            .get_queue_mut()
            .iter(atomic_mem.memory())
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
impl<D: 'static + SpiDevice + Sync + Send> VhostUserBackendMut for VhostUserSpiBackend<D> {
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
            | VhostUserProtocolFeatures::CONFIG
            | VhostUserProtocolFeatures::REPLY_ACK
    }

    fn set_event_idx(&mut self, enabled: bool) {
        self.event_idx = enabled;
    }

    fn update_memory(&mut self, mem: GuestMemoryAtomic<GuestMemoryMmap>) -> IoResult<()> {
        self.mem = Some(mem);
        Ok(())
    }

    fn get_config(&self, offset: u32, size: u32) -> Vec<u8> {
        self.spi_ctrl.config().as_slice()[(offset as usize)..][..(size as usize)].to_vec()
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
                return Err(Error::HandleEventUnknown(device_event).into());
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
    use std::path::PathBuf;
    use std::slice::from_raw_parts;
    use virtio_bindings::bindings::virtio_ring::{VRING_DESC_F_NEXT, VRING_DESC_F_WRITE};
    use virtio_queue::{mock::MockSplitQueue, Descriptor};
    use vm_memory::{Bytes, GuestAddress, GuestMemoryAtomic, GuestMemoryMmap};

    use super::Error;
    use super::*;
    use crate::spi::tests::{verify_rdwr_buf, DummyDevice};

    // Prepares descriptor chains
    fn setup_descs(descs: &[Descriptor]) -> (VringRwLock, GuestMemoryAtomic<GuestMemoryMmap>) {
        let mem = GuestMemoryAtomic::new(
            GuestMemoryMmap::<()>::from_ranges(&[(GuestAddress(0), 0x1000_0000)]).unwrap(),
        );
        let mem_handle = mem.memory();

        let queue = MockSplitQueue::new(&*mem_handle, 16);

        let mut modified_descs: Vec<Descriptor> = Vec::with_capacity(descs.len());

        // Use this tag to indicate the start of request
        let mut request_head: bool = true;

        for (idx, desc) in descs.iter().enumerate() {
            let next = if desc.flags() & VRING_DESC_F_NEXT as u16 == 0 {
                // This is the last descriptor of the request. Next descriptor is the head
                // of the next request, so set tag as true.
                request_head = true;
                0
            } else {
                // If not the request header and readable, the descriptor indicates the tx_buf.
                // Then update the tx_buf to test the transfer process.
                if !request_head && desc.flags() & VRING_DESC_F_WRITE as u16 == 0 {
                    let tx_data: Vec<u8> = (0..desc.len() as u8).collect();

                    mem.memory()
                        .write(&tx_data, desc.addr())
                        .expect("writing to succeed");
                }

                request_head = false;
                idx as u16 + 1
            };

            modified_descs.push(Descriptor::new(
                desc.addr().0,
                desc.len(),
                desc.flags(),
                next,
            ));
        }

        queue
            .build_multiple_desc_chains(&modified_descs[..])
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

    // Validate descriptor chains after processing them, checks pass/failure of
    // operation and the value of the buffers updated by the `DummyDevice`.
    fn validate_rx_data(mem: GuestMemoryAtomic<GuestMemoryMmap>, rx_addr: u64, rx_len: u32) {
        let mut rx_buf: Vec<u8> = vec![0; rx_len as usize];

        mem.memory()
            .read(&mut rx_buf, GuestAddress(rx_addr))
            .expect("reading to succeed");

        verify_rdwr_buf(rx_buf.as_ptr() as u64, rx_len);
    }

    fn validate_trans_result(
        mem: GuestMemoryAtomic<GuestMemoryMmap>,
        result_addr: u64,
        status: u8,
    ) {
        let in_hdr = mem
            .memory()
            .read_obj::<VirtioSpiTransferResult>(GuestAddress(result_addr))
            .expect("reading to succeed");

        assert_eq!(in_hdr.status, status);
    }

    #[test]
    fn process_requests_success() {
        let spi_dummy_ctrl =
            SpiController::new(DummyDevice::open(&PathBuf::from("spidev0.0")).unwrap()).unwrap();
        let mut backend = VhostUserSpiBackend::new(Arc::new(spi_dummy_ctrl)).unwrap();

        // Parameters to create two requests
        let trans_header_addr1: u64 = 0x10_0000;
        let tx_buf_addr1: u64 = 0x20_0000;
        let rx_buf_addr1: u64 = 0x30_0000;
        let trans_result_addr1: u64 = 0x40_0000;

        let trans_header_addr2: u64 = 0x50_0000;
        let tx_buf_addr2: u64 = 0x60_0000;
        let rx_buf_addr2: u64 = 0x70_0000;
        let trans_result_addr2: u64 = 0x80_0000;

        // Valid single write request
        let to_descs = [
            Descriptor::new(
                trans_header_addr1,
                size_of::<VirtioSpiTransferHead>() as u32,
                VRING_DESC_F_NEXT as u16,
                0,
            ),
            Descriptor::new(tx_buf_addr1, 30, VRING_DESC_F_NEXT as u16, 0),
            Descriptor::new(
                trans_result_addr1,
                size_of::<VirtioSpiTransferResult>() as u32,
                VRING_DESC_F_WRITE as u16,
                0,
            ),
        ];

        let (vring, mem) = setup_descs(&to_descs);

        let out_hdr = VirtioSpiTransferHead {
            chip_select_id: 0,
            bits_per_word: 8,
            cs_change: 0,
            tx_nbits: 1,
            rx_nbits: 1,
            reserved1: 0,
            reserved2: 0,
            reserved3: 0,
            mode: From::from(0),
            freq: From::from(10000),
            word_delay_ns: From::from(0),
            cs_setup_ns: From::from(0),
            cs_delay_hold_ns: From::from(0),
            cs_change_delay_inactive_ns: From::from(0),
        };

        mem.memory()
            .write_obj(out_hdr, GuestAddress(trans_header_addr1))
            .expect("writing to succeed");

        backend.update_memory(mem.clone()).unwrap();
        backend.process_queue(&vring).unwrap();

        validate_trans_result(
            mem.clone(),
            trans_result_addr1,
            ResponseStatus::TransOk as u8,
        );

        // Valid single read request
        let ro_descs = [
            Descriptor::new(
                trans_header_addr1,
                size_of::<VirtioSpiTransferHead>() as u32,
                VRING_DESC_F_NEXT as u16,
                0,
            ),
            Descriptor::new(
                rx_buf_addr1,
                30,
                (VRING_DESC_F_NEXT | VRING_DESC_F_WRITE) as u16,
                0,
            ),
            Descriptor::new(
                trans_result_addr1,
                size_of::<VirtioSpiTransferResult>() as u32,
                VRING_DESC_F_WRITE as u16,
                0,
            ),
        ];

        let (vring, mem) = setup_descs(&ro_descs);

        let out_hdr = VirtioSpiTransferHead {
            chip_select_id: 0,
            bits_per_word: 8,
            cs_change: 0,
            tx_nbits: 1,
            rx_nbits: 1,
            reserved1: 0,
            reserved2: 0,
            reserved3: 0,
            mode: From::from(0),
            freq: From::from(10000),
            word_delay_ns: From::from(0),
            cs_setup_ns: From::from(0),
            cs_delay_hold_ns: From::from(0),
            cs_change_delay_inactive_ns: From::from(0),
        };

        mem.memory()
            .write_obj(out_hdr, GuestAddress(trans_header_addr1))
            .expect("writing to succeed");

        backend.update_memory(mem.clone()).unwrap();
        backend.process_queue(&vring).unwrap();

        validate_trans_result(
            mem.clone(),
            trans_result_addr1,
            ResponseStatus::TransOk as u8,
        );

        validate_rx_data(mem.clone(), rx_buf_addr1, 30);

        // Valid mixed read-write request
        let tx_rx_descs = [
            Descriptor::new(
                trans_header_addr1,
                size_of::<VirtioSpiTransferHead>() as u32,
                VRING_DESC_F_NEXT as u16,
                0,
            ),
            Descriptor::new(tx_buf_addr1, 30, VRING_DESC_F_NEXT as u16, 0),
            Descriptor::new(
                rx_buf_addr1,
                30,
                (VRING_DESC_F_NEXT | VRING_DESC_F_WRITE) as u16,
                0,
            ),
            Descriptor::new(
                trans_result_addr1,
                size_of::<VirtioSpiTransferResult>() as u32,
                VRING_DESC_F_WRITE as u16,
                0,
            ),
        ];

        let (vring, mem) = setup_descs(&tx_rx_descs);

        let out_hdr = VirtioSpiTransferHead {
            chip_select_id: 0,
            bits_per_word: 8,
            cs_change: 0,
            tx_nbits: 1,
            rx_nbits: 1,
            reserved1: 0,
            reserved2: 0,
            reserved3: 0,
            mode: From::from(0),
            freq: From::from(10000),
            word_delay_ns: From::from(0),
            cs_setup_ns: From::from(0),
            cs_delay_hold_ns: From::from(0),
            cs_change_delay_inactive_ns: From::from(0),
        };

        mem.memory()
            .write_obj(out_hdr, GuestAddress(trans_header_addr1))
            .expect("writing to succeed");

        backend.update_memory(mem.clone()).unwrap();
        backend.process_queue(&vring).unwrap();

        validate_trans_result(
            mem.clone(),
            trans_result_addr1,
            ResponseStatus::TransOk as u8,
        );

        validate_rx_data(mem.clone(), rx_buf_addr1, 30);

        // Valid multiple requests
        let multi_reqs_descs = [
            Descriptor::new(
                trans_header_addr1,
                size_of::<VirtioSpiTransferHead>() as u32,
                VRING_DESC_F_NEXT as u16,
                0,
            ),
            Descriptor::new(tx_buf_addr1, 30, VRING_DESC_F_NEXT as u16, 0),
            Descriptor::new(
                rx_buf_addr1,
                30,
                (VRING_DESC_F_NEXT | VRING_DESC_F_WRITE) as u16,
                0,
            ),
            Descriptor::new(
                trans_result_addr1,
                size_of::<VirtioSpiTransferResult>() as u32,
                VRING_DESC_F_WRITE as u16,
                0,
            ),
            Descriptor::new(
                trans_header_addr2,
                size_of::<VirtioSpiTransferHead>() as u32,
                VRING_DESC_F_NEXT as u16,
                0,
            ),
            Descriptor::new(tx_buf_addr2, 16, VRING_DESC_F_NEXT as u16, 0),
            Descriptor::new(
                rx_buf_addr2,
                16,
                (VRING_DESC_F_NEXT | VRING_DESC_F_WRITE) as u16,
                0,
            ),
            Descriptor::new(
                trans_result_addr2,
                size_of::<VirtioSpiTransferResult>() as u32,
                VRING_DESC_F_WRITE as u16,
                0,
            ),
        ];

        let (vring, mem) = setup_descs(&multi_reqs_descs);

        let out_hdr = VirtioSpiTransferHead {
            chip_select_id: 0,
            bits_per_word: 8,
            cs_change: 0,
            tx_nbits: 1,
            rx_nbits: 1,
            reserved1: 0,
            reserved2: 0,
            reserved3: 0,
            mode: From::from(0),
            freq: From::from(10000),
            word_delay_ns: From::from(0),
            cs_setup_ns: From::from(0),
            cs_delay_hold_ns: From::from(0),
            cs_change_delay_inactive_ns: From::from(0),
        };

        mem.memory()
            .write_obj(out_hdr, GuestAddress(trans_header_addr1))
            .expect("writing to succeed");

        mem.memory()
            .write_obj(out_hdr, GuestAddress(trans_header_addr2))
            .expect("writing to succeed");

        backend.update_memory(mem.clone()).unwrap();
        backend.process_queue(&vring).unwrap();

        validate_trans_result(
            mem.clone(),
            trans_result_addr1,
            ResponseStatus::TransOk as u8,
        );

        validate_rx_data(mem.clone(), rx_buf_addr1, 30);

        validate_trans_result(
            mem.clone(),
            trans_result_addr2,
            ResponseStatus::TransOk as u8,
        );

        validate_rx_data(mem.clone(), rx_buf_addr2, 16);

        // unsupported LOOP mode, should filter by parameter check
        let mode_invalid_descs = [
            Descriptor::new(
                trans_header_addr1,
                size_of::<VirtioSpiTransferHead>() as u32,
                VRING_DESC_F_NEXT as u16,
                0,
            ),
            Descriptor::new(tx_buf_addr1, 30, VRING_DESC_F_NEXT as u16, 0),
            Descriptor::new(
                trans_result_addr1,
                size_of::<VirtioSpiTransferResult>() as u32,
                VRING_DESC_F_WRITE as u16,
                0,
            ),
        ];

        let (vring, mem) = setup_descs(&mode_invalid_descs);

        let out_hdr = VirtioSpiTransferHead {
            chip_select_id: 0,
            bits_per_word: 8,
            cs_change: 0,
            tx_nbits: 1,
            rx_nbits: 1,
            reserved1: 0,
            reserved2: 0,
            reserved3: 0,
            mode: From::from(0x10),
            freq: From::from(10000),
            word_delay_ns: From::from(0),
            cs_setup_ns: From::from(0),
            cs_delay_hold_ns: From::from(0),
            cs_change_delay_inactive_ns: From::from(0),
        };

        mem.memory()
            .write_obj(out_hdr, GuestAddress(trans_header_addr1))
            .expect("writing to succeed");

        backend.update_memory(mem.clone()).unwrap();
        backend.process_queue(&vring).unwrap();

        validate_trans_result(
            mem.clone(),
            trans_result_addr1,
            ResponseStatus::ParamErr as u8,
        );

        // unsupported tx_nbits, should filter by parameter check
        let mode_invalid_descs = [
            Descriptor::new(
                trans_header_addr1,
                size_of::<VirtioSpiTransferHead>() as u32,
                VRING_DESC_F_NEXT as u16,
                0,
            ),
            Descriptor::new(tx_buf_addr1, 30, VRING_DESC_F_NEXT as u16, 0),
            Descriptor::new(
                trans_result_addr1,
                size_of::<VirtioSpiTransferResult>() as u32,
                VRING_DESC_F_WRITE as u16,
                0,
            ),
        ];

        let (vring, mem) = setup_descs(&mode_invalid_descs);

        let out_hdr = VirtioSpiTransferHead {
            chip_select_id: 0,
            bits_per_word: 8,
            cs_change: 0,
            tx_nbits: 2,
            rx_nbits: 1,
            reserved1: 0,
            reserved2: 0,
            reserved3: 0,
            mode: From::from(0),
            freq: From::from(10000),
            word_delay_ns: From::from(0),
            cs_setup_ns: From::from(0),
            cs_delay_hold_ns: From::from(0),
            cs_change_delay_inactive_ns: From::from(0),
        };

        mem.memory()
            .write_obj(out_hdr, GuestAddress(trans_header_addr1))
            .expect("writing to succeed");

        backend.update_memory(mem.clone()).unwrap();
        backend.process_queue(&vring).unwrap();

        validate_trans_result(
            mem.clone(),
            trans_result_addr1,
            ResponseStatus::ParamErr as u8,
        );

        // Valid multiple requests which contains invalid request header
        let multi_reqs_descs = [
            Descriptor::new(
                trans_header_addr1,
                size_of::<VirtioSpiTransferHead>() as u32,
                VRING_DESC_F_NEXT as u16,
                0,
            ),
            Descriptor::new(tx_buf_addr1, 30, VRING_DESC_F_NEXT as u16, 0),
            Descriptor::new(
                rx_buf_addr1,
                30,
                (VRING_DESC_F_NEXT | VRING_DESC_F_WRITE) as u16,
                0,
            ),
            Descriptor::new(
                trans_result_addr1,
                size_of::<VirtioSpiTransferResult>() as u32,
                VRING_DESC_F_WRITE as u16,
                0,
            ),
            Descriptor::new(
                trans_header_addr2,
                size_of::<VirtioSpiTransferHead>() as u32,
                VRING_DESC_F_NEXT as u16,
                0,
            ),
            Descriptor::new(tx_buf_addr2, 16, VRING_DESC_F_NEXT as u16, 0),
            Descriptor::new(
                rx_buf_addr2,
                16,
                (VRING_DESC_F_NEXT | VRING_DESC_F_WRITE) as u16,
                0,
            ),
            Descriptor::new(
                trans_result_addr2,
                size_of::<VirtioSpiTransferResult>() as u32,
                VRING_DESC_F_WRITE as u16,
                0,
            ),
        ];

        let (vring, mem) = setup_descs(&multi_reqs_descs);

        let out_hdr1 = VirtioSpiTransferHead {
            chip_select_id: 0,
            bits_per_word: 8,
            cs_change: 0,
            tx_nbits: 1,
            rx_nbits: 1,
            reserved1: 0,
            reserved2: 0,
            reserved3: 0,
            mode: From::from(0),
            freq: From::from(10000),
            word_delay_ns: From::from(0),
            cs_setup_ns: From::from(0),
            cs_delay_hold_ns: From::from(0),
            cs_change_delay_inactive_ns: From::from(0),
        };

        let out_hdr2 = VirtioSpiTransferHead {
            chip_select_id: 0,
            bits_per_word: 8,
            cs_change: 0,
            tx_nbits: 1,
            rx_nbits: 4,
            reserved1: 0,
            reserved2: 0,
            reserved3: 0,
            mode: From::from(0),
            freq: From::from(10000),
            word_delay_ns: From::from(0),
            cs_setup_ns: From::from(0),
            cs_delay_hold_ns: From::from(0),
            cs_change_delay_inactive_ns: From::from(0),
        };

        mem.memory()
            .write_obj(out_hdr1, GuestAddress(trans_header_addr1))
            .expect("writing to succeed");

        mem.memory()
            .write_obj(out_hdr2, GuestAddress(trans_header_addr2))
            .expect("writing to succeed");

        backend.update_memory(mem.clone()).unwrap();
        backend.process_queue(&vring).unwrap();

        validate_trans_result(
            mem.clone(),
            trans_result_addr1,
            ResponseStatus::TransOk as u8,
        );

        validate_trans_result(
            mem.clone(),
            trans_result_addr2,
            ResponseStatus::ParamErr as u8,
        );
    }

    #[test]
    fn process_requests_failure() {
        let spi_dummy_ctrl =
            SpiController::new(DummyDevice::open(&PathBuf::from("spidev0.0")).unwrap()).unwrap();
        let mut backend = VhostUserSpiBackend::new(Arc::new(spi_dummy_ctrl)).unwrap();

        // Parameters to create two requests
        let trans_header_addr1: u64 = 0x10_0000;
        let tx_buf_addr1: u64 = 0x20_0000;
        let rx_buf_addr1: u64 = 0x30_0000;
        let trans_result_addr1: u64 = 0x40_0000;

        // Backend mem must be set properly before transmit.
        let writable_head_descs = [
            Descriptor::new(
                trans_header_addr1,
                size_of::<VirtioSpiTransferHead>() as u32,
                (VRING_DESC_F_WRITE | VRING_DESC_F_NEXT) as u16,
                0,
            ),
            Descriptor::new(tx_buf_addr1, 30, VRING_DESC_F_NEXT as u16, 0),
            Descriptor::new(
                trans_result_addr1,
                size_of::<VirtioSpiTransferResult>() as u32,
                VRING_DESC_F_WRITE as u16,
                0,
            ),
        ];

        let (vring, mem) = setup_descs(&writable_head_descs);

        let out_hdr = VirtioSpiTransferHead {
            chip_select_id: 0,
            bits_per_word: 8,
            cs_change: 0,
            tx_nbits: 1,
            rx_nbits: 1,
            reserved1: 0,
            reserved2: 0,
            reserved3: 0,
            mode: From::from(0),
            freq: From::from(10000),
            word_delay_ns: From::from(0),
            cs_setup_ns: From::from(0),
            cs_delay_hold_ns: From::from(0),
            cs_change_delay_inactive_ns: From::from(0),
        };

        mem.memory()
            .write_obj(out_hdr, GuestAddress(trans_header_addr1))
            .expect("writing to succeed");

        assert_eq!(
            backend.process_queue(&vring).unwrap_err(),
            Error::NoMemoryConfigured
        );

        // Set request head descriptor as writable, which is invalid.
        let writable_head_descs = [
            Descriptor::new(
                trans_header_addr1,
                size_of::<VirtioSpiTransferHead>() as u32,
                (VRING_DESC_F_WRITE | VRING_DESC_F_NEXT) as u16,
                0,
            ),
            Descriptor::new(tx_buf_addr1, 30, VRING_DESC_F_NEXT as u16, 0),
            Descriptor::new(
                trans_result_addr1,
                size_of::<VirtioSpiTransferResult>() as u32,
                VRING_DESC_F_WRITE as u16,
                0,
            ),
        ];

        let (vring, mem) = setup_descs(&writable_head_descs);

        let out_hdr = VirtioSpiTransferHead {
            chip_select_id: 0,
            bits_per_word: 8,
            cs_change: 0,
            tx_nbits: 1,
            rx_nbits: 1,
            reserved1: 0,
            reserved2: 0,
            reserved3: 0,
            mode: From::from(0),
            freq: From::from(10000),
            word_delay_ns: From::from(0),
            cs_setup_ns: From::from(0),
            cs_delay_hold_ns: From::from(0),
            cs_change_delay_inactive_ns: From::from(0),
        };

        mem.memory()
            .write_obj(out_hdr, GuestAddress(trans_header_addr1))
            .expect("writing to succeed");

        backend.update_memory(mem.clone()).unwrap();
        assert_eq!(
            backend.process_queue(&vring).unwrap_err(),
            Error::UnexpectedDescriptorSize(32, 30)
        );

        // Set request result descriptor as readable, which is invalid.
        let readable_result_descs = [
            Descriptor::new(
                trans_header_addr1,
                size_of::<VirtioSpiTransferHead>() as u32,
                VRING_DESC_F_NEXT as u16,
                0,
            ),
            Descriptor::new(tx_buf_addr1, 30, VRING_DESC_F_NEXT as u16, 0),
            Descriptor::new(
                trans_result_addr1,
                size_of::<VirtioSpiTransferResult>() as u32,
                0,
                0,
            ),
        ];

        let (vring, mem) = setup_descs(&readable_result_descs);

        let out_hdr = VirtioSpiTransferHead {
            chip_select_id: 0,
            bits_per_word: 8,
            cs_change: 0,
            tx_nbits: 1,
            rx_nbits: 1,
            reserved1: 0,
            reserved2: 0,
            reserved3: 0,
            mode: From::from(0),
            freq: From::from(10000),
            word_delay_ns: From::from(0),
            cs_setup_ns: From::from(0),
            cs_delay_hold_ns: From::from(0),
            cs_change_delay_inactive_ns: From::from(0),
        };

        mem.memory()
            .write_obj(out_hdr, GuestAddress(trans_header_addr1))
            .expect("writing to succeed");

        backend.update_memory(mem.clone()).unwrap();
        assert_eq!(
            backend.process_queue(&vring).unwrap_err(),
            Error::UnexpectedDescriptorSize(1, 0)
        );

        // Set tx_buf len and rx_buf len different, which is invalid.
        let tx_rx_len_diff_descs = [
            Descriptor::new(
                trans_header_addr1,
                size_of::<VirtioSpiTransferHead>() as u32,
                VRING_DESC_F_NEXT as u16,
                0,
            ),
            Descriptor::new(tx_buf_addr1, 30, VRING_DESC_F_NEXT as u16, 0),
            Descriptor::new(
                rx_buf_addr1,
                20,
                (VRING_DESC_F_WRITE | VRING_DESC_F_NEXT) as u16,
                0,
            ),
            Descriptor::new(
                trans_result_addr1,
                size_of::<VirtioSpiTransferResult>() as u32,
                VRING_DESC_F_WRITE as u16,
                0,
            ),
        ];

        let (vring, mem) = setup_descs(&tx_rx_len_diff_descs);

        let out_hdr = VirtioSpiTransferHead {
            chip_select_id: 0,
            bits_per_word: 8,
            cs_change: 0,
            tx_nbits: 1,
            rx_nbits: 1,
            reserved1: 0,
            reserved2: 0,
            reserved3: 0,
            mode: From::from(0),
            freq: From::from(10000),
            word_delay_ns: From::from(0),
            cs_setup_ns: From::from(0),
            cs_delay_hold_ns: From::from(0),
            cs_change_delay_inactive_ns: From::from(0),
        };

        mem.memory()
            .write_obj(out_hdr, GuestAddress(trans_header_addr1))
            .expect("writing to succeed");

        backend.update_memory(mem.clone()).unwrap();
        assert_eq!(
            backend.process_queue(&vring).unwrap_err(),
            Error::TxRxTrnasLenNotEqual(30, 20)
        );

        // At lease one buf needed, either tx_buf or rx_buf.
        let no_buf_descs = [
            Descriptor::new(
                trans_header_addr1,
                size_of::<VirtioSpiTransferHead>() as u32,
                VRING_DESC_F_NEXT as u16,
                0,
            ),
            Descriptor::new(
                trans_result_addr1,
                size_of::<VirtioSpiTransferResult>() as u32,
                VRING_DESC_F_WRITE as u16,
                0,
            ),
        ];

        let (vring, mem) = setup_descs(&no_buf_descs);

        let out_hdr = VirtioSpiTransferHead {
            chip_select_id: 0,
            bits_per_word: 8,
            cs_change: 0,
            tx_nbits: 1,
            rx_nbits: 1,
            reserved1: 0,
            reserved2: 0,
            reserved3: 0,
            mode: From::from(0),
            freq: From::from(10000),
            word_delay_ns: From::from(0),
            cs_setup_ns: From::from(0),
            cs_delay_hold_ns: From::from(0),
            cs_change_delay_inactive_ns: From::from(0),
        };

        mem.memory()
            .write_obj(out_hdr, GuestAddress(trans_header_addr1))
            .expect("writing to succeed");

        backend.update_memory(mem.clone()).unwrap();
        assert_eq!(
            backend.process_queue(&vring).unwrap_err(),
            Error::TransZeroLength
        );

        // The address range is from 0 to 0x1000_1000, set head address out of range.
        let head_addr_invalid_descs = [
            Descriptor::new(
                0x2000_0000,
                size_of::<VirtioSpiTransferHead>() as u32,
                VRING_DESC_F_NEXT as u16,
                0,
            ),
            Descriptor::new(tx_buf_addr1, 30, VRING_DESC_F_NEXT as u16, 0),
            Descriptor::new(
                rx_buf_addr1,
                30,
                (VRING_DESC_F_WRITE | VRING_DESC_F_NEXT) as u16,
                0,
            ),
            Descriptor::new(
                trans_result_addr1,
                size_of::<VirtioSpiTransferResult>() as u32,
                VRING_DESC_F_WRITE as u16,
                0,
            ),
        ];

        let (vring, mem) = setup_descs(&head_addr_invalid_descs);

        backend.update_memory(mem.clone()).unwrap();
        assert_eq!(
            backend.process_queue(&vring).unwrap_err(),
            Error::DescriptorReadFailed
        );

        // The address range is from 0 to 0x1000_1000, set result address out of range.
        let result_addr_invalid_descs = [
            Descriptor::new(
                trans_header_addr1,
                size_of::<VirtioSpiTransferHead>() as u32,
                VRING_DESC_F_NEXT as u16,
                0,
            ),
            Descriptor::new(tx_buf_addr1, 30, VRING_DESC_F_NEXT as u16, 0),
            Descriptor::new(
                rx_buf_addr1,
                30,
                (VRING_DESC_F_WRITE | VRING_DESC_F_NEXT) as u16,
                0,
            ),
            Descriptor::new(
                0x2000_0000,
                size_of::<VirtioSpiTransferResult>() as u32,
                VRING_DESC_F_WRITE as u16,
                0,
            ),
        ];

        let (vring, mem) = setup_descs(&result_addr_invalid_descs);

        let out_hdr = VirtioSpiTransferHead {
            chip_select_id: 0,
            bits_per_word: 8,
            cs_change: 0,
            tx_nbits: 1,
            rx_nbits: 1,
            reserved1: 0,
            reserved2: 0,
            reserved3: 0,
            mode: From::from(0),
            freq: From::from(10000),
            word_delay_ns: From::from(0),
            cs_setup_ns: From::from(0),
            cs_delay_hold_ns: From::from(0),
            cs_change_delay_inactive_ns: From::from(0),
        };

        mem.memory()
            .write_obj(out_hdr, GuestAddress(trans_header_addr1))
            .expect("writing to succeed");

        backend.update_memory(mem.clone()).unwrap();
        assert_eq!(
            backend.process_queue(&vring).unwrap_err(),
            Error::DescriptorReadFailed
        );
    }

    #[test]
    fn verify_backend() {
        let spi_dummy_ctrl =
            SpiController::new(DummyDevice::open(&PathBuf::from("spidev0.0")).unwrap()).unwrap();
        let mut backend = VhostUserSpiBackend::new(Arc::new(spi_dummy_ctrl)).unwrap();

        assert_eq!(backend.num_queues(), NUM_QUEUES);
        assert_eq!(backend.max_queue_size(), QUEUE_SIZE);
        assert_eq!(backend.features(), 0x171000000);
        assert_eq!(
            backend.protocol_features(),
            (VhostUserProtocolFeatures::MQ
                | VhostUserProtocolFeatures::CONFIG
                | VhostUserProtocolFeatures::REPLY_ACK)
        );

        assert_eq!(backend.queues_per_thread(), vec![0xffff_ffff]);

        let dummy_config = VirtioSpiConfig {
            cs_max_number: 1,
            cs_change_supported: 1,
            tx_nbits_supported: 0,
            rx_nbits_supported: 0,
            bits_per_word_mask: 0.into(),
            mode_func_supported: 0xf.into(),
            max_freq_hz: 10000.into(),
            max_word_delay_ns: 0.into(),
            max_cs_setup_ns: 0.into(),
            max_cs_hold_ns: 0.into(),
            max_cs_inactive_ns: 0.into(),
        };

        assert_eq!(
            backend.get_config(0, size_of::<VirtioSpiConfig>() as u32),
            // SAFETY: The layout of the structure is fixed and can be initialized by
            // reading its content from byte array.
            unsafe {
                from_raw_parts(
                    &dummy_config as *const _ as *const _,
                    size_of::<VirtioSpiConfig>(),
                )
                .to_vec()
            }
        );

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
