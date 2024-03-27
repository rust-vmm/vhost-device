// vhost device spi
//
// Copyright (c) 2024 Qualcomm Innovation Center, Inc. All rights reserved.
//          Haixu Cui <quic_haixcui@quicinc.com>
//
// SPDX-License-Identifier: Apache-2.0 or BSD-3-Clause

use log::warn;
use std::mem::size_of;
use std::slice::from_raw_parts;
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
    Le32,
};
use vmm_sys_util::epoll::EventSet;
use vmm_sys_util::eventfd::{EventFd, EFD_NONBLOCK};

use crate::spi::*;

const QUEUE_SIZE: usize = 1024;
const NUM_QUEUES: usize = 1;

type Result<T> = std::result::Result<T, Error>;

#[derive(Copy, Clone, Debug, Eq, PartialEq, ThisError)]
/// Errors related to vhost-device-spi daemon.
pub(crate) enum Error {
    #[error("TX length  {0} and RX length {1} don't match")]
    TxRxTrnasLenNotEqual(u32, u32),
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
    #[error("Tx buf and Rx buf mismatch in descriptor")]
    TxRxBufOrderMismatch,
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
        io::Error::new(io::ErrorKind::Other, e)
    }
}

/// The final status written by the device
const VIRTIO_SPI_TRANS_OK: u8 = 0;
const VIRTIO_SPI_PARAM_ERR: u8 = 1;
const VIRTIO_SPI_TRANS_ERR: u8 = 2;

#[derive(Copy, Clone, Default)]
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

pub(crate) struct VhostUserSpiBackend<D: SpiDevice> {
    spi_ctrl: Arc<SpiController<D>>,
    event_idx: bool,
    pub exit_event: EventFd,
    mem: Option<GuestMemoryLoadGuard<GuestMemoryMmap>>,
}

type SpiDescriptorChain = DescriptorChain<GuestMemoryLoadGuard<GuestMemoryMmap<()>>>;

impl<D: SpiDevice> VhostUserSpiBackend<D> {
    pub fn new(spi_ctrl: Arc<SpiController<D>>) -> Result<Self> {
        Ok(VhostUserSpiBackend {
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

        if requests.is_empty() {
            return Ok(true);
        }

        // Iterate over each SPI request and push it to "reqs" vector.
        for desc_chain in requests.clone() {
            let descriptors: Vec<_> = desc_chain.clone().collect();

            if (descriptors.len() != 3) && (descriptors.len() != 4) {
                return Err(Error::UnexpectedDescriptorCount(descriptors.len()));
            }

            if descriptors.len() == 4
                && (descriptors[1].is_write_only() || !descriptors[2].is_write_only())
            {
                return Err(Error::TxRxBufOrderMismatch);
            }

            let desc_out_hdr = descriptors[0];

            if desc_out_hdr.is_write_only() {
                return Err(Error::UnexpectedWriteOnlyDescriptor(0));
            }

            if desc_out_hdr.len() as usize != size_of::<VirtioSpiTransferHead>() {
                return Err(Error::UnexpectedDescriptorSize(
                    size_of::<VirtioSpiTransferHead>(),
                    desc_out_hdr.len(),
                ));
            }

            let out_hdr = desc_chain
                .memory()
                .read_obj::<VirtioSpiTransferHead>(desc_out_hdr.addr())
                .map_err(|_| Error::DescriptorReadFailed)?;

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

            let mut tx_buf: Vec<u8>;
            let mut rx_buf: Vec<u8>;
            let trans_len: u32;

            (tx_buf, rx_buf, trans_len) = match descriptors.len() {
                3 => {
                    // half-duplex transfer
                    let desc_buf = descriptors[1];
                    let len = desc_buf.len();

                    if len == 0 {
                        return Err(Error::UnexpectedDescriptorSize(1, len));
                    }

                    if desc_buf.is_write_only() {
                        rx_buf = vec![0; len as usize];
                        tx_buf = Vec::<u8>::new();
                    } else {
                        tx_buf = vec![0; len as usize];

                        desc_chain
                            .memory()
                            .read(&mut tx_buf, desc_buf.addr())
                            .map_err(|_| Error::DescriptorReadFailed)?;

                        rx_buf = Vec::<u8>::new();
                    }

                    (tx_buf, rx_buf, len)
                }

                4 => {
                    // full-duplex transfer
                    let tx_desc_buf = descriptors[1];
                    let rx_desc_buf = descriptors[2];

                    let tx_len = tx_desc_buf.len();
                    let rx_len = rx_desc_buf.len();

                    if tx_len == 0 {
                        return Err(Error::UnexpectedDescriptorSize(1, tx_len));
                    }

                    if rx_len == 0 {
                        return Err(Error::UnexpectedDescriptorSize(1, rx_len));
                    }

                    if tx_len != rx_len {
                        return Err(Error::TxRxTrnasLenNotEqual(tx_len, rx_len));
                    }

                    rx_buf = vec![0; rx_len as usize];
                    tx_buf = vec![0; tx_len as usize];

                    desc_chain
                        .memory()
                        .read(&mut tx_buf, tx_desc_buf.addr())
                        .map_err(|_| Error::DescriptorReadFailed)?;

                    (tx_buf, rx_buf, tx_len)
                }

                _ => {
                    return Err(Error::UnexpectedDescriptorCount(descriptors.len()));
                }
            };

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

        let in_hdr = match self.spi_ctrl.check_trans_params(&mut reqs[0]) {
            true => VirtioSpiTransferResult {
                status: match self.spi_ctrl.transfer(&mut reqs) {
                    Ok(()) => VIRTIO_SPI_TRANS_OK,
                    Err(_) => VIRTIO_SPI_TRANS_ERR,
                },
            },
            _ => VirtioSpiTransferResult {
                status: VIRTIO_SPI_PARAM_ERR,
            },
        };

        for (i, desc_chain) in requests.iter().enumerate() {
            let descriptors: Vec<_> = desc_chain.clone().collect();
            let desc_in_hdr = descriptors[descriptors.len() - 1];
            let mut len = size_of::<VirtioSpiTransferResult>() as u32;

            if descriptors.len() == 3 {
                let desc_buf = descriptors[1];

                if desc_buf.is_write_only() {
                    desc_chain
                        .memory()
                        .write(&reqs[i].rx_buf, desc_buf.addr())
                        .map_err(|_| Error::DescriptorWriteFailed)?;

                    if in_hdr.status == VIRTIO_SPI_TRANS_OK {
                        len += desc_buf.len();
                    }
                }
            }

            if descriptors.len() == 4 {
                let desc_buf = descriptors[2];

                desc_chain
                    .memory()
                    .write(&reqs[i].rx_buf, desc_buf.addr())
                    .map_err(|_| Error::DescriptorWriteFailed)?;

                if in_hdr.status == VIRTIO_SPI_TRANS_OK {
                    len += desc_buf.len();
                }
            }

            // Write the transfer status
            desc_chain
                .memory()
                .write_obj::<VirtioSpiTransferResult>(in_hdr, desc_in_hdr.addr())
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
        dbg!(self.event_idx = enabled);
    }

    fn update_memory(&mut self, mem: GuestMemoryAtomic<GuestMemoryMmap>) -> IoResult<()> {
        self.mem = Some(mem.memory());
        Ok(())
    }

    fn get_config(&self, offset: u32, size: u32) -> Vec<u8> {
        // SAFETY: The layout of the structure is fixed and can be initialized by
        // reading its content from byte array.
        unsafe {
            from_raw_parts(
                self.spi_ctrl
                    .config()
                    .as_slice()
                    .as_ptr()
                    .offset(offset as isize) as *const _ as *const _,
                size as usize,
            )
            .to_vec()
        }
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
    use crate::spi::tests::{update_rdwr_buf, verify_rdwr_buf, DummyDevice};

    // Prepares a single chain of descriptors
    fn prepare_desc_chain(
        start_addr: GuestAddress,
        tx_buf: &mut Vec<u8>,
        rx_buf: &mut Vec<u8>,
        chip_select_id: u8,
        bits_per_word: u8,
        cs_change: u8,
        tx_nbits: u8,
        rx_nbits: u8,
        mode: u32,
        freq: u32,
    ) -> SpiDescriptorChain {
        let mem = &GuestMemoryMmap::<()>::from_ranges(&[(start_addr, 0x1000)]).unwrap();
        let vq = MockSplitQueue::new(mem, 16);
        let mut next_addr = vq.desc_table().total_size() + 0x100;
        let mut index = 0;

        // Out header descriptor
        let out_hdr = VirtioSpiTransferHead {
            chip_select_id,
            bits_per_word,
            cs_change,
            tx_nbits,
            rx_nbits,
            reserved1: 0,
            reserved2: 0,
            reserved3: 0,
            mode: From::from(mode),
            freq: From::from(freq),
            word_delay_ns: From::from(0),
            cs_setup_ns: From::from(0),
            cs_delay_hold_ns: From::from(0),
            cs_change_delay_inactive_ns: From::from(0),
        };

        let desc_out = Descriptor::new(
            next_addr,
            size_of::<VirtioSpiTransferHead>() as u32,
            VRING_DESC_F_NEXT as u16,
            index + 1,
        );

        mem.write_obj::<VirtioSpiTransferHead>(out_hdr, desc_out.addr())
            .unwrap();
        vq.desc_table().store(index, desc_out).unwrap();
        next_addr += desc_out.len() as u64;
        index += 1;

        // TX buf descriptor: optional
        if !tx_buf.is_empty() {
            update_rdwr_buf(tx_buf);

            let desc_tx_buf = Descriptor::new(
                next_addr,
                tx_buf.len() as u32,
                (VRING_DESC_F_NEXT) as u16,
                index + 1,
            );
            mem.write(tx_buf, desc_tx_buf.addr()).unwrap();
            vq.desc_table().store(index, desc_tx_buf).unwrap();
            next_addr += desc_tx_buf.len() as u64;
            index += 1;
        }

        // RX buf descriptor: optional
        if !rx_buf.is_empty() {
            let desc_rx_buf = Descriptor::new(
                next_addr,
                rx_buf.len() as u32,
                (VRING_DESC_F_WRITE | VRING_DESC_F_NEXT) as u16,
                index + 1,
            );
            mem.write(rx_buf, desc_rx_buf.addr()).unwrap();
            vq.desc_table().store(index, desc_rx_buf).unwrap();
            next_addr += desc_rx_buf.len() as u64;
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
    fn validate_desc_chains(desc_chains: Vec<SpiDescriptorChain>, status: u8) {
        for desc_chain in desc_chains {
            let descriptors: Vec<_> = desc_chain.clone().collect();

            let in_hdr = desc_chain
                .memory()
                .read_obj::<VirtioSpiTransferResult>(descriptors[descriptors.len() - 1].addr())
                .unwrap();

            // Operation result should match expected status.
            assert_eq!(in_hdr.status, status);

            if descriptors.len() == 3 && descriptors[1].is_write_only() {
                let mut buf = vec![0; descriptors[1].len() as usize];
                desc_chain
                    .memory()
                    .read(&mut buf, descriptors[1].addr())
                    .unwrap();

                // Verify the content of the read-buffer
                verify_rdwr_buf(&buf);
            }

            if descriptors.len() == 4 {
                let mut buf = vec![0; descriptors[2].len() as usize];
                desc_chain
                    .memory()
                    .read(&mut buf, descriptors[2].addr())
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
    ) -> SpiDescriptorChain {
        let mem = &GuestMemoryMmap::<()>::from_ranges(&[(GuestAddress(0), 0x1000)]).unwrap();
        let vq = MockSplitQueue::new(mem, 16);

        for (i, flag) in flags.iter().enumerate() {
            let mut f: u16 = if i == flags.len() - 1 {
                0
            } else {
                VRING_DESC_F_NEXT as u16
            };
            f |= flag;

            let offset = match addr {
                Some(ref addr) => addr[i],
                _ => 0x100,
            };

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
        let spi_dummy_ctrl = SpiController::new(DummyDevice::open("spidev0.0").unwrap()).unwrap();
        let backend = VhostUserSpiBackend::new(Arc::new(spi_dummy_ctrl)).unwrap();
        let mem = GuestMemoryAtomic::new(
            GuestMemoryMmap::<()>::from_ranges(&[(GuestAddress(0), 0x1000)]).unwrap(),
        );
        let vring = VringRwLock::new(mem, 0x1000).unwrap();

        // Descriptor chain size zero, shouldn't fail
        backend
            .process_requests(Vec::<SpiDescriptorChain>::new(), &vring)
            .unwrap();

        // Valid single read descriptor
        let mut tx_buf: Vec<u8> = Vec::<u8>::new();
        let mut rx_buf: Vec<u8> = vec![0; 30];
        let desc_chain = prepare_desc_chain(
            GuestAddress(0),
            &mut tx_buf,
            &mut rx_buf,
            0,
            8,
            0,
            1,
            1,
            0,
            10000,
        );
        let desc_chains = vec![desc_chain];

        backend
            .process_requests(desc_chains.clone(), &vring)
            .unwrap();
        validate_desc_chains(desc_chains, VIRTIO_SPI_TRANS_OK);

        // Valid single write descriptor
        let mut tx_buf: Vec<u8> = vec![0; 30];
        let mut rx_buf: Vec<u8> = Vec::<u8>::new();
        let desc_chain = prepare_desc_chain(
            GuestAddress(0),
            &mut tx_buf,
            &mut rx_buf,
            0,
            8,
            0,
            1,
            1,
            0,
            10000,
        );
        let desc_chains = vec![desc_chain];

        backend
            .process_requests(desc_chains.clone(), &vring)
            .unwrap();
        validate_desc_chains(desc_chains, VIRTIO_SPI_TRANS_OK);

        // Valid mixed read-write descriptors
        let mut tx_buf: Vec<u8> = vec![0; 30];
        let mut rx_buf: Vec<u8> = vec![0; 30];
        let mut null_buf: Vec<u8> = Vec::<u8>::new();

        let desc_chains = vec![
            // Write
            prepare_desc_chain(
                GuestAddress(0),
                &mut tx_buf,
                &mut null_buf,
                0,
                8,
                0,
                1,
                1,
                0,
                10000,
            ),
            // Read
            prepare_desc_chain(
                GuestAddress(0),
                &mut null_buf,
                &mut rx_buf,
                0,
                8,
                0,
                1,
                1,
                0,
                10000,
            ),
            // Write+Read
            prepare_desc_chain(
                GuestAddress(0),
                &mut tx_buf,
                &mut rx_buf,
                0,
                8,
                0,
                1,
                1,
                0,
                10000,
            ),
            // Write
            prepare_desc_chain(
                GuestAddress(0),
                &mut tx_buf,
                &mut null_buf,
                0,
                8,
                0,
                1,
                1,
                0,
                10000,
            ),
            // Read
            prepare_desc_chain(
                GuestAddress(0),
                &mut null_buf,
                &mut rx_buf,
                0,
                8,
                0,
                1,
                1,
                0,
                10000,
            ),
            // Write+Read
            prepare_desc_chain(
                GuestAddress(0),
                &mut tx_buf,
                &mut rx_buf,
                0,
                8,
                0,
                1,
                1,
                0,
                10000,
            ),
        ];

        backend
            .process_requests(desc_chains.clone(), &vring)
            .unwrap();
        validate_desc_chains(desc_chains, VIRTIO_SPI_TRANS_OK);

        // unsupported LOOP mode, should filter by parameter check
        let mut tx_buf: Vec<u8> = vec![0; 30];
        let mut rx_buf: Vec<u8> = Vec::<u8>::new();
        let desc_chain = prepare_desc_chain(
            GuestAddress(0),
            &mut tx_buf,
            &mut rx_buf,
            0,
            8,
            0,
            1,
            1,
            0x10,
            10000,
        );
        let desc_chains = vec![desc_chain];

        backend
            .process_requests(desc_chains.clone(), &vring)
            .unwrap();
        validate_desc_chains(desc_chains, VIRTIO_SPI_PARAM_ERR);
    }

    #[test]
    fn process_requests_failure() {
        let spi_dummy_ctrl = SpiController::new(DummyDevice::open("spidev0.0").unwrap()).unwrap();
        let backend = VhostUserSpiBackend::new(Arc::new(spi_dummy_ctrl)).unwrap();
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

        // Five descriptors
        let flags: Vec<u16> = vec![0, 0, 0, 0, 0];
        let len: Vec<u32> = vec![0, 0, 0, 0, 0];
        let desc_chain = prepare_desc_chain_dummy(None, flags, len);
        assert_eq!(
            backend
                .process_requests(vec![desc_chain], &vring)
                .unwrap_err(),
            Error::UnexpectedDescriptorCount(5)
        );

        // Write only out hdr
        let flags: Vec<u16> = vec![VRING_DESC_F_WRITE as u16, 0, VRING_DESC_F_WRITE as u16];
        let len: Vec<u32> = vec![
            size_of::<VirtioSpiTransferHead>() as u32,
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
            Error::UnexpectedDescriptorSize(size_of::<VirtioSpiTransferHead>(), 100)
        );

        // Invalid out hdr address
        let addr: Vec<u64> = vec![0x10000, 0, 0];
        let flags: Vec<u16> = vec![0, 0, VRING_DESC_F_WRITE as u16];
        let len: Vec<u32> = vec![
            size_of::<VirtioSpiTransferHead>() as u32,
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
            size_of::<VirtioSpiTransferHead>() as u32,
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
        let len: Vec<u32> = vec![size_of::<VirtioSpiTransferHead>() as u32, 1, 100];
        let desc_chain = prepare_desc_chain_dummy(None, flags, len);
        assert_eq!(
            backend
                .process_requests(vec![desc_chain], &vring)
                .unwrap_err(),
            Error::UnexpectedDescriptorSize(size_of::<u8>(), 100)
        );

        // Invalid in hdr address
        let addr: Vec<u64> = vec![0, 0, 0x10000];
        let flags: Vec<u16> = vec![0, VRING_DESC_F_WRITE as u16, VRING_DESC_F_WRITE as u16];
        let len: Vec<u32> = vec![
            size_of::<VirtioSpiTransferHead>() as u32,
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
            size_of::<VirtioSpiTransferHead>() as u32,
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

        // Different tx length and rx length
        let flags: Vec<u16> = vec![0, 0, VRING_DESC_F_WRITE as u16, VRING_DESC_F_WRITE as u16];
        let len: Vec<u32> = vec![
            size_of::<VirtioSpiTransferHead>() as u32,
            1,
            2,
            size_of::<u8>() as u32,
        ];
        let desc_chain = prepare_desc_chain_dummy(None, flags, len);
        assert_eq!(
            backend
                .process_requests(vec![desc_chain], &vring)
                .unwrap_err(),
            Error::TxRxTrnasLenNotEqual(1, 2)
        );

        // Invalid buf address
        let addr: Vec<u64> = vec![0, 0x10000, 0];
        let flags: Vec<u16> = vec![0, 0, VRING_DESC_F_WRITE as u16];
        let len: Vec<u32> = vec![
            size_of::<VirtioSpiTransferHead>() as u32,
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

        // tx buffer and rx buffer order mismatch
        let flags: Vec<u16> = vec![0, VRING_DESC_F_WRITE as u16, 0, VRING_DESC_F_WRITE as u16];
        let len: Vec<u32> = vec![
            size_of::<VirtioSpiTransferHead>() as u32,
            10,
            10,
            size_of::<u8>() as u32,
        ];
        let desc_chain = prepare_desc_chain_dummy(None, flags, len);
        assert_eq!(
            backend
                .process_requests(vec![desc_chain], &vring)
                .unwrap_err(),
            Error::TxRxBufOrderMismatch
        );
    }

    #[test]
    fn verify_backend() {
        let spi_dummy_ctrl = SpiController::new(DummyDevice::open("spidev0.0").unwrap()).unwrap();
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
