// SPDX-License-Identifier: Apache-2.0 or BSD-3-Clause

use std::convert::TryFrom;
use std::io::{self, ErrorKind};

use log::{debug, error, info, warn};
use vhost::vhost_user::{VhostUserProtocolFeatures, VhostUserVirtioFeatures};
use vhost_user_backend::{VhostUserBackendMut, VringRwLock, VringT};
use virtio_bindings::{
    virtio_config::VIRTIO_F_VERSION_1,
    virtio_ring::{VIRTIO_RING_F_EVENT_IDX, VIRTIO_RING_F_INDIRECT_DESC},
    virtio_scsi::VIRTIO_SCSI_F_HOTPLUG,
};
use virtio_queue::QueueOwnedT;
use vm_memory::{GuestAddressSpace, GuestMemoryAtomic, GuestMemoryLoadGuard, GuestMemoryMmap};
use vmm_sys_util::{
    epoll::EventSet,
    eventfd::{EventFd, EFD_NONBLOCK},
};

use crate::scsi::Target;
use crate::{
    scsi::{self, CmdError, TaskAttr},
    virtio::{self, Request, RequestParseError, Response, ResponseCode, VirtioScsiLun, SENSE_SIZE},
};

const REQUEST_QUEUE: u16 = 2;

type DescriptorChainWriter = virtio::DescriptorChainWriter<GuestMemoryLoadGuard<GuestMemoryMmap>>;
type DescriptorChainReader = virtio::DescriptorChainReader<GuestMemoryLoadGuard<GuestMemoryMmap>>;

pub(crate) struct VhostUserScsiBackend {
    event_idx: bool,
    mem: Option<GuestMemoryAtomic<GuestMemoryMmap>>,
    targets: Vec<Box<dyn Target>>,
    pub(crate) exit_event: EventFd,
}

impl VhostUserScsiBackend {
    pub(crate) fn new() -> Self {
        Self {
            event_idx: false,
            mem: None,
            targets: Vec::new(),
            exit_event: EventFd::new(EFD_NONBLOCK).expect("Creating exit eventfd"),
        }
    }

    fn parse_target(&mut self, lun: VirtioScsiLun) -> Option<(&mut Box<dyn Target>, u16)> {
        match lun {
            VirtioScsiLun::TargetLun(target, lun) => self
                .targets
                .get_mut(usize::from(target))
                .map(|tgt| (tgt, lun)),
            VirtioScsiLun::ReportLuns => {
                // TODO: do we need to handle the REPORT LUNS well-known LUN?
                // In practice, everyone seems to just use LUN 0
                warn!("Guest is trying to use the REPORT LUNS well-known LUN, which we don't support.");
                None
            }
        }
    }

    fn process_requests(
        &mut self,
        reader: &mut DescriptorChainReader,
        writer: &mut DescriptorChainWriter,
    ) {
        let mut body_writer = writer.clone();
        const RESPONSE_HEADER_SIZE: u32 = 12;
        body_writer.skip(
            RESPONSE_HEADER_SIZE + u32::try_from(SENSE_SIZE).expect("SENSE_SIZE should fit 32bit"),
        );

        let response = match Request::parse(reader) {
            Ok(r) => {
                if let Some((target, lun)) = self.parse_target(r.lun) {
                    let output = target.execute_command(
                        lun,
                        reader,
                        &mut body_writer,
                        scsi::Request {
                            id: r.id,
                            cdb: &r.cdb,
                            task_attr: match r.task_attr {
                                0 => TaskAttr::Simple,
                                1 => TaskAttr::Ordered,
                                2 => TaskAttr::HeadOfQueue,
                                3 => TaskAttr::Aca,
                                _ => {
                                    // virtio-scsi spec allows us to map any task attr to simple, presumably
                                    // including future ones
                                    warn!("Unknown task attr: {}", r.task_attr);
                                    TaskAttr::Simple
                                }
                            },
                            crn: r.crn,
                            prio: r.prio,
                        },
                    );

                    match output {
                        Ok(output) => {
                            assert!(output.sense.len() < SENSE_SIZE);

                            Response {
                                response: ResponseCode::Ok,
                                status: output.status,
                                status_qualifier: output.status_qualifier,
                                sense: output.sense,
                                // TODO: handle residual for data in
                                residual: body_writer.residual(),
                            }
                        }
                        Err(CmdError::CdbTooShort) => {
                            // the CDB buffer is, by default, sized larger than any CDB we support; we don't
                            // handle writes to config space (because QEMU doesn't let us), so there's no
                            // way the guest can set it too small
                            unreachable!();
                        }
                        Err(CmdError::DataIn(e)) => {
                            if e.kind() == ErrorKind::WriteZero {
                                Response::error(ResponseCode::Overrun, 0)
                            } else {
                                error!("Error writing response to guest memory: {}", e);

                                // There's some chance the header and data in are on different descriptors,
                                // and only the data in descriptor is bad, so let's at least try to write an
                                // error to the header
                                Response::error(ResponseCode::Failure, body_writer.residual())
                            }
                        }
                    }
                } else {
                    debug!("Rejecting command to LUN with bad target {:?}", r.lun);
                    Response::error(ResponseCode::BadTarget, body_writer.residual())
                }
            }
            Err(RequestParseError::CouldNotReadGuestMemory(e)) => {
                // See comment later about errors while writing to guest mem; maybe we at least
                // got functional write desciptors, so we can report an error
                error!("Error reading request from guest memory: {:?}", e);
                Response::error(ResponseCode::Failure, body_writer.residual())
            }
            Err(RequestParseError::FailedParsingLun(lun)) => {
                error!("Unable to parse LUN: {:?}", lun);
                Response::error(ResponseCode::Failure, body_writer.residual())
            }
        };

        if let Err(e) = response.write(writer) {
            // Alright, so something went wrong writing our response header to guest memory.
            // The only reason this should ever happen, I think, is if the guest gave us a
            // virtio descriptor with an invalid address.

            // There's not a great way to recover from this - we just discovered that
            // our only way of communicating with the guest doesn't work - so we either
            // silently fail or crash. There isn't too much sense in crashing, IMO, as
            // the guest could still recover by, say, installing a fixed kernel and
            // rebooting. So let's just log an error and do nothing.
            error!("Error writing response to guest memory: {:?}", e);
        }
    }

    fn process_request_queue(&mut self, vring: &VringRwLock) -> Result<(), io::Error> {
        let chains: Vec<_> = vring
            .get_mut()
            .get_queue_mut()
            .iter(self.mem.as_ref().unwrap().memory())
            .map_err(|e| io::Error::new(ErrorKind::Other, e))?
            .collect();
        for dc in chains {
            let mut writer = DescriptorChainWriter::new(dc.clone());
            let mut reader = DescriptorChainReader::new(dc.clone());

            self.process_requests(&mut reader, &mut writer);

            vring
                .add_used(dc.head_index(), writer.max_written())
                .map_err(|e| io::Error::new(ErrorKind::Other, e))?;
        }

        vring
            .signal_used_queue()
            .map_err(|e| io::Error::new(ErrorKind::Other, e))?;
        Ok(())
    }

    pub(crate) fn add_target(&mut self, target: Box<dyn Target>) {
        self.targets.push(target);
    }
}

impl VhostUserBackendMut<VringRwLock> for VhostUserScsiBackend {
    fn num_queues(&self) -> usize {
        // control + event + request queues
        let num_request_queues = 1;
        2 + num_request_queues
    }

    fn max_queue_size(&self) -> usize {
        128 // qemu assumes this by default
    }

    fn features(&self) -> u64 {
        1 << VIRTIO_F_VERSION_1
            | 1 << VIRTIO_SCSI_F_HOTPLUG
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
        atomic_mem: GuestMemoryAtomic<GuestMemoryMmap>,
    ) -> std::result::Result<(), std::io::Error> {
        info!("Memory updated - guest probably booting");
        self.mem = Some(atomic_mem);
        Ok(())
    }

    fn handle_event(
        &mut self,
        device_event: u16,
        evset: EventSet,
        vrings: &[VringRwLock],
        thread_id: usize,
    ) -> io::Result<bool> {
        assert!(evset == EventSet::IN);
        assert!(vrings.len() == 3);
        assert!((device_event as usize) < vrings.len());
        assert!(thread_id == 0);

        let vring = &vrings[device_event as usize];
        match device_event {
            REQUEST_QUEUE => {
                if self.event_idx {
                    // vm-virtio's Queue implementation only checks avail_index
                    // once, so to properly support EVENT_IDX we need to keep
                    // calling process_request_queue() until it stops finding
                    // new requests on the queue.
                    loop {
                        vring.disable_notification().unwrap();
                        self.process_request_queue(vring)?;
                        if !vring.enable_notification().unwrap() {
                            break;
                        }
                    }
                } else {
                    // Without EVENT_IDX, a single call is enough.
                    self.process_request_queue(vring)?;
                }
            }
            _ => {
                error!("Ignoring descriptor on queue {}", device_event);
            }
        }

        Ok(false)
    }

    fn get_config(&self, _offset: u32, _size: u32) -> Vec<u8> {
        // QEMU handles config space itself
        panic!("Access to configuration space is not supported.");
    }

    fn set_config(&mut self, _offset: u32, _buf: &[u8]) -> std::result::Result<(), std::io::Error> {
        // QEMU handles config space itself
        panic!("Access to configuration space is not supported.");
    }

    fn exit_event(&self, _thread_index: usize) -> Option<EventFd> {
        Some(self.exit_event.try_clone().expect("Cloning exit eventfd"))
    }
}
