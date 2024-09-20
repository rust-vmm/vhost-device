// SPDX-License-Identifier: Apache-2.0 or BSD-3-Clause

use core::slice;
use std::convert::{TryFrom, TryInto};
use std::io::{self, ErrorKind};
use std::mem;

use log::{debug, error, info, warn};
use vhost::vhost_user::{VhostUserProtocolFeatures, VhostUserVirtioFeatures};
use vhost_user_backend::{VhostUserBackendMut, VringRwLock, VringT};
use virtio_bindings::virtio_scsi::{virtio_scsi_config, virtio_scsi_event};
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
use crate::virtio::CDB_SIZE;
use crate::{
    scsi::{self, CmdError, TaskAttr},
    virtio::{self, Request, RequestParseError, Response, ResponseCode, VirtioScsiLun, SENSE_SIZE},
};

const REQUEST_QUEUE: u16 = 2;

type DescriptorChainWriter = virtio::DescriptorChainWriter<GuestMemoryLoadGuard<GuestMemoryMmap>>;
type DescriptorChainReader = virtio::DescriptorChainReader<GuestMemoryLoadGuard<GuestMemoryMmap>>;

pub struct VhostUserScsiBackend {
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

impl VhostUserBackendMut for VhostUserScsiBackend {
    type Vring = VringRwLock;
    type Bitmap = ();

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
        VhostUserProtocolFeatures::MQ | VhostUserProtocolFeatures::CONFIG
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
    ) -> io::Result<()> {
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

        Ok(())
    }

    fn get_config(&self, offset: u32, size: u32) -> Vec<u8> {
        let config = virtio_scsi_config {
            num_queues: 1,
            seg_max: 128 - 2,
            max_sectors: 0xFFFF,
            cmd_per_lun: 128,
            event_info_size: mem::size_of::<virtio_scsi_event>()
                .try_into()
                .expect("event info size should fit 32bit"),
            sense_size: SENSE_SIZE.try_into().expect("SENSE_SIZE should fit 32bit"),
            cdb_size: CDB_SIZE.try_into().expect("CDB_SIZE should fit 32bit"),
            max_channel: 0,
            max_target: 255,
            max_lun: u32::from(!u16::from(VirtioScsiLun::ADDRESS_METHOD_PATTERN) << 8 | 0xff),
        };

        // SAFETY:
        // Pointer is aligned (points to start of struct), valid and we only
        // access up to the size of the struct.
        let config_slice = unsafe {
            slice::from_raw_parts(
                (&config as *const virtio_scsi_config).cast::<u8>(),
                mem::size_of::<virtio_scsi_config>(),
            )
        };

        config_slice
            .iter()
            .skip(offset as usize)
            .take(size as usize)
            .cloned()
            .collect()
    }

    fn set_config(&mut self, _offset: u32, _buf: &[u8]) -> std::result::Result<(), std::io::Error> {
        // QEMU handles config space itself
        panic!("Access to configuration space is not supported.");
    }

    fn exit_event(&self, _thread_index: usize) -> Option<EventFd> {
        Some(self.exit_event.try_clone().expect("Cloning exit eventfd"))
    }
}

#[cfg(test)]
mod tests {
    use std::{
        convert::TryInto,
        io::{self, Read, Write},
        sync::{Arc, Mutex},
    };

    use vhost_user_backend::{VhostUserBackendMut, VringRwLock, VringT};
    use virtio_bindings::{
        virtio_ring::VRING_DESC_F_WRITE,
        virtio_scsi::{
            virtio_scsi_cmd_req, virtio_scsi_config, VIRTIO_SCSI_S_BAD_TARGET,
            VIRTIO_SCSI_S_FAILURE, VIRTIO_SCSI_S_OK,
        },
    };
    use virtio_queue::{mock::MockSplitQueue, Descriptor};
    use vm_memory::{
        ByteValued, Bytes, GuestAddress, GuestAddressSpace, GuestMemoryAtomic, GuestMemoryMmap,
    };

    use super::VhostUserScsiBackend;
    use crate::{
        scsi::{CmdOutput, Target, TaskAttr},
        virtio::{
            tests::{VirtioScsiCmdReq, VirtioScsiCmdResp},
            VirtioScsiLun, CDB_SIZE,
        },
    };

    #[allow(dead_code)]
    struct RecordedCommand {
        lun: u16,
        id: u64,
        cdb: [u8; CDB_SIZE],
        task_attr: TaskAttr,
        crn: u8,
        prio: u8,
    }

    struct FakeTargetCommandCollector {
        received_commands: Vec<RecordedCommand>,
    }

    impl FakeTargetCommandCollector {
        fn new() -> Arc<Mutex<Self>> {
            Arc::new(Mutex::new(Self {
                received_commands: vec![],
            }))
        }
    }

    type FakeResponse = Result<crate::scsi::CmdOutput, crate::scsi::CmdError>;

    struct FakeTarget<Cb> {
        collector: Arc<Mutex<FakeTargetCommandCollector>>,
        callback: Cb,
    }

    impl<Cb> FakeTarget<Cb> {
        fn new(collector: Arc<Mutex<FakeTargetCommandCollector>>, callback: Cb) -> Self
        where
            Cb: FnMut(u16, crate::scsi::Request) -> FakeResponse + Sync + Send,
        {
            Self {
                collector,
                callback,
            }
        }
    }

    impl<Cb> Target for FakeTarget<Cb>
    where
        Cb: FnMut(u16, crate::scsi::Request) -> FakeResponse + Sync + Send,
    {
        fn execute_command(
            &mut self,
            lun: u16,
            _data_out: &mut dyn Read,
            _data_in: &mut dyn Write,
            req: crate::scsi::Request,
        ) -> Result<crate::scsi::CmdOutput, crate::scsi::CmdError> {
            let mut collector = self.collector.lock().unwrap();
            collector.received_commands.push(RecordedCommand {
                lun,
                id: req.id,
                cdb: req.cdb.try_into().unwrap(),
                task_attr: req.task_attr,
                crn: req.crn,
                prio: req.prio,
            });
            (self.callback)(lun, req)
        }
    }

    fn setup(
        req: impl ByteValued,
    ) -> (
        VhostUserScsiBackend,
        VringRwLock,
        GuestMemoryAtomic<GuestMemoryMmap>,
    ) {
        let mem = GuestMemoryAtomic::new(
            GuestMemoryMmap::<()>::from_ranges(&[(GuestAddress(0), 0x1000_0000)]).unwrap(),
        );
        // The `build_desc_chain` function will populate the `NEXT` related flags and field.
        let v = vec![
            Descriptor::new(0x10_0000, 0x100, 0, 0), // request
            Descriptor::new(0x20_0000, 0x100, VRING_DESC_F_WRITE as u16, 0), // response
        ];

        mem.memory()
            .write_obj(req, GuestAddress(0x10_0000))
            .expect("writing to succeed");

        let mem_handle = mem.memory();

        let queue = MockSplitQueue::new(&*mem_handle, 16);
        // queue.set_avail_idx(1);

        queue.build_desc_chain(&v).unwrap();

        // Put the descriptor index 0 in the first available ring position.
        mem.memory()
            .write_obj(0u16, queue.avail_addr().unchecked_add(4))
            .unwrap();

        // Set `avail_idx` to 1.
        mem.memory()
            .write_obj(1u16, queue.avail_addr().unchecked_add(2))
            .unwrap();

        let vring = VringRwLock::new(mem.clone(), 16).unwrap();

        // vring.set_queue_info(0x10_0000, 0x10_0000, 0x300).unwrap();
        vring.set_queue_size(16);
        vring
            .set_queue_info(
                queue.desc_table_addr().0,
                queue.avail_addr().0,
                queue.used_addr().0,
            )
            .unwrap();
        vring.set_queue_ready(true);

        let mut backend = VhostUserScsiBackend::new();
        backend.update_memory(mem.clone()).unwrap();

        (backend, vring, mem)
    }

    fn get_response(mem: &GuestMemoryAtomic<GuestMemoryMmap>) -> VirtioScsiCmdResp {
        mem.memory()
            .read_obj::<VirtioScsiCmdResp>(GuestAddress(0x20_0000))
            .expect("Unable to read response from memory")
    }

    fn create_lun_specifier(target: u8, lun: u16) -> [u8; 8] {
        let lun = lun.to_le_bytes();

        [
            0x1,
            target,
            lun[0] | VirtioScsiLun::FLAT_SPACE_ADDRESSING_METHOD,
            lun[1],
            0x0,
            0x0,
            0x0,
            0x0,
        ]
    }

    #[test]
    fn backend_test() {
        let collector = FakeTargetCommandCollector::new();
        let fake_target = Box::new(FakeTarget::new(collector.clone(), |_, _| {
            Ok(CmdOutput::ok())
        }));

        let req = VirtioScsiCmdReq(virtio_scsi_cmd_req {
            lun: create_lun_specifier(0, 0),
            tag: 0,
            task_attr: 0,
            prio: 0,
            crn: 0,
            cdb: [0; CDB_SIZE],
        });

        let (mut backend, vring, mem) = setup(req);
        backend.add_target(fake_target);
        backend.process_request_queue(&vring).unwrap();

        let res = get_response(&mem);
        assert_eq!(res.0.response, VIRTIO_SCSI_S_OK as u8);

        let collector = collector.lock().unwrap();
        assert_eq!(
            collector.received_commands.len(),
            1,
            "expect one command to be passed to Target"
        );
    }

    #[test]
    fn backend_error_reporting_test() {
        let collector = FakeTargetCommandCollector::new();
        let fake_target = Box::new(FakeTarget::new(collector.clone(), |_, _| {
            Err(crate::scsi::CmdError::DataIn(io::Error::new(
                io::ErrorKind::Other,
                "internal error",
            )))
        }));

        let req = VirtioScsiCmdReq(virtio_scsi_cmd_req {
            lun: create_lun_specifier(0, 0),
            tag: 0,
            task_attr: 0,
            prio: 0,
            crn: 0,
            cdb: [0; CDB_SIZE],
        });

        let (mut backend, vring, mem) = setup(req);
        backend.add_target(fake_target);
        backend.process_request_queue(&vring).unwrap();

        let res = get_response(&mem);
        assert_eq!(res.0.response, VIRTIO_SCSI_S_FAILURE as u8);

        let collector = collector.lock().unwrap();
        assert_eq!(
            collector.received_commands.len(),
            1,
            "expect one command to be passed to Target"
        );
    }

    #[test]
    fn test_command_to_unknown_lun() {
        let collector = FakeTargetCommandCollector::new();

        let req = VirtioScsiCmdReq(virtio_scsi_cmd_req {
            lun: create_lun_specifier(0, 0),
            tag: 0,
            task_attr: 0,
            prio: 0,
            crn: 0,
            cdb: [0; CDB_SIZE],
        });

        let (mut backend, vring, mem) = setup(req);
        backend.process_request_queue(&vring).unwrap();

        let res = get_response(&mem);
        assert_eq!(res.0.response, VIRTIO_SCSI_S_BAD_TARGET as u8);

        let collector = collector.lock().unwrap();
        assert_eq!(
            collector.received_commands.len(),
            0,
            "expect no command to make it to the target"
        );
    }

    #[test]
    fn test_broken_read_descriptor() {
        let collector = FakeTargetCommandCollector::new();

        let broken_req = [0u8; 1]; // single byte request

        let (mut backend, vring, mem) = setup(broken_req);
        backend.process_request_queue(&vring).unwrap();

        let res = get_response(&mem);
        assert_eq!(res.0.response, VIRTIO_SCSI_S_FAILURE as u8);

        let collector = collector.lock().unwrap();
        assert_eq!(
            collector.received_commands.len(),
            0,
            "expect no command to make it to the target"
        );
    }

    #[test]
    fn test_reading_config() {
        let backend = VhostUserScsiBackend::new();

        // 0 len slice
        assert_eq!(vec![0_u8; 0], backend.get_config(0, 0));
        // overly long slice
        assert_eq!(
            std::mem::size_of::<virtio_scsi_config>(),
            backend.get_config(0, 2000).len()
        );
        // subslice
        assert_eq!(1, backend.get_config(4, 1).len());
        // overly long subslice
        assert_eq!(28, backend.get_config(8, 10000).len());
        // offset after end
        assert_eq!(0, backend.get_config(100000, 10).len());
    }
}
