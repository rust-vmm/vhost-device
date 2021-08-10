#![warn(clippy::pedantic)]
#![warn(clippy::nursery)]
#![warn(missing_debug_implementations)]
#![allow(clippy::cast_possible_truncation)]
#![allow(clippy::module_name_repetitions)]
#![allow(clippy::non_ascii_literal)]
mod scsi;
mod virtio;

use std::{
    convert::TryInto,
    fs::File,
    io::{self, ErrorKind, Read},
    path::PathBuf,
    process::exit,
    sync::{Arc, RwLock},
};

use log::{debug, error, info, warn};
use structopt::StructOpt;
use vhost::{
    vhost_user,
    vhost_user::{
        message::{VhostUserProtocolFeatures, VhostUserVirtioFeatures},
        Listener,
    },
};
use vhost_user_backend::{VhostUserBackendMut, VhostUserDaemon, VringRwLock, VringT};
use virtio::VirtioScsiLun;
use virtio_bindings::bindings::virtio_net::VIRTIO_F_VERSION_1;
use vm_memory::{GuestMemoryAtomic, GuestMemoryMmap};
use vmm_sys_util::{
    epoll::EventSet,
    eventfd::{EventFd, EFD_NONBLOCK},
};

use crate::{
    scsi::{
        emulation::{block_device::BlockDevice, EmulatedTarget},
        CmdError, TaskAttr,
    },
    virtio::{Response, ResponseCode},
};

// These are the defaults given in the virtio spec; QEMU doesn't let the driver
// write to config space, so these will always be the correct values.
const CDB_SIZE: usize = 32;
const SENSE_SIZE: usize = 96;

type DescriptorChainWriter = virtio::DescriptorChainWriter<GuestMemoryAtomic<GuestMemoryMmap>>;
type DescriptorChainReader = virtio::DescriptorChainReader<GuestMemoryAtomic<GuestMemoryMmap>>;
type Target = dyn scsi::Target<DescriptorChainWriter, DescriptorChainReader>;

struct VhostUserScsiBackend {
    mem: Option<GuestMemoryAtomic<GuestMemoryMmap>>,
    targets: Vec<Box<Target>>,
    exit_event: EventFd,
}

impl VhostUserScsiBackend {
    fn new() -> Self {
        Self {
            mem: None,
            targets: Vec::new(),
            exit_event: EventFd::new(EFD_NONBLOCK).expect("Creating exit eventfd"),
        }
    }
}

impl VhostUserScsiBackend {
    fn parse_target(&self, lun: VirtioScsiLun) -> Option<(&Target, u16)> {
        match lun {
            VirtioScsiLun::TargetLun(target, lun) => self
                .targets
                .get(usize::from(target))
                .map(|tgt| (tgt.as_ref(), lun)),
            VirtioScsiLun::ReportLuns => {
                // TODO: do we need to handle the REPORT LUNS well-known LUN?
                // In practice, everyone seems to just use LUN 0
                warn!("Guest is trying to use the REPORT LUNS well-known LUN, which we don't support.");
                None
            }
        }
    }

    fn handle_request_queue(
        &self,
        reader: &mut DescriptorChainReader,
        writer: &mut DescriptorChainWriter,
    ) {
        let mut request = [0; 19 + CDB_SIZE];

        let mut body_writer = writer.clone();
        body_writer.skip(12 + SENSE_SIZE as u32); // response header is 12 bytes long

        if let Err(e) = reader.read_exact(&mut request) {
            // See comment later about errors while writing to guest mem; maybe we at least
            // got functional write desciptors, so we can report an error
            error!("Error reading request from guest memory: {:?}", e);
            let res = Response::error(ResponseCode::Failure, body_writer.residual()).write(writer);
            if let Err(e) = res {
                error!("Error writing error response to guest memory: {:?}", e);
                // nothing else we can do here, since our way of communicating
                // with the guest is broken
            }
            return;
        }
        // unwrap is safe, we just sliced 8 out
        let lun = if let Some(lun) = VirtioScsiLun::parse(request[0..8].try_into().unwrap()) {
            lun
        } else {
            error!("Unable to parse LUN: {:?}", &request[0..8]);
            let res = Response::error(ResponseCode::Failure, body_writer.residual()).write(writer);
            if let Err(e) = res {
                error!("Error writing error response to guest memory: {:?}", e);
                // nothing else we can do here, since our way of
                // communicating with the guest is
                // broken
            };
            return;
        };
        // ditto
        let id = u64::from_le_bytes(request[8..16].try_into().unwrap());

        let task_attr = match request[16] {
            0 => TaskAttr::Simple,
            1 => TaskAttr::Ordered,
            2 => TaskAttr::HeadOfQueue,
            3 => TaskAttr::Aca,
            _ => {
                // virtio-scsi spec allows us to map any task attr to simple, presumably
                // including future ones
                warn!("Unknown task attr: {}", request[16]);
                TaskAttr::Simple
            }
        };
        let prio = request[17];
        let crn = request[18];
        let cdb = &request[19..(19 + CDB_SIZE)];

        let response = if let Some((target, lun)) = self.parse_target(lun) {
            let output = target.execute_command(
                lun,
                scsi::Request {
                    id,
                    cdb,
                    task_attr,
                    data_in: &mut body_writer,
                    data_out: reader,
                    crn,
                    prio,
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
            debug!("Rejecting command to LUN with bad target {:?}", lun);
            Response::error(ResponseCode::BadTarget, body_writer.residual())
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

    fn add_target(&mut self, target: Box<Target>) {
        self.targets.push(target);
    }
}

impl VhostUserBackendMut<VringRwLock> for VhostUserScsiBackend {
    fn num_queues(&self) -> usize {
        let num_request_queues = 1;
        2 + num_request_queues
    }

    fn max_queue_size(&self) -> usize {
        128 // qemu assumes this by default
    }

    fn features(&self) -> u64 {
        // TODO: Any other ones worth implementing? EVENT_IDX and INDIRECT_DESC
        // are supported by virtiofsd
        1 << VIRTIO_F_VERSION_1 | VhostUserVirtioFeatures::PROTOCOL_FEATURES.bits() | 1 << 2
    }

    fn protocol_features(&self) -> VhostUserProtocolFeatures {
        VhostUserProtocolFeatures::MQ
    }

    fn set_event_idx(&mut self, enabled: bool) {
        // Should always be true until we support EVENT_IDX in features.
        assert!(!enabled);
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

        // unwrap: only fails if the lock is poisoned, in which case we already panicked
        // somewhere else
        let mut vring = vrings[device_event as usize].get_mut();
        let queue = vring.get_queue_mut();

        let chains: Vec<_> = queue
            .iter()
            .map_err(|e| io::Error::new(ErrorKind::Other, e))?
            .collect();

        for dc in chains {
            let mut writer = DescriptorChainWriter::new(dc.clone());
            let mut reader = DescriptorChainReader::new(dc.clone());

            #[allow(clippy::single_match_else)]
            match device_event {
                2 => self.handle_request_queue(&mut reader, &mut writer),
                _ => {
                    error!("Ignoring descriptor on queue {}", device_event);
                    continue;
                }
            }

            queue
                .add_used(dc.head_index(), writer.max_written())
                .map_err(|e| io::Error::new(ErrorKind::Other, e))?;
        }

        vring
            .signal_used_queue()
            .map_err(|e| io::Error::new(ErrorKind::Other, e))?;

        Ok(false) // TODO: what's this bool? no idea. virtiofd-rs returns false
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

#[derive(StructOpt, Debug)]
struct Opt {
    /// Make the images read-only.
    ///
    /// Currently, we don't actually support writes, but sometimes we want to
    /// pretend the disk is writable to work around issues with some tools that
    /// use the Linux SCSI generic API.
    #[structopt(long("read-only"), short("r"))]
    read_only: bool,
    /// Tell the guest this disk is non-rotational.
    ///
    /// Affects some heuristics in Linux around, for example, scheduling.
    #[structopt(long("solid-state"), short("s"))]
    solid_state: bool,
    #[structopt(parse(from_os_str))]
    sock: PathBuf,
    #[structopt(parse(from_os_str))]
    images: Vec<PathBuf>,
}

fn main() {
    env_logger::init();

    let opt = Opt::from_args();

    let mut backend = VhostUserScsiBackend::new();
    let mut target = EmulatedTarget::new();

    if opt.images.len() > 256 {
        error!("More than 256 LUNs aren't currently supported.");
        // This is fairly simple to add; it's just a matter of supporting the right LUN
        // encoding formats.
        exit(1);
    }

    if !opt.read_only {
        warn!("Currently, only read-only images are supported. Unless you know what you're doing, you want to pass -r");
    }

    for image in opt.images {
        let mut dev = BlockDevice::new(File::open(image).expect("Opening image"));
        dev.set_write_protected(opt.read_only);
        dev.set_solid_state(opt.solid_state);
        target.add_lun(Box::new(dev));
    }

    backend.add_target(Box::new(target));

    let backend = Arc::new(RwLock::new(backend));

    let mut daemon = VhostUserDaemon::new(
        "vhost-user-scsi".into(),
        Arc::clone(&backend),
        GuestMemoryAtomic::new(GuestMemoryMmap::new()),
    )
    .expect("Creating daemon");

    daemon
        .start(Listener::new(opt.sock, true).expect("Creating listener"))
        .expect("Starting daemon");

    let run_result = daemon.wait();

    match run_result {
        Ok(()) => {
            info!("Stopping cleanly.");
        }
        Err(vhost_user_backend::Error::HandleRequest(vhost_user::Error::PartialMessage)) => {
            info!("vhost-user connection closed with partial message. If the VM is shutting down, this is expected behavior; otherwise, it might be a bug.");
        }
        Err(e) => {
            error!("Error running daemon: {:?}", e);
        }
    }

    // No matter the result, we need to shut down the worker thread.
    // unwrap will only panic if we already panicked somewhere else
    backend
        .read()
        .unwrap()
        .exit_event
        .write(1)
        .expect("Shutting down worker thread");

    dbg!();
}
