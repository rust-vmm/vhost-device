// SPDX-License-Identifier: Apache-2.0 or BSD-3-Clause

use std::{
    collections::{HashMap, HashSet},
    io::{self, Result as IoResult},
    path::{Path, PathBuf},
    sync::{Arc, Mutex, RwLock},
    u16, u32, u64, u8,
};

use log::warn;
use thiserror::Error as ThisError;
use vhost::vhost_user::message::{VhostUserProtocolFeatures, VhostUserVirtioFeatures};
use vhost_user_backend::{VhostUserBackend, VringRwLock};
use virtio_bindings::bindings::{
    virtio_config::VIRTIO_F_NOTIFY_ON_EMPTY, virtio_config::VIRTIO_F_VERSION_1,
    virtio_ring::VIRTIO_RING_F_EVENT_IDX,
};
use vm_memory::{ByteValued, GuestMemoryAtomic, GuestMemoryMmap, Le64};
use vmm_sys_util::{
    epoll::EventSet,
    eventfd::{EventFd, EFD_NONBLOCK},
};

use crate::thread_backend::RawPktsQ;
use crate::vhu_vsock_thread::*;

pub(crate) type CidMap =
    HashMap<u64, (Arc<RwLock<RawPktsQ>>, Arc<RwLock<HashSet<String>>>, EventFd)>;

const NUM_QUEUES: usize = 3;

// New descriptors pending on the rx queue
const RX_QUEUE_EVENT: u16 = 0;
// New descriptors are pending on the tx queue.
const TX_QUEUE_EVENT: u16 = 1;
// New descriptors are pending on the event queue.
const EVT_QUEUE_EVENT: u16 = 2;

/// Notification coming from the backend.
/// Event range [0...num_queues] is reserved for queues and exit event.
/// So NUM_QUEUES + 1 is used.
pub(crate) const BACKEND_EVENT: u16 = (NUM_QUEUES + 1) as u16;

/// Notification coming from the sibling VM.
pub(crate) const SIBLING_VM_EVENT: u16 = BACKEND_EVENT + 1;

/// CID of the host
pub(crate) const VSOCK_HOST_CID: u64 = 2;

/// Connection oriented packet
pub(crate) const VSOCK_TYPE_STREAM: u16 = 1;

/// Vsock packet operation ID

/// Connection request
pub(crate) const VSOCK_OP_REQUEST: u16 = 1;
/// Connection response
pub(crate) const VSOCK_OP_RESPONSE: u16 = 2;
/// Connection reset
pub(crate) const VSOCK_OP_RST: u16 = 3;
/// Shutdown connection
pub(crate) const VSOCK_OP_SHUTDOWN: u16 = 4;
/// Data read/write
pub(crate) const VSOCK_OP_RW: u16 = 5;
/// Flow control credit update
pub(crate) const VSOCK_OP_CREDIT_UPDATE: u16 = 6;
/// Flow control credit request
pub(crate) const VSOCK_OP_CREDIT_REQUEST: u16 = 7;

/// Vsock packet flags

/// VSOCK_OP_SHUTDOWN: Packet sender will receive no more data
pub(crate) const VSOCK_FLAGS_SHUTDOWN_RCV: u32 = 1;
/// VSOCK_OP_SHUTDOWN: Packet sender will send no more data
pub(crate) const VSOCK_FLAGS_SHUTDOWN_SEND: u32 = 2;

// Queue mask to select vrings.
const QUEUE_MASK: u64 = 0b11;

pub(crate) type Result<T> = std::result::Result<T, Error>;

/// Custom error types
#[derive(Debug, ThisError)]
pub(crate) enum Error {
    #[error("Failed to handle event other than EPOLLIN event")]
    HandleEventNotEpollIn,
    #[error("Failed to handle unknown event")]
    HandleUnknownEvent,
    #[error("Failed to accept new local socket connection")]
    UnixAccept(std::io::Error),
    #[error("Failed to bind a unix stream")]
    UnixBind(std::io::Error),
    #[error("Failed to create an epoll fd")]
    EpollFdCreate(std::io::Error),
    #[error("Failed to add to epoll")]
    EpollAdd(std::io::Error),
    #[error("Failed to modify evset associated with epoll")]
    EpollModify(std::io::Error),
    #[error("Failed to read from unix stream")]
    UnixRead(std::io::Error),
    #[error("Failed to convert byte array to string")]
    ConvertFromUtf8(std::str::Utf8Error),
    #[error("Invalid vsock connection request from host")]
    InvalidPortRequest,
    #[error("Unable to convert string to integer")]
    ParseInteger(std::num::ParseIntError),
    #[error("Error reading stream port")]
    ReadStreamPort(Box<Error>),
    #[error("Failed to de-register fd from epoll")]
    EpollRemove(std::io::Error),
    #[error("No memory configured")]
    NoMemoryConfigured,
    #[error("Unable to iterate queue")]
    IterateQueue,
    #[error("No rx request available")]
    NoRequestRx,
    #[error("Packet missing data buffer")]
    PktBufMissing,
    #[error("Failed to connect to unix socket")]
    UnixConnect(std::io::Error),
    #[error("Unable to write to unix stream")]
    UnixWrite,
    #[error("Unable to push data to local tx buffer")]
    LocalTxBufFull,
    #[error("Unable to flush data from local tx buffer")]
    LocalTxBufFlush(std::io::Error),
    #[error("No free local port available for new host inititated connection")]
    NoFreeLocalPort,
    #[error("Backend rx queue is empty")]
    EmptyBackendRxQ,
    #[error("Failed to create an EventFd")]
    EventFdCreate(std::io::Error),
    #[error("Raw vsock packets queue is empty")]
    EmptyRawPktsQueue,
    #[error("CID already in use by another vsock device")]
    CidAlreadyInUse,
}

impl std::convert::From<Error> for std::io::Error {
    fn from(e: Error) -> Self {
        std::io::Error::new(io::ErrorKind::Other, e)
    }
}

#[derive(Debug, Clone)]
/// This structure is the public API through which an external program
/// is allowed to configure the backend.
pub(crate) struct VsockConfig {
    guest_cid: u64,
    socket: PathBuf,
    uds_path: PathBuf,
    tx_buffer_size: u32,
    queue_size: usize,
    groups: Vec<String>,
}

impl VsockConfig {
    /// Create a new instance of the VsockConfig struct, containing the
    /// parameters to be fed into the vsock-backend server.
    pub fn new(
        guest_cid: u64,
        socket: PathBuf,
        uds_path: PathBuf,
        tx_buffer_size: u32,
        queue_size: usize,
        groups: Vec<String>,
    ) -> Self {
        Self {
            guest_cid,
            socket,
            uds_path,
            tx_buffer_size,
            queue_size,
            groups,
        }
    }

    /// Return the guest's current CID.
    pub fn get_guest_cid(&self) -> u64 {
        self.guest_cid
    }

    /// Return the path of the unix domain socket which is listening to
    /// requests from the host side application.
    pub fn get_uds_path(&self) -> &Path {
        self.uds_path.as_path()
    }

    /// Return the path of the unix domain socket which is listening to
    /// requests from the guest.
    pub fn get_socket_path(&self) -> &Path {
        self.socket.as_path()
    }

    pub fn get_tx_buffer_size(&self) -> u32 {
        self.tx_buffer_size
    }

    pub fn get_queue_size(&self) -> usize {
        self.queue_size
    }

    pub fn get_groups(&self) -> Vec<String> {
        self.groups.clone()
    }
}

/// A local port and peer port pair used to retrieve
/// the corresponding connection.
#[derive(Hash, PartialEq, Eq, Debug, Clone)]
pub(crate) struct ConnMapKey {
    local_port: u32,
    peer_port: u32,
}

impl ConnMapKey {
    pub fn new(local_port: u32, peer_port: u32) -> Self {
        Self {
            local_port,
            peer_port,
        }
    }
}

/// Virtio Vsock Configuration
#[derive(Copy, Clone, Debug, Default, PartialEq)]
#[repr(C)]
struct VirtioVsockConfig {
    pub guest_cid: Le64,
}

// SAFETY: The layout of the structure is fixed and can be initialized by
// reading its content from byte array.
unsafe impl ByteValued for VirtioVsockConfig {}

pub(crate) struct VhostUserVsockBackend {
    config: VirtioVsockConfig,
    queue_size: usize,
    pub threads: Vec<Mutex<VhostUserVsockThread>>,
    queues_per_thread: Vec<u64>,
    pub exit_event: EventFd,
}

impl VhostUserVsockBackend {
    pub fn new(config: VsockConfig, cid_map: Arc<RwLock<CidMap>>) -> Result<Self> {
        let thread = Mutex::new(VhostUserVsockThread::new(
            config.get_uds_path().to_path_buf(),
            config.get_guest_cid(),
            config.get_tx_buffer_size(),
            config.get_groups(),
            cid_map,
        )?);
        let queues_per_thread = vec![QUEUE_MASK];

        Ok(Self {
            config: VirtioVsockConfig {
                guest_cid: From::from(config.get_guest_cid()),
            },
            queue_size: config.get_queue_size(),
            threads: vec![thread],
            queues_per_thread,
            exit_event: EventFd::new(EFD_NONBLOCK).map_err(Error::EventFdCreate)?,
        })
    }
}

impl VhostUserBackend for VhostUserVsockBackend {
    type Vring = VringRwLock;
    type Bitmap = ();

    fn num_queues(&self) -> usize {
        NUM_QUEUES
    }

    fn max_queue_size(&self) -> usize {
        self.queue_size
    }

    fn features(&self) -> u64 {
        1 << VIRTIO_F_VERSION_1
            | 1 << VIRTIO_F_NOTIFY_ON_EMPTY
            | 1 << VIRTIO_RING_F_EVENT_IDX
            | VhostUserVirtioFeatures::PROTOCOL_FEATURES.bits()
    }

    fn protocol_features(&self) -> VhostUserProtocolFeatures {
        VhostUserProtocolFeatures::CONFIG
    }

    fn set_event_idx(&self, enabled: bool) {
        for thread in self.threads.iter() {
            thread.lock().unwrap().event_idx = enabled;
        }
    }

    fn update_memory(&self, atomic_mem: GuestMemoryAtomic<GuestMemoryMmap>) -> IoResult<()> {
        for thread in self.threads.iter() {
            thread.lock().unwrap().mem = Some(atomic_mem.clone());
        }
        Ok(())
    }

    fn handle_event(
        &self,
        device_event: u16,
        evset: EventSet,
        vrings: &[VringRwLock],
        thread_id: usize,
    ) -> IoResult<()> {
        let vring_rx = &vrings[0];
        let vring_tx = &vrings[1];

        if evset != EventSet::IN {
            return Err(Error::HandleEventNotEpollIn.into());
        }

        let mut thread = self.threads[thread_id].lock().unwrap();
        let evt_idx = thread.event_idx;

        match device_event {
            RX_QUEUE_EVENT => {}
            TX_QUEUE_EVENT => {
                thread.process_tx(vring_tx, evt_idx)?;
            }
            EVT_QUEUE_EVENT => {
                warn!("Received an unexpected EVT_QUEUE_EVENT");
            }
            BACKEND_EVENT => {
                thread.process_backend_evt(evset);
                if let Err(e) = thread.process_tx(vring_tx, evt_idx) {
                    match e {
                        Error::NoMemoryConfigured => {
                            warn!("Received a backend event before vring initialization")
                        }
                        _ => return Err(e.into()),
                    }
                }
            }
            SIBLING_VM_EVENT => {
                let _ = thread.sibling_event_fd.read();
                thread.process_raw_pkts(vring_rx, evt_idx)?;
                return Ok(());
            }
            _ => {
                return Err(Error::HandleUnknownEvent.into());
            }
        }

        if device_event != EVT_QUEUE_EVENT {
            thread.process_rx(vring_rx, evt_idx)?;
        }

        Ok(())
    }

    fn get_config(&self, offset: u32, size: u32) -> Vec<u8> {
        let offset = offset as usize;
        let size = size as usize;

        let buf = self.config.as_slice();

        if offset + size > buf.len() {
            return Vec::new();
        }

        buf[offset..offset + size].to_vec()
    }

    fn queues_per_thread(&self) -> Vec<u64> {
        self.queues_per_thread.clone()
    }

    fn exit_event(&self, _thread_index: usize) -> Option<EventFd> {
        self.exit_event.try_clone().ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::convert::TryInto;
    use tempfile::tempdir;
    use vhost_user_backend::VringT;
    use vm_memory::GuestAddress;

    const CONN_TX_BUF_SIZE: u32 = 64 * 1024;
    const QUEUE_SIZE: usize = 1024;

    #[test]
    fn test_vsock_backend() {
        const CID: u64 = 3;

        let groups_list: Vec<String> = vec![String::from("default")];

        let test_dir = tempdir().expect("Could not create a temp test directory.");

        let vhost_socket_path = test_dir.path().join("test_vsock_backend.socket");
        let vsock_socket_path = test_dir.path().join("test_vsock_backend.vsock");

        let config = VsockConfig::new(
            CID,
            vhost_socket_path.clone(),
            vsock_socket_path.clone(),
            CONN_TX_BUF_SIZE,
            QUEUE_SIZE,
            groups_list,
        );

        let cid_map: Arc<RwLock<CidMap>> = Arc::new(RwLock::new(HashMap::new()));

        let backend = VhostUserVsockBackend::new(config, cid_map);

        assert!(backend.is_ok());
        let backend = backend.unwrap();

        assert_eq!(backend.num_queues(), NUM_QUEUES);
        assert_eq!(backend.max_queue_size(), QUEUE_SIZE);
        assert_ne!(backend.features(), 0);
        assert!(!backend.protocol_features().is_empty());
        backend.set_event_idx(false);

        let mem = GuestMemoryAtomic::new(
            GuestMemoryMmap::<()>::from_ranges(&[(GuestAddress(0), 0x10000)]).unwrap(),
        );
        let vrings = [
            VringRwLock::new(mem.clone(), 0x1000).unwrap(),
            VringRwLock::new(mem.clone(), 0x2000).unwrap(),
        ];
        vrings[0].set_queue_info(0x100, 0x200, 0x300).unwrap();
        vrings[0].set_queue_ready(true);
        vrings[1].set_queue_info(0x1100, 0x1200, 0x1300).unwrap();
        vrings[1].set_queue_ready(true);

        assert!(backend.update_memory(mem).is_ok());

        let queues_per_thread = backend.queues_per_thread();
        assert_eq!(queues_per_thread.len(), 1);
        assert_eq!(queues_per_thread[0], 0b11);

        let config = backend.get_config(0, 8);
        assert_eq!(config.len(), 8);
        let cid = u64::from_le_bytes(config.try_into().unwrap());
        assert_eq!(cid, CID);

        let exit = backend.exit_event(0);
        assert!(exit.is_some());
        exit.unwrap().write(1).unwrap();

        let ret = backend.handle_event(RX_QUEUE_EVENT, EventSet::IN, &vrings, 0);
        assert!(ret.is_ok());

        let ret = backend.handle_event(TX_QUEUE_EVENT, EventSet::IN, &vrings, 0);
        assert!(ret.is_ok());

        let ret = backend.handle_event(EVT_QUEUE_EVENT, EventSet::IN, &vrings, 0);
        assert!(ret.is_ok());

        let ret = backend.handle_event(BACKEND_EVENT, EventSet::IN, &vrings, 0);
        assert!(ret.is_ok());

        // cleanup
        let _ = std::fs::remove_file(&vhost_socket_path);
        let _ = std::fs::remove_file(&vsock_socket_path);

        test_dir.close().unwrap();
    }

    #[test]
    fn test_vsock_backend_failures() {
        const CID: u64 = 3;

        let groups: Vec<String> = vec![String::from("default")];

        let test_dir = tempdir().expect("Could not create a temp test directory.");

        let vhost_socket_path = test_dir.path().join("test_vsock_backend_failures.socket");
        let vsock_socket_path = test_dir.path().join("test_vsock_backend_failures.vsock");

        let config = VsockConfig::new(
            CID,
            PathBuf::from("/sys/not_allowed.socket"),
            PathBuf::from("/sys/not_allowed.vsock"),
            CONN_TX_BUF_SIZE,
            QUEUE_SIZE,
            groups.clone(),
        );

        let cid_map: Arc<RwLock<CidMap>> = Arc::new(RwLock::new(HashMap::new()));

        let backend = VhostUserVsockBackend::new(config, cid_map.clone());
        assert!(backend.is_err());

        let config = VsockConfig::new(
            CID,
            vhost_socket_path.clone(),
            vsock_socket_path.clone(),
            CONN_TX_BUF_SIZE,
            QUEUE_SIZE,
            groups,
        );

        let backend = VhostUserVsockBackend::new(config, cid_map).unwrap();
        let mem = GuestMemoryAtomic::new(
            GuestMemoryMmap::<()>::from_ranges(&[(GuestAddress(0), 0x10000)]).unwrap(),
        );
        let vrings = [
            VringRwLock::new(mem.clone(), 0x1000).unwrap(),
            VringRwLock::new(mem.clone(), 0x2000).unwrap(),
        ];

        backend.update_memory(mem).unwrap();

        // reading out of the config space, expecting empty config
        let config = backend.get_config(2, 8);
        assert_eq!(config.len(), 0);

        assert_eq!(
            backend
                .handle_event(RX_QUEUE_EVENT, EventSet::OUT, &vrings, 0)
                .unwrap_err()
                .to_string(),
            Error::HandleEventNotEpollIn.to_string()
        );
        assert_eq!(
            backend
                .handle_event(SIBLING_VM_EVENT + 1, EventSet::IN, &vrings, 0)
                .unwrap_err()
                .to_string(),
            Error::HandleUnknownEvent.to_string()
        );

        // cleanup
        let _ = std::fs::remove_file(&vhost_socket_path);
        let _ = std::fs::remove_file(&vsock_socket_path);

        test_dir.close().unwrap();
    }

    #[test]
    fn test_vhu_vsock_structs() {
        let config = VsockConfig::new(0, "".into(), "".into(), 0, 0, vec![String::new()]);

        assert_eq!(format!("{config:?}"), "VsockConfig { guest_cid: 0, socket: \"\", uds_path: \"\", tx_buffer_size: 0, queue_size: 0, groups: [\"\"] }");

        let conn_map = ConnMapKey::new(0, 0);
        assert_eq!(
            format!("{conn_map:?}"),
            "ConnMapKey { local_port: 0, peer_port: 0 }"
        );
        assert_eq!(conn_map, conn_map.clone());

        let virtio_config = VirtioVsockConfig::default();
        assert_eq!(
            format!("{virtio_config:?}"),
            "VirtioVsockConfig { guest_cid: Le64(0) }"
        );
        assert_eq!(virtio_config, virtio_config.clone());

        let error = Error::HandleEventNotEpollIn;
        assert_eq!(format!("{error:?}"), "HandleEventNotEpollIn");
    }
}
