// SPDX-License-Identifier: Apache-2.0 or BSD-3-Clause

use std::{
    collections::{HashMap, HashSet},
    io::Result as IoResult,
    path::PathBuf,
    sync::{Arc, Mutex, RwLock},
};

use log::warn;
use thiserror::Error as ThisError;
use vhost::vhost_user::message::{VhostUserProtocolFeatures, VhostUserVirtioFeatures};
use vhost_user_backend::{VhostUserBackend, VringRwLock, VringT};
use virtio_bindings::bindings::{
    virtio_config::{VIRTIO_F_NOTIFY_ON_EMPTY, VIRTIO_F_VERSION_1},
    virtio_ring::VIRTIO_RING_F_EVENT_IDX,
};
use virtio_queue::QueueT;
use vm_memory::{ByteValued, GuestMemoryAtomic, GuestMemoryMmap, Le64};
use vmm_sys_util::{
    epoll::EventSet,
    event::{new_event_consumer_and_notifier, EventConsumer, EventFlag, EventNotifier},
    eventfd::EventFd,
};

use crate::{thread_backend::RawPktsQ, vhu_vsock_thread::*};

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

/// Vsock packet operation ID - Connection request
pub(crate) const VSOCK_OP_REQUEST: u16 = 1;
/// Vsock packet operation ID - Connection response
pub(crate) const VSOCK_OP_RESPONSE: u16 = 2;
/// Vsock packet operation ID - Connection reset
pub(crate) const VSOCK_OP_RST: u16 = 3;
/// Vsock packet operation ID - Shutdown connection
pub(crate) const VSOCK_OP_SHUTDOWN: u16 = 4;
/// Vsock packet operation ID - Data read/write
pub(crate) const VSOCK_OP_RW: u16 = 5;
/// Vsock packet operation ID - Flow control credit update
pub(crate) const VSOCK_OP_CREDIT_UPDATE: u16 = 6;
/// Vsock packet operation ID - Flow control credit request
pub(crate) const VSOCK_OP_CREDIT_REQUEST: u16 = 7;

/// Vsock packet flags - `VSOCK_OP_SHUTDOWN`: Packet sender will receive no more
/// data
pub(crate) const VSOCK_FLAGS_SHUTDOWN_RCV: u32 = 1;
/// Vsock packet flags - `VSOCK_OP_SHUTDOWN`: Packet sender will send no more
/// data
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
    #[error("Failed to accept new local unix domain socket connection")]
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
    #[cfg(feature = "backend_vsock")]
    #[error("Failed to accept new local vsock socket connection")]
    VsockAccept(std::io::Error),
    #[cfg(feature = "backend_vsock")]
    #[error("Failed to connect to vsock socket")]
    VsockConnect(std::io::Error),
    #[cfg(feature = "backend_vsock")]
    #[error("Failed to bind a vsock stream")]
    VsockBind(std::io::Error),
    #[error("Unable to write to stream")]
    StreamWrite,
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
        std::io::Error::other(e)
    }
}

#[cfg(feature = "backend_vsock")]
#[derive(Debug, PartialEq, Clone)]
pub(crate) struct VsockProxyInfo {
    pub forward_cid: u32,
    pub listen_ports: Vec<u32>,
}

#[derive(Debug, PartialEq, Clone)]
pub(crate) enum BackendType {
    /// unix domain socket path
    UnixDomainSocket(PathBuf),
    /// the vsock CID and ports
    #[cfg(feature = "backend_vsock")]
    Vsock(VsockProxyInfo),
}

#[derive(Debug, Clone)]
/// This structure is the public API through which an external program
/// is allowed to configure the backend.
pub(crate) struct VsockConfig {
    guest_cid: u64,
    socket: PathBuf,
    backend_info: BackendType,
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
        backend_info: BackendType,
        tx_buffer_size: u32,
        queue_size: usize,
        groups: Vec<String>,
    ) -> Self {
        Self {
            guest_cid,
            socket,
            backend_info,
            tx_buffer_size,
            queue_size,
            groups,
        }
    }

    /// Return the guest's current CID.
    pub fn get_guest_cid(&self) -> u64 {
        self.guest_cid
    }

    pub fn get_backend_info(&self) -> BackendType {
        self.backend_info.clone()
    }

    /// Return the path of the unix domain socket which is listening to
    /// requests from the guest.
    pub fn get_socket_path(&self) -> PathBuf {
        self.socket.clone()
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
    exit_consumer: EventConsumer,
    exit_notifier: EventNotifier,
}

impl VhostUserVsockBackend {
    pub fn new(config: VsockConfig, cid_map: Arc<RwLock<CidMap>>) -> Result<Self> {
        let thread = Mutex::new(VhostUserVsockThread::new(
            config.get_backend_info(),
            config.get_guest_cid(),
            config.get_tx_buffer_size(),
            config.get_groups(),
            cid_map,
        )?);
        let queues_per_thread = vec![QUEUE_MASK];

        let (exit_consumer, exit_notifier) =
            new_event_consumer_and_notifier(EventFlag::NONBLOCK).map_err(Error::EventFdCreate)?;

        Ok(Self {
            config: VirtioVsockConfig {
                guest_cid: From::from(config.get_guest_cid()),
            },
            queue_size: config.get_queue_size(),
            threads: vec![thread],
            queues_per_thread,
            exit_consumer,
            exit_notifier,
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
        (1 << VIRTIO_F_VERSION_1)
            | (1 << VIRTIO_F_NOTIFY_ON_EMPTY)
            | (1 << VIRTIO_RING_F_EVENT_IDX)
            | VhostUserVirtioFeatures::PROTOCOL_FEATURES.bits()
    }

    fn protocol_features(&self) -> VhostUserProtocolFeatures {
        VhostUserProtocolFeatures::MQ | VhostUserProtocolFeatures::CONFIG
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
                if !vring_tx.get_ref().get_queue().ready() {
                    // A VHOST_USER_GET_VRING_BASE request can cause the vring to not be ready.
                    return Ok(());
                }
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
                if vring_rx.get_ref().get_queue().ready() {
                    // A VHOST_USER_GET_VRING_BASE request can cause the vring to not be ready.
                    thread.process_raw_pkts(vring_rx, evt_idx)?;
                }
                return Ok(());
            }
            _ => {
                return Err(Error::HandleUnknownEvent.into());
            }
        }

        if device_event != EVT_QUEUE_EVENT && vring_rx.get_ref().get_queue().ready() {
            // A VHOST_USER_GET_VRING_BASE request can cause the vring to not be ready.
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

    fn exit_event(&self, _thread_index: usize) -> Option<(EventConsumer, EventNotifier)> {
        let consumer = self.exit_consumer.try_clone().ok()?;
        let notifier = self.exit_notifier.try_clone().ok()?;
        Some((consumer, notifier))
    }
}

#[cfg(test)]
mod tests {
    use std::convert::TryInto;

    use tempfile::tempdir;
    use vhost_user_backend::VringT;
    use vm_memory::GuestAddress;

    use super::*;

    const CONN_TX_BUF_SIZE: u32 = 64 * 1024;
    const QUEUE_SIZE: usize = 1024;

    fn test_vsock_backend(config: VsockConfig, expected_cid: u64) {
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

        backend.update_memory(mem).unwrap();

        let queues_per_thread = backend.queues_per_thread();
        assert_eq!(queues_per_thread.len(), 1);
        assert_eq!(queues_per_thread[0], 0b11);

        let config = backend.get_config(0, 8);
        assert_eq!(config.len(), 8);
        let cid = u64::from_le_bytes(config.try_into().unwrap());
        assert_eq!(cid, expected_cid);

        let exit = backend.exit_event(0);
        assert!(exit.is_some());
        let (_, notifier) = exit.unwrap();
        notifier.notify().unwrap();

        let ret = backend.handle_event(RX_QUEUE_EVENT, EventSet::IN, &vrings, 0);
        ret.unwrap();

        let ret = backend.handle_event(TX_QUEUE_EVENT, EventSet::IN, &vrings, 0);
        ret.unwrap();

        let ret = backend.handle_event(EVT_QUEUE_EVENT, EventSet::IN, &vrings, 0);
        ret.unwrap();

        let ret = backend.handle_event(BACKEND_EVENT, EventSet::IN, &vrings, 0);
        ret.unwrap();
    }

    #[test]
    fn test_vsock_backend_unix() {
        const CID: u64 = 3;

        let groups_list: Vec<String> = vec![String::from("default")];

        let test_dir = tempdir().expect("Could not create a temp test directory.");

        let vhost_socket_path = test_dir.path().join("test_vsock_backend_unix.socket");
        let vsock_socket_path = test_dir.path().join("test_vsock_backend.vsock");

        let config = VsockConfig::new(
            CID,
            vhost_socket_path.clone(),
            BackendType::UnixDomainSocket(vsock_socket_path.clone()),
            CONN_TX_BUF_SIZE,
            QUEUE_SIZE,
            groups_list,
        );

        test_vsock_backend(config, CID);

        // cleanup
        let _ = std::fs::remove_file(vhost_socket_path);
        let _ = std::fs::remove_file(vsock_socket_path);
        test_dir.close().unwrap();
    }

    #[cfg(feature = "backend_vsock")]
    #[test]
    fn test_vsock_backend_vsock() {
        const CID: u64 = 3;

        let groups_list: Vec<String> = vec![String::from("default")];

        let test_dir = tempdir().expect("Could not create a temp test directory.");

        let vhost_socket_path = test_dir.path().join("test_vsock_backend.socket");
        let config = VsockConfig::new(
            CID,
            vhost_socket_path.clone(),
            BackendType::Vsock(VsockProxyInfo {
                forward_cid: 1,
                listen_ports: vec![9001, 9002],
            }),
            CONN_TX_BUF_SIZE,
            QUEUE_SIZE,
            groups_list,
        );

        test_vsock_backend(config, CID);

        // cleanup
        let _ = std::fs::remove_file(vhost_socket_path);
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
            BackendType::UnixDomainSocket(PathBuf::from("/sys/not_allowed.vsock")),
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
            BackendType::UnixDomainSocket(vsock_socket_path.clone()),
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
        let _ = std::fs::remove_file(vhost_socket_path);
        let _ = std::fs::remove_file(vsock_socket_path);

        test_dir.close().unwrap();
    }

    #[test]
    fn test_vhu_vsock_structs() {
        let unix_config = VsockConfig::new(
            0,
            PathBuf::new(),
            BackendType::UnixDomainSocket(PathBuf::new()),
            0,
            0,
            vec![String::new()],
        );
        assert_eq!(format!("{unix_config:?}"), "VsockConfig { guest_cid: 0, socket: \"\", backend_info: UnixDomainSocket(\"\"), tx_buffer_size: 0, queue_size: 0, groups: [\"\"] }");

        #[cfg(feature = "backend_vsock")]
        let vsock_config = VsockConfig::new(
            0,
            PathBuf::new(),
            BackendType::Vsock(VsockProxyInfo {
                forward_cid: 1,
                listen_ports: vec![9001, 9002],
            }),
            0,
            0,
            vec![String::new()],
        );
        #[cfg(feature = "backend_vsock")]
        assert_eq!(format!("{vsock_config:?}"), "VsockConfig { guest_cid: 0, socket: \"\", backend_info: Vsock(VsockProxyInfo { forward_cid: 1, listen_ports: [9001, 9002] }), tx_buffer_size: 0, queue_size: 0, groups: [\"\"] }");

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
