// SPDX-License-Identifier: Apache-2.0 or BSD-3-Clause

mod rxops;
mod rxqueue;
mod thread_backend;
mod txbuf;
mod vhu_vsock;
mod vhu_vsock_thread;
mod vsock_conn;

use std::{
    collections::HashMap,
    convert::TryFrom,
    process::exit,
    sync::{Arc, RwLock},
    thread,
};

use crate::vhu_vsock::{CidMap, VhostUserVsockBackend, VsockConfig};
use clap::{Args, Parser};
use log::{error, info, warn};
use serde::Deserialize;
use thiserror::Error as ThisError;
use vhost::{vhost_user, vhost_user::Listener};
use vhost_user_backend::VhostUserDaemon;
use vm_memory::{GuestMemoryAtomic, GuestMemoryMmap};

const DEFAULT_GUEST_CID: u64 = 3;
const DEFAULT_TX_BUFFER_SIZE: u32 = 64 * 1024;

#[derive(Debug, ThisError)]
enum CliError {
    #[error("No arguments provided")]
    NoArgsProvided,
    #[error("Failed to parse configuration file")]
    ConfigParse,
}

#[derive(Debug, ThisError)]
enum VmArgsParseError {
    #[error("Bad argument")]
    BadArgument,
    #[error("Invalid key `{0}`")]
    InvalidKey(String),
    #[error("Unable to convert string to integer: {0}")]
    ParseInteger(std::num::ParseIntError),
    #[error("Required key `{0}` not found")]
    RequiredKeyNotFound(String),
}

#[derive(Debug, ThisError)]
enum BackendError {
    #[error("Could not create backend: {0}")]
    CouldNotCreateBackend(vhu_vsock::Error),
    #[error("Could not create daemon: {0}")]
    CouldNotCreateDaemon(vhost_user_backend::Error),
}

#[derive(Args, Clone, Debug, Deserialize)]
struct VsockParam {
    /// Context identifier of the guest which uniquely identifies the device for its lifetime.
    #[arg(
        long,
        default_value_t = DEFAULT_GUEST_CID,
        conflicts_with = "config",
        conflicts_with = "vm"
    )]
    guest_cid: u64,

    /// Unix socket to which a hypervisor connects to and sets up the control path with the device.
    #[arg(long, conflicts_with = "config", conflicts_with = "vm")]
    socket: String,

    /// Unix socket to which a host-side application connects to.
    #[arg(long, conflicts_with = "config", conflicts_with = "vm")]
    uds_path: String,

    /// The size of the buffer used for the TX virtqueue
    #[clap(long, default_value_t = DEFAULT_TX_BUFFER_SIZE, conflicts_with = "config", conflicts_with = "vm")]
    tx_buffer_size: u32,
}

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct VsockArgs {
    #[command(flatten)]
    param: Option<VsockParam>,

    /// Device parameters corresponding to a VM in the form of comma separated key=value pairs.
    /// The allowed keys are: guest_cid, socket, uds_path and tx_buffer_size
    /// Example: --vm guest-cid=3,socket=/tmp/vhost3.socket,uds-path=/tmp/vm3.vsock,tx-buffer-size=65536
    /// Multiple instances of this argument can be provided to configure devices for multiple guests.
    #[arg(long, conflicts_with = "config", verbatim_doc_comment, value_parser = parse_vm_params)]
    vm: Option<Vec<VsockConfig>>,

    /// Load from a given configuration file
    #[arg(long)]
    config: Option<String>,
}

fn parse_vm_params(s: &str) -> Result<VsockConfig, VmArgsParseError> {
    let mut guest_cid = None;
    let mut socket = None;
    let mut uds_path = None;
    let mut tx_buffer_size = None;

    for arg in s.trim().split(',') {
        let mut parts = arg.split('=');
        let key = parts.next().ok_or(VmArgsParseError::BadArgument)?;
        let val = parts.next().ok_or(VmArgsParseError::BadArgument)?;

        match key {
            "guest_cid" | "guest-cid" => {
                guest_cid = Some(val.parse().map_err(VmArgsParseError::ParseInteger)?)
            }
            "socket" => socket = Some(val.to_string()),
            "uds_path" | "uds-path" => uds_path = Some(val.to_string()),
            "tx_buffer_size" | "tx-buffer-size" => {
                tx_buffer_size = Some(val.parse().map_err(VmArgsParseError::ParseInteger)?)
            }
            _ => return Err(VmArgsParseError::InvalidKey(key.to_string())),
        }
    }

    Ok(VsockConfig::new(
        guest_cid.unwrap_or(DEFAULT_GUEST_CID),
        socket.ok_or_else(|| VmArgsParseError::RequiredKeyNotFound("socket".to_string()))?,
        uds_path.ok_or_else(|| VmArgsParseError::RequiredKeyNotFound("uds-path".to_string()))?,
        tx_buffer_size.unwrap_or(DEFAULT_TX_BUFFER_SIZE),
    ))
}

impl VsockArgs {
    pub fn parse_config(&self) -> Option<Result<Vec<VsockConfig>, CliError>> {
        if let Some(c) = &self.config {
            let b = config::Config::builder()
                .add_source(config::File::new(c.as_str(), config::FileFormat::Yaml))
                .build();
            if let Ok(s) = b {
                let mut v = s.get::<Vec<VsockParam>>("vms").unwrap();
                if !v.is_empty() {
                    let parsed: Vec<VsockConfig> = v
                        .drain(..)
                        .map(|p| {
                            VsockConfig::new(
                                p.guest_cid,
                                p.socket.trim().to_string(),
                                p.uds_path.trim().to_string(),
                                p.tx_buffer_size,
                            )
                        })
                        .collect();
                    return Some(Ok(parsed));
                } else {
                    return Some(Err(CliError::ConfigParse));
                }
            } else {
                return Some(Err(CliError::ConfigParse));
            }
        }
        None
    }
}

impl TryFrom<VsockArgs> for Vec<VsockConfig> {
    type Error = CliError;

    fn try_from(cmd_args: VsockArgs) -> Result<Self, CliError> {
        // we try to use the configuration first, if failed,  then fall back to the manual settings.
        match cmd_args.parse_config() {
            Some(c) => c,
            _ => match cmd_args.vm {
                Some(v) => Ok(v),
                _ => cmd_args.param.map_or(Err(CliError::NoArgsProvided), |p| {
                    Ok(vec![VsockConfig::new(
                        p.guest_cid,
                        p.socket.trim().to_string(),
                        p.uds_path.trim().to_string(),
                        p.tx_buffer_size,
                    )])
                }),
            },
        }
    }
}

/// This is the public API through which an external program starts the
/// vhost-device-vsock backend server.
pub(crate) fn start_backend_server(
    config: VsockConfig,
    cid_map: Arc<RwLock<CidMap>>,
) -> Result<(), BackendError> {
    loop {
        let backend = Arc::new(
            VhostUserVsockBackend::new(config.clone(), cid_map.clone())
                .map_err(BackendError::CouldNotCreateBackend)?,
        );

        let listener = Listener::new(config.get_socket_path(), true).unwrap();

        let mut daemon = VhostUserDaemon::new(
            String::from("vhost-device-vsock"),
            backend.clone(),
            GuestMemoryAtomic::new(GuestMemoryMmap::new()),
        )
        .map_err(BackendError::CouldNotCreateDaemon)?;

        let mut vring_workers = daemon.get_epoll_handlers();

        for thread in backend.threads.iter() {
            thread
                .lock()
                .unwrap()
                .set_vring_worker(Some(vring_workers.remove(0)));
        }

        daemon.start(listener).unwrap();

        match daemon.wait() {
            Ok(()) => {
                info!("Stopping cleanly");
            }
            Err(vhost_user_backend::Error::HandleRequest(
                vhost_user::Error::PartialMessage | vhost_user::Error::Disconnected,
            )) => {
                info!("vhost-user connection closed with partial message. If the VM is shutting down, this is expected behavior; otherwise, it might be a bug.");
            }
            Err(e) => {
                warn!("Error running daemon: {:?}", e);
            }
        }

        // No matter the result, we need to shut down the worker thread.
        backend.exit_event.write(1).unwrap();
    }
}

pub(crate) fn start_backend_servers(configs: &[VsockConfig]) -> Result<(), BackendError> {
    let cid_map: Arc<RwLock<CidMap>> = Arc::new(RwLock::new(HashMap::new()));
    let mut handles = Vec::new();

    for c in configs.iter() {
        let config = c.clone();
        let cid_map = cid_map.clone();
        let handle = thread::Builder::new()
            .name(format!("vhu-vsock-cid-{}", c.get_guest_cid()))
            .spawn(move || start_backend_server(config, cid_map))
            .unwrap();
        handles.push(handle);
    }

    for handle in handles {
        handle.join().unwrap()?;
    }

    Ok(())
}

fn main() {
    env_logger::init();

    let configs = match Vec::<VsockConfig>::try_from(VsockArgs::parse()) {
        Ok(c) => c,
        Err(e) => {
            println!("Error parsing arguments: {}", e);
            return;
        }
    };

    if let Err(e) = start_backend_servers(&configs) {
        error!("{e}");
        exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::File;
    use std::io::Write;
    use tempfile::tempdir;

    impl VsockArgs {
        fn from_args(guest_cid: u64, socket: &str, uds_path: &str, tx_buffer_size: u32) -> Self {
            VsockArgs {
                param: Some(VsockParam {
                    guest_cid,
                    socket: socket.to_string(),
                    uds_path: uds_path.to_string(),
                    tx_buffer_size,
                }),
                vm: None,
                config: None,
            }
        }
        fn from_file(config: &str) -> Self {
            VsockArgs {
                param: None,
                vm: None,
                config: Some(config.to_string()),
            }
        }
    }

    #[test]
    fn test_vsock_config_setup() {
        let test_dir = tempdir().expect("Could not create a temp test directory.");

        let socket_path = test_dir.path().join("vhost4.socket").display().to_string();
        let uds_path = test_dir.path().join("vm4.vsock").display().to_string();
        let args = VsockArgs::from_args(3, &socket_path, &uds_path, 64 * 1024);

        let configs = Vec::<VsockConfig>::try_from(args);
        assert!(configs.is_ok());

        let configs = configs.unwrap();
        assert_eq!(configs.len(), 1);

        let config = &configs[0];
        assert_eq!(config.get_guest_cid(), 3);
        assert_eq!(config.get_socket_path(), socket_path);
        assert_eq!(config.get_uds_path(), uds_path);
        assert_eq!(config.get_tx_buffer_size(), 64 * 1024);

        test_dir.close().unwrap();
    }

    #[test]
    fn test_vsock_config_setup_from_vm_args() {
        let test_dir = tempdir().expect("Could not create a temp test directory.");

        let socket_paths = [
            test_dir.path().join("vhost3.socket"),
            test_dir.path().join("vhost4.socket"),
            test_dir.path().join("vhost5.socket"),
        ];
        let uds_paths = [
            test_dir.path().join("vm3.vsock"),
            test_dir.path().join("vm4.vsock"),
            test_dir.path().join("vm5.vsock"),
        ];
        let params = format!(
            "--vm socket={vhost3_socket},uds_path={vm3_vsock} \
             --vm socket={vhost4_socket},uds-path={vm4_vsock},guest-cid=4,tx_buffer_size=65536 \
             --vm guest-cid=5,socket={vhost5_socket},uds_path={vm5_vsock},tx-buffer-size=32768",
            vhost3_socket = socket_paths[0].display(),
            vhost4_socket = socket_paths[1].display(),
            vhost5_socket = socket_paths[2].display(),
            vm3_vsock = uds_paths[0].display(),
            vm4_vsock = uds_paths[1].display(),
            vm5_vsock = uds_paths[2].display(),
        );

        let mut params = params.split_whitespace().collect::<Vec<&str>>();
        params.insert(0, ""); // to make the test binary name agnostic

        let args = VsockArgs::parse_from(params);

        let configs = Vec::<VsockConfig>::try_from(args);
        assert!(configs.is_ok());

        let configs = configs.unwrap();
        assert_eq!(configs.len(), 3);

        let config = configs.get(0).unwrap();
        assert_eq!(config.get_guest_cid(), 3);
        assert_eq!(
            config.get_socket_path(),
            socket_paths[0].display().to_string()
        );
        assert_eq!(config.get_uds_path(), uds_paths[0].display().to_string());
        assert_eq!(config.get_tx_buffer_size(), 65536);

        let config = configs.get(1).unwrap();
        assert_eq!(config.get_guest_cid(), 4);
        assert_eq!(
            config.get_socket_path(),
            socket_paths[1].display().to_string()
        );
        assert_eq!(config.get_uds_path(), uds_paths[1].display().to_string());
        assert_eq!(config.get_tx_buffer_size(), 65536);

        let config = configs.get(2).unwrap();
        assert_eq!(config.get_guest_cid(), 5);
        assert_eq!(
            config.get_socket_path(),
            socket_paths[2].display().to_string()
        );
        assert_eq!(config.get_uds_path(), uds_paths[2].display().to_string());
        assert_eq!(config.get_tx_buffer_size(), 32768);

        test_dir.close().unwrap();
    }

    #[test]
    fn test_vsock_config_setup_from_file() {
        let test_dir = tempdir().expect("Could not create a temp test directory.");

        let config_path = test_dir.path().join("config.yaml");
        let socket_path = test_dir.path().join("vhost4.socket");
        let uds_path = test_dir.path().join("vm4.vsock");

        let mut yaml = File::create(&config_path).unwrap();
        yaml.write_all(
            format!(
                "vms:
    - guest_cid: 4
      socket: {}
      uds_path: {}
      tx_buffer_size: 65536",
                socket_path.display(),
                uds_path.display(),
            )
            .as_bytes(),
        )
        .unwrap();
        let args = VsockArgs::from_file(&config_path.display().to_string());

        let configs = Vec::<VsockConfig>::try_from(args).unwrap();
        assert_eq!(configs.len(), 1);

        let config = &configs[0];
        assert_eq!(config.get_guest_cid(), 4);
        assert_eq!(config.get_socket_path(), socket_path.display().to_string());
        assert_eq!(config.get_uds_path(), uds_path.display().to_string());
        std::fs::remove_file(&config_path).unwrap();

        test_dir.close().unwrap();
    }

    #[test]
    fn test_vsock_server() {
        const CID: u64 = 3;
        const CONN_TX_BUF_SIZE: u32 = 64 * 1024;

        let test_dir = tempdir().expect("Could not create a temp test directory.");

        let vhost_socket_path = test_dir
            .path()
            .join("test_vsock_server.socket")
            .display()
            .to_string();
        let vsock_socket_path = test_dir
            .path()
            .join("test_vsock_server.vsock")
            .display()
            .to_string();

        let config = VsockConfig::new(CID, vhost_socket_path, vsock_socket_path, CONN_TX_BUF_SIZE);

        let cid_map: Arc<RwLock<CidMap>> = Arc::new(RwLock::new(HashMap::new()));

        let backend = Arc::new(VhostUserVsockBackend::new(config, cid_map).unwrap());

        let daemon = VhostUserDaemon::new(
            String::from("vhost-device-vsock"),
            backend.clone(),
            GuestMemoryAtomic::new(GuestMemoryMmap::new()),
        )
        .unwrap();

        let vring_workers = daemon.get_epoll_handlers();

        // VhostUserVsockBackend support a single thread that handles the TX and RX queues
        assert_eq!(backend.threads.len(), 1);

        assert_eq!(vring_workers.len(), backend.threads.len());

        test_dir.close().unwrap();
    }
}
