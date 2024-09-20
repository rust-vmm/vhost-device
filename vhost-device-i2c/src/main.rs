// VIRTIO I2C Emulation via vhost-user
//
// Copyright 2021 Linaro Ltd. All Rights Reserved.
//          Viresh Kumar <viresh.kumar@linaro.org>
//
// SPDX-License-Identifier: Apache-2.0 or BSD-3-Clause

mod i2c;
mod vhu_i2c;

use core::fmt;
use log::error;
use std::num::ParseIntError;
use std::path::PathBuf;
use std::process::exit;
use std::sync::{Arc, RwLock};
use std::thread::{spawn, JoinHandle};

use clap::Parser;
use thiserror::Error as ThisError;
use vhost_user_backend::VhostUserDaemon;
use vm_memory::{GuestMemoryAtomic, GuestMemoryMmap};

use i2c::{I2cDevice, I2cMap, PhysDevice, MAX_I2C_VDEV};
use vhu_i2c::VhostUserI2cBackend;

type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, ThisError)]
/// Errors related to low level i2c helpers
enum Error {
    #[error("Invalid socket count: {0}")]
    SocketCountInvalid(usize),
    #[error("Failed while parsing adapter identifier")]
    CoulodNotFindAdapterIdentifier,
    #[error("Duplicate adapter detected: {0}")]
    AdapterDuplicate(AdapterIdentifier),
    #[error("Invalid client address: {0}")]
    ClientAddressInvalid(u16),
    #[error("Duplicate client address detected: {0}")]
    ClientAddressDuplicate(u16),
    #[error("Low level I2c failure: {0:?}")]
    I2cFailure(i2c::Error),
    #[error("Failed while parsing to integer: {0:?}")]
    ParseFailure(ParseIntError),
    #[error("Invalid path `{0}` given: {1}")]
    PathParseFailure(PathBuf, String),
    #[error("Could not create backend: {0}")]
    CouldNotCreateBackend(vhu_i2c::Error),
    #[error("Could not create daemon: {0}")]
    CouldNotCreateDaemon(vhost_user_backend::Error),
    #[error("Fatal error: {0}")]
    ServeFailed(vhost_user_backend::Error),
}

#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
struct I2cArgs {
    /// Location of vhost-user Unix domain socket. This is suffixed by 0,1,2..socket_count-1.
    #[clap(short, long, value_name = "SOCKET")]
    socket_path: PathBuf,

    /// Number of guests (sockets) to connect to.
    #[clap(short = 'c', long, default_value_t = 1)]
    socket_count: usize,

    /// List of I2C bus and clients in format
    /// <bus-name>:<client_addr>[:<client_addr>][,<bus-name>:<client_addr>[:<client_addr>]].
    #[clap(short = 'l', long)]
    device_list: String,
}

#[derive(Debug, PartialEq)]
enum AdapterIdentifier {
    Name(String),
    Number(u32),
}

impl fmt::Display for AdapterIdentifier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Name(name) => write!(f, "adapter_name: {}", name),
            Self::Number(no) => write!(f, "adapter_no:: {}", no),
        }
    }
}

#[derive(Debug, PartialEq)]
struct DeviceConfig {
    adapter: AdapterIdentifier,
    addr: Vec<u16>,
}

impl DeviceConfig {
    fn new_with_no(no: u32) -> Result<Self> {
        Ok(Self {
            adapter: AdapterIdentifier::Number(no),
            addr: Vec::new(),
        })
    }

    fn new_with_name(name: &str) -> Result<Self> {
        Ok(Self {
            adapter: AdapterIdentifier::Name(name.trim().to_string()),
            addr: Vec::new(),
        })
    }

    fn push(&mut self, addr: u16) -> Result<()> {
        if addr as usize > MAX_I2C_VDEV {
            return Err(Error::ClientAddressInvalid(addr));
        }

        if self.addr.contains(&addr) {
            return Err(Error::ClientAddressDuplicate(addr));
        }

        self.addr.push(addr);
        Ok(())
    }
}

#[derive(Debug, PartialEq)]
struct AdapterConfig {
    inner: Vec<DeviceConfig>,
}

impl AdapterConfig {
    const fn new() -> Self {
        Self { inner: Vec::new() }
    }

    fn contains_adapter(&self, adapter: &DeviceConfig) -> bool {
        self.inner
            .iter()
            .any(|elem| elem.adapter == adapter.adapter)
    }

    fn contains_addr(&self, addr: u16) -> bool {
        self.inner.iter().any(|elem| elem.addr.contains(&addr))
    }

    fn push(&mut self, device: DeviceConfig) -> Result<()> {
        if self.contains_adapter(&device) {
            return Err(Error::AdapterDuplicate(device.adapter));
        }

        for addr in device.addr.iter() {
            if self.contains_addr(*addr) {
                return Err(Error::ClientAddressDuplicate(*addr));
            }
        }

        self.inner.push(device);
        Ok(())
    }
}

impl TryFrom<&str> for AdapterConfig {
    type Error = Error;

    fn try_from(list: &str) -> Result<Self> {
        let adapter_identifiers: Vec<&str> = list.split(',').collect();
        let mut devices = Self::new();

        for identifier_info in adapter_identifiers.iter() {
            let list: Vec<&str> = identifier_info.split(':').collect();
            let identifier = list.first().ok_or(Error::CoulodNotFindAdapterIdentifier)?;
            let mut adapter = match identifier.parse::<u32>() {
                Ok(no) => DeviceConfig::new_with_no(no)?,
                Err(_) => DeviceConfig::new_with_name(identifier)?,
            };

            for device_str in list[1..].iter() {
                let addr = device_str.parse::<u16>().map_err(Error::ParseFailure)?;
                adapter.push(addr)?;
            }

            devices.push(adapter)?;
        }
        Ok(devices)
    }
}

#[derive(PartialEq, Debug)]
struct I2cConfiguration {
    socket_path: PathBuf,
    socket_count: usize,
    devices: AdapterConfig,
}

impl TryFrom<I2cArgs> for I2cConfiguration {
    type Error = Error;

    fn try_from(args: I2cArgs) -> Result<Self> {
        use std::borrow::Cow;

        if args.socket_count == 0 {
            return Err(Error::SocketCountInvalid(0));
        }

        let absolute_socket_path = if !args.socket_path.is_absolute() {
            if let Ok(cwd) = std::env::current_dir() {
                Cow::Owned(cwd.join(&args.socket_path))
            } else {
                Cow::Borrowed(&args.socket_path)
            }
        } else {
            Cow::Borrowed(&args.socket_path)
        };

        if let Some(parent_dir) = absolute_socket_path.parent() {
            if !parent_dir.exists() {
                return Err(Error::PathParseFailure(
                    args.socket_path.clone(),
                    format!(
                        "Parent directory `{}` does not exist.",
                        parent_dir.display()
                    ),
                ));
            }
            if !parent_dir.is_dir() {
                return Err(Error::PathParseFailure(
                    args.socket_path.clone(),
                    format!("`{}` is a file, not a directory.", parent_dir.display()),
                ));
            }
        }

        let devices = AdapterConfig::try_from(args.device_list.trim())?;
        Ok(Self {
            socket_path: args.socket_path,
            socket_count: args.socket_count,
            devices,
        })
    }
}

impl I2cConfiguration {
    pub fn generate_socket_paths(&self) -> Vec<PathBuf> {
        let socket_file_name = self
            .socket_path
            .file_name()
            .expect("socket_path has no filename.");
        let socket_file_parent = self
            .socket_path
            .parent()
            .expect("socket_path has no parent directory.");

        let make_socket_path = |i: usize| -> PathBuf {
            let mut file_name = socket_file_name.to_os_string();
            file_name.push(std::ffi::OsStr::new(&i.to_string()));
            socket_file_parent.join(&file_name)
        };
        (0..self.socket_count).map(make_socket_path).collect()
    }
}

fn start_backend<D: 'static + I2cDevice + Send + Sync>(args: I2cArgs) -> Result<()> {
    let config = I2cConfiguration::try_from(args)?;

    // The same i2c_map structure instance is shared between all the guests
    let i2c_map = Arc::new(I2cMap::<D>::new(&config.devices).map_err(Error::I2cFailure)?);

    let mut handles = Vec::new();

    for socket in config.generate_socket_paths() {
        let i2c_map = i2c_map.clone();

        let handle: JoinHandle<Result<()>> = spawn(move || loop {
            // A separate thread is spawned for each socket and can connect to a separate guest.
            // These are run in an infinite loop to not require the daemon to be restarted once a
            // guest exits.
            //
            // There isn't much value in complicating code here to return an error from the
            // threads, and so the code uses unwrap() instead. The panic on a thread won't cause
            // trouble to other threads/guests or the main() function and should be safe for the
            // daemon.
            let backend = Arc::new(RwLock::new(
                VhostUserI2cBackend::new(i2c_map.clone()).map_err(Error::CouldNotCreateBackend)?,
            ));

            let mut daemon = VhostUserDaemon::new(
                String::from("vhost-device-i2c-backend"),
                backend.clone(),
                GuestMemoryAtomic::new(GuestMemoryMmap::new()),
            )
            .map_err(Error::CouldNotCreateDaemon)?;

            daemon.serve(&socket).map_err(Error::ServeFailed)?;
        });

        handles.push(handle);
    }

    for handle in handles {
        handle.join().map_err(std::panic::resume_unwind).unwrap()?;
    }

    Ok(())
}

fn main() {
    env_logger::init();

    if let Err(e) = start_backend::<PhysDevice>(I2cArgs::parse()) {
        error!("{e}");
        exit(1);
    }
}

#[cfg(test)]
mod tests {
    use assert_matches::assert_matches;
    use std::path::Path;

    use vhost::vhost_user::Listener;

    use super::*;
    use crate::i2c::tests::DummyDevice;

    impl DeviceConfig {
        pub fn new_with(adaper_id: AdapterIdentifier, addr: Vec<u16>) -> Self {
            Self {
                adapter: adaper_id,
                addr,
            }
        }
    }

    impl AdapterConfig {
        pub fn new_with(devices: Vec<DeviceConfig>) -> Self {
            Self { inner: devices }
        }
    }

    impl I2cArgs {
        fn from_args(path: &str, devices: &str, count: usize) -> Self {
            Self {
                socket_path: path.into(),
                socket_count: count,
                device_list: devices.to_string(),
            }
        }
    }

    #[test]
    fn test_device_config() {
        let id_name = AdapterIdentifier::Name("i915 gmbus dpd".to_string());
        let mut config = DeviceConfig::new_with(id_name, Vec::new());
        assert_eq!(
            config,
            DeviceConfig {
                adapter: AdapterIdentifier::Name("i915 gmbus dpd".to_string()),
                addr: Vec::new()
            }
        );

        let id_no = AdapterIdentifier::Number(11);
        config = DeviceConfig::new_with(id_no, Vec::new());
        assert_eq!(
            config,
            DeviceConfig {
                adapter: AdapterIdentifier::Number(11),
                addr: Vec::new()
            }
        );

        let invalid_addr = (MAX_I2C_VDEV + 1) as u16;

        config.push(5).unwrap();
        config.push(6).unwrap();

        assert_matches!(
            config.push(invalid_addr).unwrap_err(),
            Error::ClientAddressInvalid(a) if a == invalid_addr
        );

        assert_matches!(
            config.push(5).unwrap_err(),
            Error::ClientAddressDuplicate(5)
        );
    }

    #[test]
    fn test_parse_failure() {
        let socket_name = "vi2c.sock";
        let invalid_socket_name = " ./vi2c.sock";

        // Space in filenames
        let cmd_args = I2cArgs::from_args(invalid_socket_name, " 1:4", 1);
        // " ./vi2c.sock" will fail because " ." does not exist, while "." exists in every UNIX
        // directory.
        assert_matches!(
            I2cConfiguration::try_from(cmd_args).unwrap_err(),
            Error::PathParseFailure(p, msg) if p == Path::new(invalid_socket_name) && msg.starts_with("Parent directory `") && msg.ends_with("` does not exist.")
        );

        // Invalid client address
        let cmd_args = I2cArgs::from_args(socket_name, "1:4d", 5);
        assert_matches!(
            I2cConfiguration::try_from(cmd_args).unwrap_err(),
            Error::ParseFailure(e) if e == "4d".parse::<u16>().unwrap_err()
        );

        // Zero socket count
        let cmd_args = I2cArgs::from_args(socket_name, "1:4", 0);
        assert_matches!(
            I2cConfiguration::try_from(cmd_args).unwrap_err(),
            Error::SocketCountInvalid(0)
        );

        // Duplicate client address: 4
        let cmd_args = I2cArgs::from_args(socket_name, "1:4,2:32:21,5:4:23", 5);
        assert_matches!(
            I2cConfiguration::try_from(cmd_args).unwrap_err(),
            Error::ClientAddressDuplicate(4)
        );
    }

    #[test]
    fn test_parse_successful() {
        let socket_name = "vi2c.sock";

        // Whitespace prefix/suffix in device list argument
        let cmd_args = I2cArgs::from_args(socket_name, " 1:4 ", 1);
        let config = I2cConfiguration::try_from(cmd_args).unwrap();
        Listener::new(config.socket_path, true).unwrap();

        // Valid configuration with number as identifier
        let cmd_args = I2cArgs::from_args(socket_name, "1:4,2:32:21,5:5:23", 5);
        let config = I2cConfiguration::try_from(cmd_args).unwrap();

        let expected_devices = AdapterConfig::new_with(vec![
            DeviceConfig::new_with(AdapterIdentifier::Number(1), vec![4]),
            DeviceConfig::new_with(AdapterIdentifier::Number(2), vec![32, 21]),
            DeviceConfig::new_with(AdapterIdentifier::Number(5), vec![5, 23]),
        ]);

        let expected_config = I2cConfiguration {
            socket_count: 5,
            socket_path: socket_name.into(),
            devices: expected_devices,
        };

        assert_eq!(config, expected_config);

        // Valid configuration with name as identifier
        let cmd_args = I2cArgs::from_args(socket_name, "bus1:4,bus2:32:21,bus5:5:23", 5);
        let config = I2cConfiguration::try_from(cmd_args).unwrap();
        let expected_devices = AdapterConfig::new_with(vec![
            DeviceConfig::new_with(AdapterIdentifier::Name("bus1".to_string()), vec![4]),
            DeviceConfig::new_with(AdapterIdentifier::Name("bus2".to_string()), vec![32, 21]),
            DeviceConfig::new_with(AdapterIdentifier::Name("bus5".to_string()), vec![5, 23]),
        ]);
        let expected_config = I2cConfiguration {
            socket_count: 5,
            socket_path: socket_name.into(),
            devices: expected_devices,
        };

        assert_eq!(config, expected_config);

        //Valid configuration with mixing name and number identifier
        let cmd_args = I2cArgs::from_args(socket_name, "123asd:4,11:32:21,23:5:23", 5);
        let config = I2cConfiguration::try_from(cmd_args).unwrap();
        let expected_devices = AdapterConfig::new_with(vec![
            DeviceConfig::new_with(AdapterIdentifier::Name("123asd".to_string()), vec![4]),
            DeviceConfig::new_with(AdapterIdentifier::Number(11), vec![32, 21]),
            DeviceConfig::new_with(AdapterIdentifier::Number(23), vec![5, 23]),
        ]);
        let expected_config = I2cConfiguration {
            socket_count: 5,
            socket_path: socket_name.into(),
            devices: expected_devices,
        };

        assert_eq!(config, expected_config);

        // Socket paths are what we expect them to be.
        assert_eq!(
            config.generate_socket_paths(),
            vec![
                Path::new("vi2c.sock0").to_path_buf(),
                Path::new("vi2c.sock1").to_path_buf(),
                Path::new("vi2c.sock2").to_path_buf(),
                Path::new("vi2c.sock3").to_path_buf(),
                Path::new("vi2c.sock4").to_path_buf()
            ]
        );
    }

    #[test]
    fn test_i2c_map_duplicate_device4() {
        let mut config = AdapterConfig::new();

        config
            .push(DeviceConfig::new_with(
                AdapterIdentifier::Number(1),
                vec![4],
            ))
            .unwrap();
        config
            .push(DeviceConfig::new_with(
                AdapterIdentifier::Number(2),
                vec![32, 21],
            ))
            .unwrap();

        assert_matches!(
            config
                .push(DeviceConfig::new_with(
                    AdapterIdentifier::Number(5),
                    vec![4, 23]
                ))
                .unwrap_err(),
            Error::ClientAddressDuplicate(4)
        );
    }

    #[test]
    fn test_duplicated_adapter_no() {
        let mut config = AdapterConfig::new();

        config
            .push(DeviceConfig::new_with(
                AdapterIdentifier::Number(1),
                vec![4],
            ))
            .unwrap();
        config
            .push(DeviceConfig::new_with(
                AdapterIdentifier::Number(5),
                vec![10, 23],
            ))
            .unwrap();

        assert_matches!(
            config
                .push(DeviceConfig::new_with(AdapterIdentifier::Number(1), vec![32, 21]))
                .unwrap_err(),
            Error::AdapterDuplicate(n) if n == AdapterIdentifier::Number(1)
        );
    }

    #[test]
    fn test_duplicated_adapter_name() {
        let mut config = AdapterConfig::new();

        config
            .push(DeviceConfig::new_with(
                AdapterIdentifier::Name("bus1".to_string()),
                vec![4],
            ))
            .unwrap();
        config
            .push(DeviceConfig::new_with(
                AdapterIdentifier::Name("bus5".to_string()),
                vec![10, 23],
            ))
            .unwrap();

        assert_matches!(
            config
                .push(DeviceConfig::new_with(AdapterIdentifier::Name("bus5".to_string()), vec![32, 21]))
                .unwrap_err(),
            Error::AdapterDuplicate(n) if n == AdapterIdentifier::Name("bus5".to_string())
        );
    }

    #[test]
    fn test_fail_listener() {
        // This will fail the listeners and thread will panic.
        let socket_name = "~/path/not/present/i2c";
        let cmd_args = I2cArgs::from_args(socket_name, "1:4,3:5", 5);

        assert_matches!(
            start_backend::<DummyDevice>(cmd_args).unwrap_err(),
            Error::PathParseFailure(_, _)
        );
    }
}
