// VIRTIO I2C Emulation via vhost-user
//
// Copyright 2021 Linaro Ltd. All Rights Reserved.
//          Viresh Kumar <viresh.kumar@linaro.org>
//
// SPDX-License-Identifier: Apache-2.0

mod i2c;
mod vhu_i2c;

use log::{info, warn};
use std::convert::TryFrom;
use std::num::ParseIntError;
use std::sync::{Arc, RwLock};
use std::thread::spawn;

use clap::{load_yaml, App, ArgMatches};
use thiserror::Error as ThisError;
use vhost::{vhost_user, vhost_user::Listener};
use vhost_user_backend::VhostUserDaemon;
use vm_memory::{GuestMemoryAtomic, GuestMemoryMmap};

use i2c::{I2cDevice, I2cMap, PhysDevice, MAX_I2C_VDEV};
use vhu_i2c::VhostUserI2cBackend;

type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, PartialEq, ThisError)]
/// Errors related to low level i2c helpers
pub enum Error {
    #[error("Invalid socket path")]
    SocketPathInvalid,
    #[error("Invalid socket count: {0}")]
    SocketCountInvalid(usize),
    #[error("Invalid device list")]
    DeviceListInvalid,
    #[error("Duplicate adapter detected: {0}")]
    AdapterDuplicate(u32),
    #[error("Invalid client address: {0}")]
    ClientAddressInvalid(u16),
    #[error("Duplicate client address detected: {0}")]
    ClientAddressDuplicate(u16),
    #[error("Low level I2c failure: {0:?}")]
    I2cFailure(i2c::Error),
    #[error("Failed while parsing to integer: {0:?}")]
    ParseFailure(ParseIntError),
    #[error("Failed to join threads")]
    FailedJoiningThreads,
}

#[derive(Debug, PartialEq)]
struct DeviceConfig {
    adapter_no: u32,
    addr: Vec<u16>,
}

impl DeviceConfig {
    fn new(adapter_no: u32) -> Self {
        DeviceConfig {
            adapter_no,
            addr: Vec::new(),
        }
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
pub(crate) struct AdapterConfig {
    inner: Vec<DeviceConfig>,
}

impl AdapterConfig {
    fn new() -> Self {
        Self { inner: Vec::new() }
    }

    fn contains_adapter_no(&self, adapter_no: u32) -> bool {
        self.inner.iter().any(|elem| elem.adapter_no == adapter_no)
    }

    fn contains_addr(&self, addr: u16) -> bool {
        self.inner.iter().any(|elem| elem.addr.contains(&addr))
    }

    fn push(&mut self, device: DeviceConfig) -> Result<()> {
        if self.contains_adapter_no(device.adapter_no) {
            return Err(Error::AdapterDuplicate(device.adapter_no));
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
        let busses: Vec<&str> = list.split(',').collect();
        let mut devices = AdapterConfig::new();

        for businfo in busses.iter() {
            let list: Vec<&str> = businfo.split(':').collect();
            let bus_addr = list[0].parse::<u32>().map_err(Error::ParseFailure)?;
            let mut adapter = DeviceConfig::new(bus_addr);

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
    socket_path: String,
    socket_count: usize,
    devices: AdapterConfig,
}

impl TryFrom<ArgMatches> for I2cConfiguration {
    type Error = Error;

    fn try_from(cmd_args: ArgMatches) -> Result<Self> {
        let socket_path = cmd_args
            .value_of("socket_path")
            .ok_or(Error::SocketPathInvalid)?
            .to_string();

        let socket_count = cmd_args
            .value_of("socket_count")
            .unwrap_or("1")
            .parse::<usize>()
            .map_err(Error::ParseFailure)?;

        if socket_count == 0 {
            return Err(Error::SocketCountInvalid(0));
        }

        let list = cmd_args
            .value_of("devices")
            .ok_or(Error::DeviceListInvalid)?;
        let devices = AdapterConfig::try_from(list)?;
        Ok(I2cConfiguration {
            socket_path,
            socket_count,
            devices,
        })
    }
}

fn start_backend<D: 'static + I2cDevice + Send + Sync>(config: I2cConfiguration) -> Result<()> {
    // The same i2c_map structure instance is shared between all the guests
    let i2c_map = Arc::new(I2cMap::<D>::new(&config.devices).map_err(Error::I2cFailure)?);

    let mut handles = Vec::new();

    for i in 0..config.socket_count {
        let socket = config.socket_path.to_owned() + &i.to_string();
        let i2c_map = i2c_map.clone();

        let handle = spawn(move || loop {
            // A separate thread is spawned for each socket and can connect to a separate guest.
            // These are run in an infinite loop to not require the daemon to be restarted once a
            // guest exits.
            //
            // There isn't much value in complicating code here to return an error from the
            // threads, and so the code uses unwrap() instead. The panic on a thread won't cause
            // trouble to other threads/guests or the main() function and should be safe for the
            // daemon.
            let backend = Arc::new(RwLock::new(
                VhostUserI2cBackend::new(i2c_map.clone()).unwrap(),
            ));
            let listener = Listener::new(socket.clone(), true).unwrap();

            let mut daemon = VhostUserDaemon::new(
                String::from("vhost-device-i2c-backend"),
                backend.clone(),
                GuestMemoryAtomic::new(GuestMemoryMmap::new()),
            )
            .unwrap();

            daemon.start(listener).unwrap();

            match daemon.wait() {
                Ok(()) => {
                    info!("Stopping cleanly.");
                }
                Err(vhost_user_backend::Error::HandleRequest(
                    vhost_user::Error::PartialMessage,
                )) => {
                    info!("vhost-user connection closed with partial message. If the VM is shutting down, this is expected behavior; otherwise, it might be a bug.");
                }
                Err(e) => {
                    warn!("Error running daemon: {:?}", e);
                }
            }

            // No matter the result, we need to shut down the worker thread.
            backend.read().unwrap().exit_event.write(1).unwrap();
        });

        handles.push(handle);
    }

    for handle in handles {
        handle.join().map_err(|_| Error::FailedJoiningThreads)?;
    }

    Ok(())
}

fn main() -> Result<()> {
    let yaml = load_yaml!("cli.yaml");
    let cmd_args = App::from(yaml).get_matches();

    let config = I2cConfiguration::try_from(cmd_args).unwrap();
    start_backend::<PhysDevice>(config)
}

#[cfg(test)]
mod tests {
    use super::*;

    impl DeviceConfig {
        pub fn new_with(adapter_no: u32, addr: Vec<u16>) -> Self {
            DeviceConfig { adapter_no, addr }
        }
    }

    impl AdapterConfig {
        pub fn new_with(devices: Vec<DeviceConfig>) -> Self {
            AdapterConfig { inner: devices }
        }
    }

    fn get_cmd_args(name: Option<&str>, devices: &str, count: Option<&str>) -> ArgMatches {
        let mut args = vec!["prog", "-l", devices];
        let yaml = load_yaml!("cli.yaml");
        let app = App::from(yaml);

        if let Some(name) = name {
            args.extend_from_slice(&["-s", &name]);
        }

        if let Some(count) = count {
            args.extend_from_slice(&["-c", &count]);
        }
        app.try_get_matches_from(args).unwrap()
    }

    #[test]
    fn test_parse_failure() {
        let socket_name = Some("vi2c.sock");

        // Invalid bus_addr
        let cmd_args = get_cmd_args(socket_name, "1:4,3d:5", Some("5"));
        assert_eq!(
            I2cConfiguration::try_from(cmd_args).unwrap_err(),
            Error::ParseFailure("3d".parse::<u32>().unwrap_err())
        );

        // Invalid client address
        let cmd_args = get_cmd_args(socket_name, "1:4d", Some("5"));
        assert_eq!(
            I2cConfiguration::try_from(cmd_args).unwrap_err(),
            Error::ParseFailure("4d".parse::<u16>().unwrap_err())
        );

        // Invalid socket path
        let cmd_args = get_cmd_args(None, "1:4d", Some("5"));
        assert_eq!(
            I2cConfiguration::try_from(cmd_args).unwrap_err(),
            Error::SocketPathInvalid
        );

        // Invalid socket count
        let cmd_args = get_cmd_args(socket_name, "1:4", Some("1d"));
        assert_eq!(
            I2cConfiguration::try_from(cmd_args).unwrap_err(),
            Error::ParseFailure("1d".parse::<u16>().unwrap_err())
        );

        // Zero socket count
        let cmd_args = get_cmd_args(socket_name, "1:4", Some("0"));
        assert_eq!(
            I2cConfiguration::try_from(cmd_args).unwrap_err(),
            Error::SocketCountInvalid(0)
        );

        // Duplicate client address: 4
        let cmd_args = get_cmd_args(socket_name, "1:4,2:32:21,5:4:23", Some("5"));
        assert_eq!(
            I2cConfiguration::try_from(cmd_args).unwrap_err(),
            Error::ClientAddressDuplicate(4)
        );
    }

    #[test]
    fn test_parse_successful() {
        let socket_name = Some("vi2c.sock");

        // Missing socket count, default (1) should be used.
        let cmd_args = get_cmd_args(socket_name, "1:4,2:32:21,5:5:23", None);
        let config = I2cConfiguration::try_from(cmd_args).unwrap();
        assert_eq!(config.socket_count, 1);

        let cmd_args = get_cmd_args(socket_name, "1:4,2:32:21,5:5:23", Some("5"));
        let config = I2cConfiguration::try_from(cmd_args).unwrap();

        let expected_devices = AdapterConfig::new_with(vec![
            DeviceConfig::new_with(1, vec![4]),
            DeviceConfig::new_with(2, vec![32, 21]),
            DeviceConfig::new_with(5, vec![5, 23]),
        ]);

        let expected_config = I2cConfiguration {
            socket_count: 5,
            socket_path: String::from(socket_name.unwrap()),
            devices: expected_devices,
        };

        assert_eq!(config, expected_config);
    }

    #[test]
    fn test_i2c_map_duplicate_device4() {
        assert_eq!(
            AdapterConfig::try_from("1:4,2:32:21,5:4:23").unwrap_err(),
            Error::ClientAddressDuplicate(4)
        );
    }

    #[test]
    fn test_duplicated_adapter_no() {
        assert_eq!(
            AdapterConfig::try_from("1:4,1:32:21,5:10:23").unwrap_err(),
            Error::AdapterDuplicate(1)
        );
    }
}
