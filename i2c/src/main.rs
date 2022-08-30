// VIRTIO I2C Emulation via vhost-user
//
// Copyright 2021 Linaro Ltd. All Rights Reserved.
//          Viresh Kumar <viresh.kumar@linaro.org>
//
// SPDX-License-Identifier: Apache-2.0

mod i2c;
mod vhu_i2c;

use log::{info, warn};
use std::num::ParseIntError;
use std::sync::{Arc, RwLock};
use std::thread::spawn;

use clap::Parser;
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

#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
struct I2cArgs {
    /// Location of vhost-user Unix domain socket. This is suffixed by 0,1,2..socket_count-1.
    #[clap(short, long)]
    socket_path: String,

    /// Number of guests (sockets) to connect to.
    #[clap(short = 'c', long, default_value_t = 1)]
    socket_count: usize,

    /// List of I2C bus and clients in format
    /// <bus>:<client_addr>[:<client_addr>][,<bus>:<client_addr>[:<client_addr>]].
    #[clap(short = 'l', long)]
    device_list: String,
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

impl TryFrom<I2cArgs> for I2cConfiguration {
    type Error = Error;

    fn try_from(args: I2cArgs) -> Result<Self> {
        if args.socket_count == 0 {
            return Err(Error::SocketCountInvalid(0));
        }

        let devices = AdapterConfig::try_from(args.device_list.trim())?;
        Ok(I2cConfiguration {
            socket_path: args.socket_path.trim().to_string(),
            socket_count: args.socket_count,
            devices,
        })
    }
}

fn start_backend<D: 'static + I2cDevice + Send + Sync>(args: I2cArgs) -> Result<()> {
    let config = I2cConfiguration::try_from(args).unwrap();

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
    env_logger::init();

    start_backend::<PhysDevice>(I2cArgs::parse())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::i2c::tests::DummyDevice;

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

    impl I2cArgs {
        fn from_args(path: &str, devices: &str, count: usize) -> I2cArgs {
            I2cArgs {
                socket_path: path.to_string(),
                socket_count: count,
                device_list: devices.to_string(),
            }
        }
    }

    #[test]
    fn test_device_config() {
        let mut config = DeviceConfig::new(5);
        let invalid_addr = (MAX_I2C_VDEV + 1) as u16;

        config.push(5).unwrap();
        config.push(6).unwrap();

        assert_eq!(
            config.push(invalid_addr).unwrap_err(),
            Error::ClientAddressInvalid(invalid_addr)
        );

        assert_eq!(
            config.push(5).unwrap_err(),
            Error::ClientAddressDuplicate(5)
        );
    }

    #[test]
    fn test_parse_failure() {
        let socket_name = "vi2c.sock";

        // Invalid bus_addr
        let cmd_args = I2cArgs::from_args(socket_name, "1:4,3d:5", 5);
        assert_eq!(
            I2cConfiguration::try_from(cmd_args).unwrap_err(),
            Error::ParseFailure("3d".parse::<u32>().unwrap_err())
        );

        // Invalid client address
        let cmd_args = I2cArgs::from_args(socket_name, "1:4d", 5);
        assert_eq!(
            I2cConfiguration::try_from(cmd_args).unwrap_err(),
            Error::ParseFailure("4d".parse::<u16>().unwrap_err())
        );

        // Zero socket count
        let cmd_args = I2cArgs::from_args(socket_name, "1:4", 0);
        assert_eq!(
            I2cConfiguration::try_from(cmd_args).unwrap_err(),
            Error::SocketCountInvalid(0)
        );

        // Duplicate client address: 4
        let cmd_args = I2cArgs::from_args(socket_name, "1:4,2:32:21,5:4:23", 5);
        assert_eq!(
            I2cConfiguration::try_from(cmd_args).unwrap_err(),
            Error::ClientAddressDuplicate(4)
        );
    }

    #[test]
    fn test_parse_successful() {
        let socket_name = "vi2c.sock";

        // Space before and after the device list and socket name
        let cmd_args = I2cArgs::from_args(" ./vi2c.sock", " 1:4 ", 1);
        let config = I2cConfiguration::try_from(cmd_args).unwrap();
        Listener::new(config.socket_path, true).unwrap();

        // Valid configuration
        let cmd_args = I2cArgs::from_args(socket_name, "1:4,2:32:21,5:5:23", 5);
        let config = I2cConfiguration::try_from(cmd_args).unwrap();

        let expected_devices = AdapterConfig::new_with(vec![
            DeviceConfig::new_with(1, vec![4]),
            DeviceConfig::new_with(2, vec![32, 21]),
            DeviceConfig::new_with(5, vec![5, 23]),
        ]);

        let expected_config = I2cConfiguration {
            socket_count: 5,
            socket_path: String::from(socket_name),
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

    #[test]
    fn test_fail_listener() {
        // This will fail the listeners and thread will panic.
        let socket_name = "~/path/not/present/i2c";
        let cmd_args = I2cArgs::from_args(socket_name, "1:4,3:5", 5);

        assert_eq!(
            start_backend::<DummyDevice>(cmd_args).unwrap_err(),
            Error::FailedJoiningThreads
        );
    }
}
