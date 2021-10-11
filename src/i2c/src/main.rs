// VIRTIO I2C Emulation via vhost-user
//
// Copyright 2021 Linaro Ltd. All Rights Reserved.
//          Viresh Kumar <viresh.kumar@linaro.org>
//
// SPDX-License-Identifier: Apache-2.0

mod i2c;
mod vhu_i2c;

use std::convert::TryFrom;
use std::sync::{Arc, RwLock};
use std::thread::spawn;

use clap::{load_yaml, App, ArgMatches};
use vhost::{vhost_user, vhost_user::Listener};
use vhost_user_backend::VhostUserDaemon;
use vm_memory::{GuestMemoryAtomic, GuestMemoryMmap};

use i2c::{I2cDevice, I2cMap, PhysDevice, MAX_I2C_VDEV};
use vhu_i2c::VhostUserI2cBackend;

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

    fn push(&mut self, addr: u16) -> std::result::Result<(), String> {
        if addr as usize > MAX_I2C_VDEV {
            return Err(format!("Invalid address: {} (> maximum allowed)", addr));
        }

        if self.addr.contains(&addr) {
            return Err(format!("Address already in use: {}", addr));
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

    fn push(&mut self, device: DeviceConfig) -> std::result::Result<(), String> {
        if self.contains_adapter_no(device.adapter_no) {
            return Err("Duplicated adapter number".to_string());
        }

        for addr in device.addr.iter() {
            if self.contains_addr(*addr) {
                return Err(format!("Address already in use: {}", addr));
            }
        }

        self.inner.push(device);
        Ok(())
    }
}

impl TryFrom<&str> for AdapterConfig {
    type Error = String;

    fn try_from(list: &str) -> Result<Self, Self::Error> {
        let busses: Vec<&str> = list.split(',').collect();
        let mut devices = AdapterConfig::new();

        for businfo in busses.iter() {
            let list: Vec<&str> = businfo.split(':').collect();
            let bus_addr = list[0].parse::<u32>().map_err(|_| "Invalid bus address")?;
            let mut adapter = DeviceConfig::new(bus_addr);

            for device_str in list[1..].iter() {
                let addr = device_str
                    .parse::<u16>()
                    .map_err(|_| "Invalid device addr")?;
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
    type Error = String;

    fn try_from(cmd_args: ArgMatches) -> Result<Self, Self::Error> {
        let socket_path = cmd_args
            .value_of("socket_path")
            .ok_or("Invalid socket path")?
            .to_string();

        let socket_count = cmd_args
            .value_of("socket_count")
            .unwrap_or("1")
            .parse::<usize>()
            .map_err(|_| "Invalid socket_count")?;

        if socket_count == 0 {
            return Err("Socket count can't be 0".to_string());
        }

        let list = cmd_args.value_of("devices").ok_or("Invalid devices list")?;
        let devices = AdapterConfig::try_from(list)?;
        Ok(I2cConfiguration {
            socket_path,
            socket_count,
            devices,
        })
    }
}

fn start_backend<D: 'static + I2cDevice + Send + Sync>(
    config: I2cConfiguration,
) -> Result<(), String> {
    // The same i2c_map structure instance is shared between all the guests
    let i2c_map = Arc::new(
        I2cMap::<D>::new(&config.devices)
            .map_err(|e| format!("Failed to create i2c_map ({})", e))?,
    );

    let mut handles = Vec::new();

    for i in 0..config.socket_count {
        let socket = config.socket_path.to_owned() + &i.to_string();
        let i2c_map = i2c_map.clone();

        let handle = spawn(move || loop {
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
                    println!("Stopping cleanly.");
                }
                Err(vhost_user_backend::Error::HandleRequest(
                    vhost_user::Error::PartialMessage,
                )) => {
                    println!("vhost-user connection closed with partial message. If the VM is shutting down, this is expected behavior; otherwise, it might be a bug.");
                }
                Err(e) => {
                    println!("Error running daemon: {:?}", e);
                }
            }

            // No matter the result, we need to shut down the worker thread.
            backend
                .read()
                .unwrap()
                .exit_event
                .write(1)
                .expect("Shutting down worker thread");
        });

        handles.push(handle);
    }

    for handle in handles {
        handle.join().map_err(|_| "Failed to join threads")?;
    }

    Ok(())
}

fn main() -> Result<(), String> {
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

    fn get_cmd_args(name: &str, devices: &str, count: Option<u32>) -> ArgMatches {
        let mut args = vec!["prog", "-s", name, "-l", devices];
        let yaml = load_yaml!("cli.yaml");
        let app = App::from(yaml);
        let socket_count_str;

        if let Some(count) = count {
            socket_count_str = count.to_string();
            args.extend_from_slice(&["-c", &socket_count_str]);
        }
        app.try_get_matches_from(args).unwrap()
    }

    #[test]
    fn test_parse_failure() {
        let socket_name = "vi2c.sock";

        // Invalid device list
        let cmd_args = get_cmd_args(socket_name, "1:4d", Some(5));
        assert_eq!(
            I2cConfiguration::try_from(cmd_args).unwrap_err(),
            "Invalid device addr"
        );

        // Invalid socket count
        let cmd_args = get_cmd_args(socket_name, "1:4", Some(0));
        assert_eq!(
            I2cConfiguration::try_from(cmd_args).unwrap_err(),
            "Socket count can't be 0"
        );

        // Duplicate client address: 4
        let cmd_args = get_cmd_args(socket_name, "1:4,2:32:21,5:4:23", Some(5));
        assert_eq!(
            I2cConfiguration::try_from(cmd_args).unwrap_err(),
            "Address already in use: 4"
        );
    }

    #[test]
    fn test_parse_successful() {
        let socket_name = "vi2c.sock";

        // Missing socket count, default (1) should be used.
        let cmd_args = get_cmd_args(socket_name, "1:4,2:32:21,5:5:23", None);
        let config = I2cConfiguration::try_from(cmd_args).unwrap();
        assert_eq!(config.socket_count, 1);

        let cmd_args = get_cmd_args(socket_name, "1:4,2:32:21,5:5:23", Some(5));
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
}
