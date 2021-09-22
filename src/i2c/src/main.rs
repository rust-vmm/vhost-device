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

use crate::i2c::DeviceConfig;
use i2c::{AdapterConfig, I2cDevice, I2cMap, PhysDevice};
use vhu_i2c::VhostUserI2cBackend;

#[derive(PartialEq, Debug)]
struct I2cConfiguration {
    socket_path: String,
    socket_count: usize,
    devices: AdapterConfig,
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
                    .map_err(|_| "Invalid device addr: {}")?;
                adapter.push(addr)?;
            }

            devices.push(adapter)?;
        }
        Ok(devices)
    }
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

    fn get_cmd_args(name: &str, devices: &str, count: u32) -> ArgMatches {
        let yaml = load_yaml!("cli.yaml");
        let app = App::from(yaml);

        if count != 0 {
            app.try_get_matches_from(vec![
                "prog",
                "-s",
                name,
                "-l",
                devices,
                "-c",
                &count.to_string(),
            ])
            .unwrap()
        } else {
            app.try_get_matches_from(vec!["prog", "-s", name, "-l", devices])
                .unwrap()
        }
    }

    #[test]
    fn test_parse_failure() {
        let cmd_args = get_cmd_args("vi2c.sock_failure", "1:4d", 5);
        // TODO: Check against the actual error instead of `is_err`.
        assert!(I2cConfiguration::try_from(cmd_args).is_err());

        let cmd_args = get_cmd_args("vi2c.sock_duplicate", "1:4,2:32:21,5:4:23", 5);
        // TODO: Check against the actual error instead of `is_err`.
        assert!(I2cConfiguration::try_from(cmd_args).is_err());
    }

    #[test]
    fn test_parse_successful() {
        let cmd_args = get_cmd_args("vi2c.sock_single", "1:4,2:32:21,5:5:23", 5);
        let config = I2cConfiguration::try_from(cmd_args).unwrap();

        let expected_devices = AdapterConfig::new_with(vec![
            DeviceConfig::new_with(1, vec![4]),
            DeviceConfig::new_with(2, vec![32, 21]),
            DeviceConfig::new_with(5, vec![5, 23]),
        ]);

        let expected_config = I2cConfiguration {
            socket_count: 5,
            socket_path: String::from("vi2c.sock_single"),
            devices: expected_devices,
        };

        assert_eq!(config, expected_config);
    }
}
