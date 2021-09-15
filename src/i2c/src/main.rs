// VIRTIO I2C Emulation via vhost-user
//
// Copyright 2021 Linaro Ltd. All Rights Reserved.
//          Viresh Kumar <viresh.kumar@linaro.org>
//
// SPDX-License-Identifier: Apache-2.0

mod i2c;
mod vhu_i2c;

use std::convert::TryFrom;
use std::num::ParseIntError;
use std::sync::{Arc, RwLock};
use std::thread::spawn;

use clap::{load_yaml, App, ArgMatches};
use vhost::{vhost_user, vhost_user::Listener};
use vhost_user_backend::VhostUserDaemon;
use vm_memory::{GuestMemoryAtomic, GuestMemoryMmap};

use i2c::{DeviceConfig, I2cConfiguration, I2cDevice, I2cMap, PhysDevice, MAX_I2C_VDEV};
use vhu_i2c::VhostUserI2cBackend;

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
        let busses: Vec<&str> = list.split(',').collect();

        let mut devices = Vec::new();

        for businfo in busses.iter() {
            let list: Vec<&str> = businfo.split(':').collect();
            let bus_addr = list[0].parse::<u32>().map_err(|_| "Invalid bus address")?;
            let bus_devices = list[1..]
                .iter()
                .map(|str| str.parse::<usize>())
                .collect::<Result<Vec<usize>, ParseIntError>>()
                .map_err(|_| "Invalid device")?;

            // Check if any of the devices has a size > the maximum allowed one.
            if bus_devices
                .iter()
                .filter(|addr| **addr > MAX_I2C_VDEV)
                .count()
                > 0
            {
                // TODO: if needed we can show which one is actually not respecting the max size.
                return Err("Invalid addr.".to_string());
            }

            devices.push(DeviceConfig {
                adapter_no: bus_addr,
                addr: bus_devices,
            })
        }

        Ok(I2cConfiguration {
            socket_path,
            socket_count,
            devices,
        })
    }
}

fn start_daemon<D: 'static + I2cDevice + Send + Sync>(
    backend: Arc<RwLock<VhostUserI2cBackend<D>>>,
    listener: Listener,
) -> bool {
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
        Err(vhost_user_backend::Error::HandleRequest(vhost_user::Error::PartialMessage)) => {
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

    false
}

fn start_backend<D: I2cDevice + Sync + Send + 'static>(
    cmd_args: ArgMatches,
    start_daemon: fn(Arc<RwLock<VhostUserI2cBackend<D>>>, Listener) -> bool,
) -> Result<(), String> {
    let mut handles = Vec::new();

    let i2c_config = I2cConfiguration::try_from(cmd_args)?;

    // The same i2c_map structure instance is shared between all the guests
    let i2c_map = Arc::new(
        I2cMap::<D>::new(&i2c_config.devices)
            .map_err(|e| format!("Failed to create i2c_map ({})", e))?,
    );

    for i in 0..i2c_config.socket_count {
        let socket = i2c_config.socket_path.to_owned() + &i.to_string();
        let i2c_map = i2c_map.clone();

        let handle = spawn(move || loop {
            let backend = Arc::new(RwLock::new(
                VhostUserI2cBackend::new(i2c_map.clone()).unwrap(),
            ));
            let listener = Listener::new(socket.clone(), true).unwrap();

            if start_daemon(backend, listener) {
                break;
            }
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

    start_backend::<PhysDevice>(cmd_args, start_daemon)
}

#[cfg(test)]
mod tests {
    use super::*;
    use i2c::tests::I2cMockAdapter;

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

    fn mock_start_daemon<D: I2cDevice>(
        _backend: Arc<RwLock<VhostUserI2cBackend<D>>>,
        _listener: Listener,
    ) -> bool {
        true
    }
    /*
    #[test]
    fn test_backend_single() {
        let cmd_args = get_cmd_args("vi2c.sock_single", "1:4,2:32:21,5:5:23", 0);
        assert!(start_backend::<I2cMockAdapter>(cmd_args, mock_start_daemon).is_ok());
    }

    #[test]
    fn test_backend_multiple() {
        let cmd_args = get_cmd_args("vi2c.sock", "1:4,2:32:21,5:5:23", 5);
        assert!(start_backend::<I2cMockAdapter>(cmd_args, mock_start_daemon).is_ok());
    }

    #[test]
    fn test_backend_failure() {
        let cmd_args = get_cmd_args("vi2c.sock_failure", "1:4d", 5);
        assert!(start_backend::<I2cMockAdapter>(cmd_args, mock_start_daemon).is_err());
    }

    #[test]
    fn test_backend_failure_duplicate_device4() {
        let cmd_args = get_cmd_args("vi2c.sock_duplicate", "1:4,2:32:21,5:4:23", 5);
        assert!(start_backend::<I2cMockAdapter>(cmd_args, mock_start_daemon).is_err());
    }
     */
}
