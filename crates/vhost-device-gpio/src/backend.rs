// VIRTIO GPIO Emulation via vhost-user
//
// Copyright 2022 Linaro Ltd. All Rights Reserved.
//          Viresh Kumar <viresh.kumar@linaro.org>
//
// SPDX-License-Identifier: Apache-2.0 or BSD-3-Clause

use log::{error, info, warn};
use std::num::ParseIntError;
use std::process::exit;
use std::sync::{Arc, RwLock};
use std::thread::{spawn, JoinHandle};

use clap::Parser;
use thiserror::Error as ThisError;
use vhost::{vhost_user, vhost_user::Listener};
use vhost_user_backend::VhostUserDaemon;
use vm_memory::{GuestMemoryAtomic, GuestMemoryMmap};

use crate::gpio::{GpioController, GpioDevice, PhysDevice};
use crate::vhu_gpio::VhostUserGpioBackend;

pub(crate) type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, ThisError)]
/// Errors related to low level GPIO helpers
pub(crate) enum Error {
    #[error("Invalid socket count: {0}")]
    SocketCountInvalid(usize),
    #[error("Socket count ({0}) doesn't match device count {1}")]
    DeviceCountMismatch(usize, usize),
    #[error("Duplicate device detected: {0}")]
    DeviceDuplicate(u32),
    #[error("Failed while parsing to integer: {0:?}")]
    ParseFailure(ParseIntError),
    #[error("Failed to join threads")]
    FailedJoiningThreads,
    #[error("Could not open gpio device: {0}")]
    CouldNotOpenDevice(crate::gpio::Error),
    #[error("Could not create gpio controller: {0}")]
    CouldNotCreateGpioController(crate::gpio::Error),
    #[error("Could not create gpio backend: {0}")]
    CouldNotCreateBackend(crate::vhu_gpio::Error),
    #[error("Could not create daemon: {0}")]
    CouldNotCreateDaemon(vhost_user_backend::Error),
}

#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
struct GpioArgs {
    /// Location of vhost-user Unix domain socket. This is suffixed by 0,1,2..socket_count-1.
    #[clap(short, long)]
    socket_path: String,

    /// Number of guests (sockets) to connect to.
    #[clap(short = 'c', long, default_value_t = 1)]
    socket_count: usize,

    /// List of GPIO devices, one for each guest, in the format <N1>[:<N2>]. The first entry is for
    /// Guest that connects to socket 0, next one for socket 1, and so on. Each device number here
    /// will be used to access the corresponding /dev/gpiochipX. Example, "-c 4 -l 3:4:6:1"
    #[clap(short = 'l', long)]
    device_list: String,
}

#[derive(Debug, PartialEq)]
pub(crate) struct DeviceConfig {
    inner: Vec<u32>,
}

impl DeviceConfig {
    fn new() -> Self {
        Self { inner: Vec::new() }
    }

    fn contains_device(&self, number: u32) -> bool {
        self.inner.iter().any(|elem| *elem == number)
    }

    fn push(&mut self, device: u32) -> Result<()> {
        if self.contains_device(device) {
            return Err(Error::DeviceDuplicate(device));
        }

        self.inner.push(device);
        Ok(())
    }
}

impl TryFrom<&str> for DeviceConfig {
    type Error = Error;

    fn try_from(list: &str) -> Result<Self> {
        let list: Vec<&str> = list.split(':').collect();
        let mut devices = DeviceConfig::new();

        for info in list.iter() {
            let number = info.parse::<u32>().map_err(Error::ParseFailure)?;
            devices.push(number)?;
        }
        Ok(devices)
    }
}

#[derive(PartialEq, Debug)]
struct GpioConfiguration {
    socket_path: String,
    socket_count: usize,
    devices: DeviceConfig,
}

impl TryFrom<GpioArgs> for GpioConfiguration {
    type Error = Error;

    fn try_from(args: GpioArgs) -> Result<Self> {
        if args.socket_count == 0 {
            return Err(Error::SocketCountInvalid(0));
        }

        let devices = DeviceConfig::try_from(args.device_list.as_str())?;

        if devices.inner.len() != args.socket_count {
            return Err(Error::DeviceCountMismatch(
                args.socket_count,
                devices.inner.len(),
            ));
        }

        Ok(GpioConfiguration {
            socket_path: args.socket_path,
            socket_count: args.socket_count,
            devices,
        })
    }
}

fn start_backend<D: 'static + GpioDevice + Send + Sync>(args: GpioArgs) -> Result<()> {
    let config = GpioConfiguration::try_from(args).unwrap();
    let mut handles = Vec::new();

    for i in 0..config.socket_count {
        let socket = config.socket_path.to_owned() + &i.to_string();
        let device_num = config.devices.inner[i];

        let handle: JoinHandle<Result<()>> = spawn(move || loop {
            // A separate thread is spawned for each socket and can connect to a separate guest.
            // These are run in an infinite loop to not require the daemon to be restarted once a
            // guest exits.
            //
            // There isn't much value in complicating code here to return an error from the
            // threads, and so the code uses unwrap() instead. The panic on a thread won't cause
            // trouble to other threads/guests or the main() function and should be safe for the
            // daemon.
            let device = D::open(device_num).map_err(Error::CouldNotOpenDevice)?;
            let controller =
                GpioController::<D>::new(device).map_err(Error::CouldNotCreateGpioController)?;
            let backend = Arc::new(RwLock::new(
                VhostUserGpioBackend::new(controller).map_err(Error::CouldNotCreateBackend)?,
            ));
            let listener = Listener::new(socket.clone(), true).unwrap();

            let mut daemon = VhostUserDaemon::new(
                String::from("vhost-device-gpio-backend"),
                backend.clone(),
                GuestMemoryAtomic::new(GuestMemoryMmap::new()),
            )
            .map_err(Error::CouldNotCreateDaemon)?;

            daemon.start(listener).unwrap();

            match daemon.wait() {
                Ok(()) => {
                    info!("Stopping cleanly.");
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
            backend.read().unwrap().exit_event.write(1).unwrap();
        });

        handles.push(handle);
    }

    for handle in handles {
        handle.join().map_err(|_| Error::FailedJoiningThreads)??;
    }

    Ok(())
}

pub(crate) fn gpio_init() {
    env_logger::init();

    if let Err(e) = start_backend::<PhysDevice>(GpioArgs::parse()) {
        error!("{e}");
        exit(1);
    }
}

#[cfg(test)]
mod tests {
    use assert_matches::assert_matches;

    use super::*;
    use crate::mock_gpio::MockGpioDevice;

    impl DeviceConfig {
        pub fn new_with(devices: Vec<u32>) -> Self {
            DeviceConfig { inner: devices }
        }
    }

    fn get_cmd_args(path: &str, devices: &str, count: usize) -> GpioArgs {
        GpioArgs {
            socket_path: path.to_string(),
            socket_count: count,
            device_list: devices.to_string(),
        }
    }

    #[test]
    fn test_gpio_device_config() {
        let mut config = DeviceConfig::new();

        config.push(5).unwrap();
        config.push(6).unwrap();

        assert_matches!(config.push(5).unwrap_err(), Error::DeviceDuplicate(5));
    }

    #[test]
    fn test_gpio_parse_failure() {
        let socket_name = "vgpio.sock";

        // Invalid device number
        let cmd_args = get_cmd_args(socket_name, "1:4d:5", 3);
        assert_matches!(
            GpioConfiguration::try_from(cmd_args).unwrap_err(),
            Error::ParseFailure(e) if e == "4d".parse::<u32>().unwrap_err()
        );

        // Zero socket count
        let cmd_args = get_cmd_args(socket_name, "1:4", 0);
        assert_matches!(
            GpioConfiguration::try_from(cmd_args).unwrap_err(),
            Error::SocketCountInvalid(0)
        );

        // Duplicate client address: 4
        let cmd_args = get_cmd_args(socket_name, "1:4:5:6:4", 5);
        assert_matches!(
            GpioConfiguration::try_from(cmd_args).unwrap_err(),
            Error::DeviceDuplicate(4)
        );

        // Device count mismatch
        let cmd_args = get_cmd_args(socket_name, "1:4:5:6", 5);
        assert_matches!(
            GpioConfiguration::try_from(cmd_args).unwrap_err(),
            Error::DeviceCountMismatch(5, 4)
        );
    }

    #[test]
    fn test_gpio_parse_successful() {
        let socket_name = "vgpio.sock";

        // Match expected and actual configuration
        let cmd_args = get_cmd_args(socket_name, "1:4:32:21:5", 5);
        let config = GpioConfiguration::try_from(cmd_args).unwrap();

        let expected_devices = DeviceConfig::new_with(vec![1, 4, 32, 21, 5]);
        let expected_config = GpioConfiguration {
            socket_count: 5,
            socket_path: String::from(socket_name),
            devices: expected_devices,
        };

        assert_eq!(config, expected_config);
    }

    #[test]
    fn test_gpio_fail_listener() {
        // This will fail the listeners and thread will panic.
        let socket_name = "~/path/not/present/gpio";
        let cmd_args = get_cmd_args(socket_name, "1:4:3:5", 4);

        assert_matches!(
            start_backend::<MockGpioDevice>(cmd_args).unwrap_err(),
            Error::FailedJoiningThreads
        );
    }
}
