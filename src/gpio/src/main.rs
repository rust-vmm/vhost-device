// VIRTIO GPIO Emulation via vhost-user
//
// Copyright 2021 Linaro Ltd. All Rights Reserved.
//          Viresh Kumar <viresh.kumar@linaro.org>
//
// SPDX-License-Identifier: Apache-2.0

mod gpio;
mod vhu_gpio;

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

use gpio::{GpioController, GpioDevice, PhysDevice};
use vhu_gpio::VhostUserGpioBackend;

type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, PartialEq, ThisError)]
/// Errors related to low level GPIO helpers
pub enum Error {
    #[error("Invalid socket path")]
    SocketPathInvalid,
    #[error("Invalid socket count: {0}")]
    SocketCountInvalid(usize),
    #[error("Socket count ({0}) doesn't match device count {1}")]
    DeviceCountMismatch(usize, usize),
    #[error("Invalid device list")]
    DeviceListInvalid,
    #[error("Duplicate device detected: {0}")]
    DeviceDuplicate(u32),
    #[error("Failed while parsing to integer: {0:?}")]
    ParseFailure(ParseIntError),
    #[error("Failed to join threads")]
    FailedJoiningThreads,
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

impl TryFrom<ArgMatches> for GpioConfiguration {
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

        let devices = DeviceConfig::try_from(list)?;

        if devices.inner.len() != socket_count as usize {
            return Err(Error::DeviceCountMismatch(
                socket_count,
                devices.inner.len(),
            ));
        }

        Ok(GpioConfiguration {
            socket_path,
            socket_count,
            devices,
        })
    }
}

fn start_backend<D: 'static + GpioDevice + Send + Sync>(config: GpioConfiguration) -> Result<()> {
    let mut handles = Vec::new();

    for i in 0..config.socket_count {
        let socket = config.socket_path.to_owned() + &i.to_string();
        let device_num = config.devices.inner[i];

        let handle = spawn(move || loop {
            // A separate thread is spawned for each socket and can connect to a separate guest.
            // These are run in an infinite loop to not require the daemon to be restarted once a
            // guest exits.
            //
            // There isn't much value in complicating code here to return an error from the
            // threads, and so the code uses unwrap() instead. The panic on a thread won't cause
            // trouble to other threads/guests or the main() function and should be safe for the
            // daemon.
            let device = D::open(device_num).unwrap();
            let controller = GpioController::<D>::new(device).unwrap();
            let backend = Arc::new(RwLock::new(VhostUserGpioBackend::new(controller).unwrap()));
            let listener = Listener::new(socket.clone(), true).unwrap();

            let mut daemon = VhostUserDaemon::new(
                String::from("vhost-device-gpio-backend"),
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

    let yaml = load_yaml!("cli.yaml");
    let cmd_args = App::from(yaml).get_matches();
    let config = GpioConfiguration::try_from(cmd_args).unwrap();

    start_backend::<PhysDevice>(config)
}
