// SPDX-FileCopyrightText: Red Hat, Inc.
// SPDX-License-Identifier: Apache-2.0
// Based on implementation of other devices here, Copyright by Linaro Ltd.

mod devices;
mod scmi;
mod vhu_scmi;

use std::{
    process::exit,
    sync::{Arc, RwLock},
};

use clap::Parser;
use itertools::Itertools;
use log::{debug, error, info, warn};

use vhost::vhost_user;
use vhost::vhost_user::Listener;
use vhost_user_backend::VhostUserDaemon;
use vhu_scmi::VuScmiBackend;
use vm_memory::{GuestMemoryAtomic, GuestMemoryMmap};

type Result<T> = std::result::Result<T, String>;

#[derive(Parser)]
struct ScmiArgs {
    // Location of vhost-user Unix domain socket.
    #[clap(short, long, help = "vhost-user socket to use")]
    socket_path: String,
    // Specification of SCMI devices to create.
    #[clap(
        short,
        long,
        help = "Devices to expose (use `help' device for more info)"
    )]
    #[arg(num_args(1..))]
    device: Vec<String>,
}

// [(NAME, [(PROPERTY, VALUE), ...]), ...]
type DeviceDescription = Vec<(String, DeviceProperties)>;
type DeviceProperties = Vec<(String, String)>;

pub struct VuScmiConfig {
    socket_path: String,
    devices: DeviceDescription,
}

impl TryFrom<ScmiArgs> for VuScmiConfig {
    type Error = String;

    fn try_from(cmd_args: ScmiArgs) -> Result<Self> {
        let socket_path = cmd_args.socket_path.trim().to_string();
        let device_iterator = cmd_args.device.iter();
        let mut devices: DeviceDescription = vec![];
        for d in device_iterator {
            let mut split = d.split(',');
            let name = split.next().unwrap().to_owned();
            let mut properties: DeviceProperties = vec![];
            for s in split {
                if let Some((key, value)) = s.split('=').collect_tuple() {
                    properties.push((key.to_owned(), value.to_owned()));
                } else {
                    return Result::Err(format!("Invalid device {name} property format: {s}"));
                }
            }
            devices.push((name, properties));
        }
        Ok(Self {
            socket_path,
            devices,
        })
    }
}

fn start_backend(config: VuScmiConfig) -> Result<()> {
    loop {
        debug!("Starting backend");
        // TODO: Print a nice error message on backend configuration failure.
        let backend = Arc::new(RwLock::new(VuScmiBackend::new(&config).unwrap()));
        let listener = Listener::new(config.socket_path.clone(), true).unwrap();
        let mut daemon = VhostUserDaemon::new(
            "vhost-device-scmi".to_owned(),
            backend.clone(),
            GuestMemoryAtomic::new(GuestMemoryMmap::new()),
        )
        .unwrap();

        daemon.start(listener).unwrap();

        match daemon.wait() {
            Ok(()) => {
                info!("Stopping cleanly");
            }
            Err(vhost_user_backend::Error::HandleRequest(vhost_user::Error::PartialMessage)) => {
                info!(
                    "vhost-user connection closed with partial message.
                       If the VM is shutting down, this is expected behavior;
                       otherwise, it might be a bug."
                );
            }
            Err(e) => {
                warn!("Error running daemon: {:?}", e);
            }
        }

        // No matter the result, we need to shut down the worker thread.
        backend.read().unwrap().exit_event.write(1).unwrap();
        debug!("Finishing backend");
    }
}

fn main() {
    env_logger::init();
    match VuScmiConfig::try_from(ScmiArgs::parse()) {
        Ok(config) => {
            if let Err(error) = start_backend(config) {
                error!("{error}");
                exit(1);
            }
        }
        Err(message) => {
            println!("{message}");
            // TODO: print help
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_command_line() {
        let path = "/foo/scmi.sock".to_owned();
        let params_string = format!(
            "binary \
                     --device dummy \
                     -s {path} \
                     --device fake,name=foo,prop=value \
                     -d fake,name=bar"
        );
        let params: Vec<&str> = params_string.split_whitespace().collect();
        let args: ScmiArgs = Parser::parse_from(params);
        let config = VuScmiConfig::try_from(args).unwrap();
        assert_eq!(config.socket_path, path);
        let devices = vec![
            ("dummy".to_owned(), vec![]),
            (
                "fake".to_owned(),
                vec![
                    ("name".to_owned(), "foo".to_owned()),
                    ("prop".to_owned(), "value".to_owned()),
                ],
            ),
            (
                "fake".to_owned(),
                vec![("name".to_owned(), "bar".to_owned())],
            ),
        ];
        assert_eq!(config.devices, devices);
    }
}
