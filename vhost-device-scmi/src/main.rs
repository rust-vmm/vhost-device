// SPDX-FileCopyrightText: Red Hat, Inc.
// SPDX-License-Identifier: Apache-2.0
// Based on implementation of other devices here, Copyright by Linaro Ltd.

//! vhost-user daemon implementation for
//! [System Control and Management Interface](https://developer.arm.com/Architectures/System%20Control%20and%20Management%20Interface)
//! (SCMI).
//!
//! Currently, the mandatory parts of the following SCMI protocols are implemented:
//!
//! - base
//! - sensor management
//!
//! As for sensor management, support for industrial I/O (IIO) Linux devices
//! and a fake sensor device is implemented.
//!
//! The daemon listens on a socket that is specified using `--socket-path`
//! command line option.  Usually at least one exposed device is specified,
//! which is done using `--device` command line option.  It can be used more
//! than once, for different devices.  `--help-devices` lists the available
//! devices and their options.
//!
//! The daemon normally logs info and higher messages to the standard error
//! output.  To log more messages, you can set `RUST_LOG` environment variable,
//! e.g. to `debug`.
//!
//! Here is an example command line invocation of the daemon:
//!
//! ```sh
//! RUST_LOG=debug vhost-device-scmi \
//!   --socket ~/tmp/scmi.sock \
//!   --device iio,path=/sys/bus/iio/devices/iio:device0,channel=in_accel
//! ```

mod devices;
mod scmi;
mod vhu_scmi;

use devices::common::{print_devices_help, DeviceDescription, DeviceProperties};

use std::{
    process::exit,
    sync::{Arc, RwLock},
};

use clap::{CommandFactory, Parser};
use itertools::Itertools;
use log::{debug, error};

use vhost_user_backend::VhostUserDaemon;
use vhu_scmi::VuScmiBackend;
use vm_memory::{GuestMemoryAtomic, GuestMemoryMmap};

type Result<T> = std::result::Result<T, String>;

#[derive(Parser)]
struct ScmiArgs {
    // Location of vhost-user Unix domain socket.
    // Required, unless one of the --help options is used.
    #[clap(short, long, help = "vhost-user socket to use (required)")]
    socket_path: Option<String>,
    // Specification of SCMI devices to create.
    #[clap(short, long, help = "Devices to expose")]
    #[arg(num_args(1..))]
    device: Vec<String>,
    #[clap(long, help = "Print help on available devices")]
    help_devices: bool,
}

pub struct VuScmiConfig {
    socket_path: String,
    devices: DeviceDescription,
}

impl TryFrom<ScmiArgs> for VuScmiConfig {
    type Error = String;

    fn try_from(cmd_args: ScmiArgs) -> Result<Self> {
        if cmd_args.socket_path.is_none() {
            return Result::Err("Required argument socket-path was not provided".to_string());
        }
        let socket_path = cmd_args.socket_path.unwrap().trim().to_string();
        let mut devices: DeviceDescription = vec![];
        let device_iterator = cmd_args.device.iter();
        for d in device_iterator {
            let mut split = d.split(',');
            let name = split.next().unwrap().to_owned();
            let mut properties = vec![];
            for s in split {
                if let Some((key, value)) = s.split('=').collect_tuple() {
                    properties.push((key.to_owned(), value.to_owned()));
                } else {
                    return Result::Err(format!("Invalid device {name} property format: {s}"));
                }
            }
            devices.push((name, DeviceProperties::new(properties)));
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
        let backend_instance = VuScmiBackend::new(&config);
        if let Err(error) = backend_instance {
            return Err(error.to_string());
        }

        let backend = Arc::new(RwLock::new(backend_instance.unwrap()));
        let mut daemon = VhostUserDaemon::new(
            "vhost-device-scmi".to_owned(),
            backend.clone(),
            GuestMemoryAtomic::new(GuestMemoryMmap::new()),
        )
        .unwrap();

        daemon
            .serve(&config.socket_path)
            .map_err(|e| format!("{e}"))?;
        debug!("Finishing backend");
    }
}

fn process_args(args: ScmiArgs) -> Option<ScmiArgs> {
    if args.help_devices {
        print_devices_help();
        None
    } else {
        Some(args)
    }
}

fn print_help(message: &String) {
    println!("{message}\n");
    let mut command = ScmiArgs::command();
    command.print_help().unwrap();
}

fn main() {
    env_logger::init();
    if let Some(args) = process_args(ScmiArgs::parse()) {
        match VuScmiConfig::try_from(args) {
            Ok(config) => {
                if let Err(error) = start_backend(config) {
                    error!("{error}");
                    println!("{error}");
                    exit(1);
                }
            }
            Err(message) => print_help(&message),
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
        let args: ScmiArgs = process_args(Parser::parse_from(params)).unwrap();
        let config = VuScmiConfig::try_from(args).unwrap();
        assert_eq!(config.socket_path, path);
        let devices = vec![
            ("dummy".to_owned(), DeviceProperties::new(vec![])),
            (
                "fake".to_owned(),
                DeviceProperties::new(vec![
                    ("name".to_owned(), "foo".to_owned()),
                    ("prop".to_owned(), "value".to_owned()),
                ]),
            ),
            (
                "fake".to_owned(),
                DeviceProperties::new(vec![("name".to_owned(), "bar".to_owned())]),
            ),
        ];
        assert_eq!(config.devices, devices);
    }

    #[test]
    fn test_device_help_processing() {
        let params_string = "binary --help-devices".to_string();
        let params: Vec<&str> = params_string.split_whitespace().collect();
        let args: ScmiArgs = Parser::parse_from(params);
        let processed = process_args(args);
        assert!(processed.is_none());
    }

    #[test]
    fn test_help() {
        // No way known to me to capture print_help() output from clap.
        print_help(&String::from("test"));
    }
}
