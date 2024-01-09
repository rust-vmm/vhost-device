// VIRTIO CAN Emulation via vhost-user
//
// Copyright 2023-2024 VIRTUAL OPEN SYSTEMS SAS. All Rights Reserved.
//          Timos Ampelikiotis <t.ampelikiotis@virtualopensystems.com>
//
// SPDX-License-Identifier: Apache-2.0 or BSD-3-Clause

mod backend;
mod can;
mod vhu_can;
mod virtio_can;

use clap::Parser;
use log::{error, info};
use socketcan::{CanSocket, Socket};
use std::convert::TryFrom;
use std::path::PathBuf;
use std::process::exit;

pub(crate) type Result<T> = std::result::Result<T, Error>;
use crate::backend::{start_backend, Error, VuCanConfig};

#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
struct CanArgs {
    /// Location of vhost-user Unix domain socket. This is suffixed by 0,1,2..socket_count-1.
    #[clap(short, long, value_name = "SOCKET")]
    socket_path: PathBuf,

    /// A can device name to be used for reading (ex. vcan, can0, can1, ... etc.)
    #[clap(short = 'd', long)]
    can_devices: String,

    /// Number of guests (sockets) to connect to.
    #[clap(short = 'c', long, default_value_t = 1)]
    socket_count: u32,
}

fn check_can_devices(can_devices: &[String]) -> Result<()> {
    for can_dev in can_devices {
        if CanSocket::open(can_dev).is_err() {
            info!("There is no interface with the following name {}", can_dev);
            return Err(Error::CouldNotFindCANDevs);
        }
    }
    Ok(())
}

fn parse_can_devices(input: &CanArgs) -> Result<Vec<String>> {
    let can_devices_vec: Vec<&str> = input.can_devices.split_whitespace().collect();
    let can_devices: Vec<_> = can_devices_vec.iter().map(|x| x.to_string()).collect();

    if (can_devices.len() as u32) != input.socket_count {
        info!(
            "Number of CAN/FD devices ({}) not equal with socket count {}",
            input.can_devices, input.socket_count
        );
        return Err(Error::SocketCountInvalid(
            input.socket_count.try_into().unwrap(),
        ));
    }

    match check_can_devices(&can_devices) {
        Ok(_) => Ok(can_devices),
        Err(_) => Err(Error::CouldNotFindCANDevs),
    }
}

impl TryFrom<CanArgs> for VuCanConfig {
    type Error = Error;

    fn try_from(args: CanArgs) -> Result<Self> {
        if args.socket_count == 0 {
            return Err(Self::Error::SocketCountInvalid(0));
        }

        let can_devices = match parse_can_devices(&args) {
            Ok(can_devs) => can_devs,
            Err(e) => return Err(e),
        };

        Ok(VuCanConfig {
            socket_path: args.socket_path,
            socket_count: args.socket_count,
            can_devices,
        })
    }
}

fn main() {
    env_logger::init();
    if let Err(e) = VuCanConfig::try_from(CanArgs::parse()).and_then(start_backend) {
        error!("{e}");
        exit(1);
    }
}
