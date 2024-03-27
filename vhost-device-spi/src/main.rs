// VIRTIO SPI Emulation via vhost-user
//
// Copyright (c) 2024 Qualcomm Innovation Center, Inc. All rights reserved.
//          Haixu Cui <quic_haixcui@quicinc.com>
//
// SPDX-License-Identifier: Apache-2.0 or BSD-3-Clause

mod spi;
mod vhu_spi;
mod virtio_spi;

use std::{
    process::exit,
    sync::{Arc, RwLock},
    thread::{spawn, JoinHandle},
};

use clap::Parser;
use log::error;
use thiserror::Error as ThisError;
use vhost_user_backend::VhostUserDaemon;
use vm_memory::{GuestMemoryAtomic, GuestMemoryMmap};

use spi::{PhysDevice, SpiController, SpiDevice};
use vhu_spi::VhostUserSpiBackend;

type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, ThisError)]
/// Errors related to low level spi helpers
pub(crate) enum Error {
    #[error("Invalid socket count: {0}")]
    SocketCountInvalid(usize),
    #[error("Low level Spi failure: {0:?}")]
    SpiFailure(spi::Error),
    #[error("Could not create backend: {0}")]
    CouldNotCreateBackend(vhu_spi::Error),
    #[error("Could not create daemon: {0}")]
    CouldNotCreateDaemon(vhost_user_backend::Error),
    #[error("Fatal error: {0}")]
    ServeFailed(vhost_user_backend::Error),
}

#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
struct SpiArgs {
    /// Location of vhost-user Unix domain socket. This is suffixed by 0,1,2..socket_count-1.
    #[clap(short, long)]
    socket_path: String,

    /// Number of guests (sockets) to connect to.
    #[clap(short = 'c', long, default_value_t = 1)]
    socket_count: usize,

    /// SPI device full path
    #[clap(short = 'l', long)]
    device: String,
}

#[derive(PartialEq, Debug)]
struct SpiConfiguration {
    socket_path: String,
    socket_count: usize,
    device: String,
}

impl SpiConfiguration {
    fn try_from(args: SpiArgs) -> Result<Self> {
        if args.socket_count == 0 {
            return Err(Error::SocketCountInvalid(0));
        }

        Ok(SpiConfiguration {
            socket_path: args.socket_path.trim().to_string(),
            socket_count: args.socket_count,
            device: args.device.trim().to_string(),
        })
    }
}

fn start_backend<D: 'static + SpiDevice + Send + Sync>(args: SpiArgs) -> Result<()> {
    let config = SpiConfiguration::try_from(args)?;

    let spi_dev = D::open(&config.device).map_err(Error::SpiFailure)?;

    let spi_ctrl = Arc::new(SpiController::<D>::new(spi_dev).map_err(Error::SpiFailure)?);

    let mut handles = Vec::new();

    for i in 0..config.socket_count {
        let socket = config.socket_path.to_owned() + &i.to_string();
        let spi_ctrl = spi_ctrl.clone();

        let handle: JoinHandle<Result<()>> = spawn(move || loop {
            // A separate thread is spawned for each socket and can connect to a separate guest.
            // These are run in an infinite loop to not require the daemon to be restarted once a
            // guest exits.
            //
            // There isn't much value in complicating code here to return an error from the
            // threads, and so the code uses unwrap() instead. The panic on a thread won't cause
            // trouble to other threads/guests or the main() function and should be safe for the
            // daemon.
            let backend = Arc::new(RwLock::new(
                VhostUserSpiBackend::new(spi_ctrl.clone()).map_err(Error::CouldNotCreateBackend)?,
            ));

            let mut daemon = VhostUserDaemon::new(
                String::from("vhost-device-spi-backend"),
                backend.clone(),
                GuestMemoryAtomic::new(GuestMemoryMmap::new()),
            )
            .map_err(Error::CouldNotCreateDaemon)?;

            daemon.serve(&socket).map_err(Error::ServeFailed)?;
        });

        handles.push(handle);
    }

    for handle in handles {
        handle.join().map_err(std::panic::resume_unwind).unwrap()?;
    }

    Ok(())
}

fn main() {
    env_logger::init();

    if let Err(e) = start_backend::<PhysDevice>(SpiArgs::parse()) {
        error!("{e}");
        exit(1);
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use assert_matches::assert_matches;

    use super::*;
    use crate::spi::tests::DummyDevice;

    impl SpiArgs {
        fn from_args(path: &str, device: &str, count: usize) -> SpiArgs {
            SpiArgs {
                socket_path: path.to_string(),
                socket_count: count,
                device: device.to_string(),
            }
        }
    }

    #[test]
    fn test_parse_failure() {
        let socket_name = "vspi.sock";

        // Zero socket count
        let cmd_args = SpiArgs::from_args(socket_name, "spidev0.0", 0);
        assert_matches!(
            SpiConfiguration::try_from(cmd_args).unwrap_err(),
            Error::SocketCountInvalid(0)
        );
    }

    #[test]
    fn test_fail_listener() {
        // This will fail the listeners and thread will panic.
        let socket_name = "~/path/not/present/spi";
        let cmd_args = SpiArgs::from_args(socket_name, "spidev0.0", 1);

        assert_matches!(
            start_backend::<DummyDevice>(cmd_args).unwrap_err(),
            Error::ServeFailed(_)
        );
    }
}
