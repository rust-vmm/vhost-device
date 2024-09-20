// VIRTIO SPI Emulation via vhost-user
//
// Copyright (c) 2024 Qualcomm Innovation Center, Inc. All rights reserved.
//          Haixu Cui <quic_haixcui@quicinc.com>
//
// SPDX-License-Identifier: Apache-2.0 or BSD-3-Clause

mod linux_spi;
mod spi;
mod vhu_spi;
mod virtio_spi;

use std::{
    any::Any,
    collections::HashMap,
    num::NonZeroUsize,
    path::PathBuf,
    process::exit,
    sync::{Arc, RwLock},
    thread,
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
enum Error {
    #[error("SPI device file doesn't exists or can't be accessed")]
    AccessDeviceFailure(spi::Error),
    #[error("Could not create backend: {0}")]
    CouldNotCreateBackend(vhu_spi::Error),
    #[error("Could not create daemon: {0}")]
    CouldNotCreateDaemon(vhost_user_backend::Error),
    #[error("Fatal error: {0}")]
    ServeFailed(vhost_user_backend::Error),
    #[error("Thread `{0}` panicked")]
    ThreadPanic(String, Box<dyn Any + Send>),
}

#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
struct SpiArgs {
    /// Location of vhost-user Unix domain socket. This is suffixed by 0,1,2..socket_count-1.
    #[clap(short, long)]
    socket_path: PathBuf,

    /// Number of guests (sockets) to connect to.
    #[clap(short = 'c', long, default_value_t = NonZeroUsize::new(1).unwrap())]
    socket_count: NonZeroUsize,

    /// SPI device full path
    #[clap(short = 'l', long)]
    device: PathBuf,
}

#[derive(PartialEq, Debug)]
struct SpiConfiguration {
    socket_path: PathBuf,
    socket_count: usize,
    device: PathBuf,
}

impl SpiConfiguration {
    fn from(args: SpiArgs) -> Result<Self> {
        Ok(Self {
            socket_path: args.socket_path,
            socket_count: args.socket_count.get(),
            device: args.device,
        })
    }
}

impl SpiConfiguration {
    pub fn generate_socket_paths(&self) -> Vec<PathBuf> {
        let socket_file_name = self
            .socket_path
            .file_name()
            .expect("socket_path has no filename.");
        let socket_file_parent = self
            .socket_path
            .parent()
            .expect("socket_path has no parent directory.");

        let make_socket_path = |i: usize| -> PathBuf {
            let mut file_name = socket_file_name.to_os_string();
            file_name.push(std::ffi::OsStr::new(&i.to_string()));
            socket_file_parent.join(&file_name)
        };
        (0..self.socket_count).map(make_socket_path).collect()
    }
}

pub(crate) fn start_backend_server<D: 'static + SpiDevice + Send + Sync>(
    socket: PathBuf,
    device: PathBuf,
) -> Result<()> {
    loop {
        let spi_dev = D::open(&device).map_err(Error::AccessDeviceFailure)?;
        let spi_ctrl =
            Arc::new(SpiController::<D>::new(spi_dev).map_err(Error::AccessDeviceFailure)?);

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
    }
}

fn start_backend<D: 'static + SpiDevice + Send + Sync>(args: SpiArgs) -> Result<()> {
    let config = SpiConfiguration::from(args)?;

    let mut handles = HashMap::new();

    let (senders, receiver) = std::sync::mpsc::channel();

    for (thread_id, socket) in config.generate_socket_paths().into_iter().enumerate() {
        let name = format!("vhu-vsock-spi-{:?}", thread_id);

        let sender = senders.clone();

        let device_ref = config.device.clone();

        let handle = thread::Builder::new()
            .name(name.clone())
            .spawn(move || {
                let result =
                    std::panic::catch_unwind(move || start_backend_server::<D>(socket, device_ref));

                sender.send(thread_id).unwrap();

                result.map_err(|e| Error::ThreadPanic(name, e))?
            })
            .unwrap();

        handles.insert(thread_id, handle);
    }

    while !handles.is_empty() {
        let thread_id = receiver.recv().unwrap();
        handles
            .remove(&thread_id)
            .unwrap()
            .join()
            .map_err(std::panic::resume_unwind)
            .unwrap()?;
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
    use std::path::Path;

    use super::*;
    use crate::spi::tests::DummyDevice;

    impl SpiArgs {
        fn from_args(path: &str, device: &str, count: usize) -> SpiArgs {
            SpiArgs {
                socket_path: PathBuf::from(path),
                socket_count: NonZeroUsize::new(count)
                    .expect("Socket count must be a non-zero value"),
                device: PathBuf::from(device),
            }
        }
    }

    #[test]
    fn test_parse_successful() {
        let socket_name = "vspi.sock";
        let device_path = "/dev/spidev0.0";

        let cmd_args = SpiArgs::from_args(socket_name, device_path, 3);

        let config = SpiConfiguration::from(cmd_args).unwrap();

        assert_eq!(
            config.generate_socket_paths(),
            vec![
                Path::new("vspi.sock0").to_path_buf(),
                Path::new("vspi.sock1").to_path_buf(),
                Path::new("vspi.sock2").to_path_buf(),
            ]
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
