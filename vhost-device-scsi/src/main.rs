// SPDX-License-Identifier: Apache-2.0 or BSD-3-Clause

use vhost_device_scsi::{
    scsi::emulation::{
        block_device::{BlockDevice, FileBackend, MediumRotationRate},
        target::EmulatedTarget,
    },
    vhu_scsi::VhostUserScsiBackend,
};

use std::{
    fs::File,
    path::PathBuf,
    process::exit,
    sync::{Arc, RwLock},
};

use clap::Parser;
use log::{error, warn};
use thiserror::Error as ThisError;
use vhost_user_backend::VhostUserDaemon;
use vm_memory::{GuestMemoryAtomic, GuestMemoryMmap};

#[derive(Debug, ThisError)]
enum Error {
    #[error("More than 256 LUNs aren't currently supported")]
    TooManyLUNs,
    #[error("Failed serving the daemon: {0}")]
    ServeFailed(vhost_user_backend::Error),
}

type Result<T> = std::result::Result<T, Error>;

#[derive(Parser)]
struct ScsiArgs {
    /// Make the images read-only.
    ///
    /// Currently, we don't actually support writes, but sometimes we want to
    /// pretend the disk is writable to work around issues with some tools that
    /// use the Linux SCSI generic API.
    #[arg(long = "read-only", short = 'r')]
    read_only: bool,
    /// Tell the guest this disk is non-rotational.
    ///
    /// Affects some heuristics in Linux around, for example, scheduling.
    #[arg(long = "solid-state")]
    solid_state: bool,
    /// Location of vhost-user socket.
    #[clap(short, long)]
    socket_path: PathBuf,
    /// Images against which the SCSI actions are emulated.
    images: Vec<PathBuf>,
}

fn create_backend(args: &ScsiArgs) -> Result<VhostUserScsiBackend> {
    let mut backend = VhostUserScsiBackend::new();
    let mut target = EmulatedTarget::new();

    if args.images.len() > 256 {
        // This is fairly simple to add; it's just a matter of supporting the right LUN
        // encoding formats.
        error!("Currently only up to 256 targets are supported");
        return Err(Error::TooManyLUNs);
    }

    if !args.read_only {
        warn!("Currently, only read-only images are supported. Unless you know what you're doing, you want to pass -r");
    }

    for image in &args.images {
        let mut dev = BlockDevice::new(FileBackend::new(
            File::options()
                .read(true)
                .write(true)
                .open(image)
                .expect("Opening image"),
        ));
        dev.set_write_protected(args.read_only);
        dev.set_solid_state(if args.solid_state {
            MediumRotationRate::NonRotating
        } else {
            MediumRotationRate::Unreported
        });
        target.add_lun(Box::new(dev));
    }

    backend.add_target(Box::new(target));
    Ok(backend)
}

fn start_backend(backend: VhostUserScsiBackend, args: ScsiArgs) -> Result<()> {
    let backend = Arc::new(RwLock::new(backend));
    let mut daemon = VhostUserDaemon::new(
        "vhost-device-scsi".into(),
        Arc::clone(&backend),
        GuestMemoryAtomic::new(GuestMemoryMmap::new()),
    )
    .expect("Creating daemon");

    daemon.serve(args.socket_path).map_err(Error::ServeFailed)?;

    Ok(())
}

fn run() -> Result<()> {
    env_logger::init();
    let args = ScsiArgs::parse();
    let backend = create_backend(&args)?;
    start_backend(backend, args)?;

    Ok(())
}

fn main() {
    if let Err(e) = run() {
        error!("{e}");
        exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_backend() {
        let sock = tempfile::NamedTempFile::new().unwrap();
        let args = ScsiArgs {
            images: vec!["/dev/null".into()],
            read_only: true,
            socket_path: sock.path().into(),
            solid_state: false,
        };
        create_backend(&args).unwrap();
    }

    #[test]
    fn test_fail_listener() {
        let socket_name = "~/path/not/present/scsi";
        let args = ScsiArgs {
            images: vec!["/dev/null".into()],
            read_only: true,
            socket_path: socket_name.into(),
            solid_state: false,
        };
        let backend = create_backend(&args).unwrap();
        let err = start_backend(backend, args).unwrap_err();
        if let Error::ServeFailed(_) = err {
        } else {
            panic!("expected failure when creating listener");
        }
    }
}
