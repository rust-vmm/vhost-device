// SPDX-License-Identifier: Apache-2.0 or BSD-3-Clause

use std::path::PathBuf;

use clap::Parser;

#[derive(Parser)]
pub struct ScsiArgs {
    /// Make the images read-only.
    ///
    /// Currently, we don't actually support writes, but sometimes we want to
    /// pretend the disk is writable to work around issues with some tools that
    /// use the Linux SCSI generic API.
    #[arg(long = "read-only", short = 'r')]
    pub read_only: bool,
    /// Tell the guest this disk is non-rotational.
    ///
    /// Affects some heuristics in Linux around, for example, scheduling.
    #[arg(long = "solid-state")]
    pub solid_state: bool,
    /// Location of vhost-user socket.
    #[clap(short, long)]
    pub socket_path: PathBuf,
    /// Images against which the SCSI actions are emulated.
    pub images: Vec<PathBuf>,
}
