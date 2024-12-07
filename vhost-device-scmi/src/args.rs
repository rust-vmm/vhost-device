// SPDX-FileCopyrightText: Red Hat, Inc.
// SPDX-License-Identifier: Apache-2.0
// Based on implementation of other devices here, Copyright by Linaro Ltd.
//! An arguments type for the binary interface of this library.

use std::path::PathBuf;

use clap::Parser;

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
pub struct ScmiArgs {
    // Location of vhost-user Unix domain socket.
    // Required, unless one of the --help options is used.
    #[clap(
        short,
        long,
        default_value_if(
            "help_devices",
            clap::builder::ArgPredicate::IsPresent,
            "PathBuf::new()"
        ),
        help = "vhost-user socket to use"
    )]
    pub socket_path: PathBuf,
    // Specification of SCMI devices to create.
    #[clap(short, long, help = "Devices to expose")]
    #[arg(num_args(1..))]
    pub device: Vec<String>,
    #[clap(long, exclusive = true, help = "Print help on available devices")]
    pub help_devices: bool,
}
