// Copyright 2026 Red Hat Inc
//
// SPDX-License-Identifier: Apache-2.0 or BSD-3-Clause

extern crate vhost_device_media;

use std::path::PathBuf;

use clap::Parser;
use vhost_device_media::{start_backend, BackendType, Error, VuMediaConfig};

#[derive(Clone, Parser, Debug)]
#[clap(author, version, about, long_about = None)]
struct MediaArgs {
    /// Unix socket to which a hypervisor connects to and sets up the control
    /// path with the device.
    #[clap(short, long)]
    socket_path: PathBuf,

    /// Path to the V4L2 media device file. Defaults to /dev/video0.
    #[clap(short = 'd', long, default_value = "/dev/video0")]
    v4l2_device: PathBuf,

    /// Media backend to be used.
    #[clap(short, long, default_value = "null")]
    #[clap(value_enum)]
    backend: BackendType,
}

impl From<MediaArgs> for VuMediaConfig {
    fn from(args: MediaArgs) -> Self {
        Self {
            socket_path: args.socket_path,
            v4l2_device: args.v4l2_device,
            backend: args.backend,
        }
    }
}

fn main() -> std::result::Result<(), Error> {
    env_logger::init();

    start_backend(VuMediaConfig::from(MediaArgs::parse()))
}
