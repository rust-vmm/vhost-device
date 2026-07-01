// Copyright 2026 Red Hat Inc
//
// SPDX-License-Identifier: Apache-2.0 or BSD-3-Clause

//! An arguments type for the binary interface of this library.

use std::path::PathBuf;

use clap::{Parser, ValueEnum};

#[derive(Clone, Parser, Debug)]
#[clap(author, version, about, long_about = None)]
pub struct MediaArgs {
    /// Unix socket to which a hypervisor connects to and sets up the control
    /// path with the device.
    #[clap(short, long)]
    pub socket_path: PathBuf,

    /// Path to the V4L2 media device file. Defaults to /dev/video0.
    #[clap(short = 'd', long, default_value = "/dev/video0")]
    pub v4l2_device: PathBuf,

    /// Media backend to be used.
    #[clap(short, long, default_value = "null")]
    #[clap(value_enum)]
    pub backend: BackendType,
}

#[derive(ValueEnum, Debug, Clone, Eq, PartialEq)]
pub enum BackendType {
    Null,
    #[cfg(feature = "simple-capture")]
    SimpleCapture,
    #[cfg(feature = "v4l2-proxy")]
    V4l2Proxy,
    #[cfg(feature = "ffmpeg")]
    FfmpegDecoder,
}
