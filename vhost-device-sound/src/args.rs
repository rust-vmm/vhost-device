// SPDX-License-Identifier: Apache-2.0 or BSD-3-Clause
//! An arguments type for the binary interface of this library.

use std::os::fd::RawFd;
use std::path::PathBuf;

use clap::{ArgGroup, Parser, ValueEnum};

#[derive(Parser, Debug)]
#[clap(
    version,
    about,
    long_about = None,
    group(ArgGroup::new("socket group").required(true).args(&["socket", "socket_fd"])),
)]
pub struct SoundArgs {
    /// vhost-user Unix domain socket path.
    #[clap(long)]
    pub socket: Option<PathBuf>,
    /// vhost-user Unix domain socket FD.
    #[clap(long)]
    pub socket_fd: Option<RawFd>,
    /// audio backend to be used
    #[clap(long)]
    #[clap(value_enum)]
    pub backend: BackendType,
}

#[derive(ValueEnum, Clone, Copy, Default, Debug, Eq, PartialEq)]
pub enum BackendType {
    #[default]
    Null,
    #[cfg(all(feature = "pw-backend", target_env = "gnu"))]
    Pipewire,
    #[cfg(all(feature = "alsa-backend", target_env = "gnu"))]
    Alsa,
    #[cfg(all(feature = "gst-backend", target_env = "gnu"))]
    #[value(name = "gstreamer")]
    GStreamer,
}
