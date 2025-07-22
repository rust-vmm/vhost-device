// SPDX-License-Identifier: Apache-2.0 or BSD-3-Clause
//! An arguments type for the binary interface of this library.

use std::path::PathBuf;

use clap::{Parser, ValueEnum};

#[derive(Parser, Debug)]
#[clap(version, about, long_about = None)]
pub struct SoundArgs {
    /// vhost-user Unix domain socket path.
    #[clap(long)]
    pub socket: PathBuf,
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
    GStreamer,
}
