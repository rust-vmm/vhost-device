// SPDX-License-Identifier: Apache-2.0 or BSD-3-Clause
// Copyright 2026 Panasonic Automotive Systems Co., Ltd.
// Author: Manos Pitsidianakis <manos.pitsidianakis@linaro.org>
//! An arguments type for the binary interface of this library.

use clap::{ArgGroup, Parser};

use std::os::fd::RawFd;
use std::path::PathBuf;

#[derive(Parser, Clone, Debug)]
#[clap(
    author,
    version,
    about,
    long_about = None,
    group(ArgGroup::new("socket group").required(true).args(&["socket_path", "socket_fd"])),
)]
pub struct RtcArgs {
    /// Location of vhost-user Unix domain socket.
    #[clap(short, long, value_name = "SOCKET")]
    pub socket_path: Option<PathBuf>,
    /// vhost-user Unix domain socket FD.
    #[clap(long, value_name = "FD")]
    pub socket_fd: Option<RawFd>,
    /// Don't offer alarm functionality for smeared UTC clocks. Turns
    /// `VIRTIO_RTC_F_ALARM` feature off.
    #[clap(long)]
    pub no_offer_alarm: bool,
    /// Don't offer UTC clock.
    #[clap(long)]
    pub no_utc: bool,
    /// Don't offer TAI clock.
    #[clap(long)]
    pub no_tai: bool,
    /// Don't offer monotonic clock.
    #[clap(long)]
    pub no_monotonic: bool,
}
