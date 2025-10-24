// SPDX-License-Identifier: Apache-2.0 or BSD-3-Clause
// Copyright 2026 Panasonic Automotive Systems Co., Ltd.
// Author: Manos Pitsidianakis <manos.pitsidianakis@linaro.org>

use std::os::unix::net::UnixListener;
use std::os::unix::prelude::*;
use std::process::exit;

use clap::Parser;
use vhost::vhost_user::Listener;
use vhost_device_rtc::{start_backend, RtcConfiguration};

mod args;
use args::RtcArgs;

impl From<RtcArgs> for RtcConfiguration {
    fn from(args: RtcArgs) -> Self {
        RtcConfiguration {
            offer_alarm: !args.no_offer_alarm,
            utc: !args.no_utc,
            tai: !args.no_tai,
            monotonic: !args.no_monotonic,
        }
    }
}

fn main() {
    env_logger::init();

    let mut args = RtcArgs::parse();

    let mut listener = if let Some(fd) = args.socket_fd.take() {
        // SAFETY: user has assured us this is safe.
        unsafe { UnixListener::from_raw_fd(fd) }.into()
    } else if let Some(path) = args.socket_path.take() {
        Listener::new(path, true).unwrap()
    } else {
        unreachable!()
    };

    let config = RtcConfiguration::from(args);
    if !config.utc && !config.tai && !config.monotonic {
        log::warn!("No clocks configured, so no clocks will be available.");
    }
    loop {
        if let Err(err) = start_backend(&mut listener, config) {
            log::error!("{err}");
            exit(1);
        }
    }
}

#[test]
fn test_args() {
    let mut args = RtcArgs {
        socket_fd: None,
        socket_path: None,
        no_offer_alarm: false,
        no_utc: false,
        no_tai: false,
        no_monotonic: false,
    };

    assert_eq!(
        RtcConfiguration::from(args.clone()),
        RtcConfiguration {
            offer_alarm: true,
            utc: true,
            tai: true,
            monotonic: true,
        }
    );
    args.no_offer_alarm = true;

    assert_eq!(
        RtcConfiguration::from(args.clone()),
        RtcConfiguration {
            offer_alarm: false,
            utc: true,
            tai: true,
            monotonic: true,
        }
    );

    args.no_utc = true;

    assert_eq!(
        RtcConfiguration::from(args.clone()),
        RtcConfiguration {
            offer_alarm: false,
            utc: false,
            tai: true,
            monotonic: true,
        }
    );

    args.no_tai = true;

    assert_eq!(
        RtcConfiguration::from(args.clone()),
        RtcConfiguration {
            offer_alarm: false,
            utc: false,
            tai: false,
            monotonic: true,
        }
    );
    args.no_monotonic = true;

    assert_eq!(
        RtcConfiguration::from(args.clone()),
        RtcConfiguration {
            offer_alarm: false,
            utc: false,
            tai: false,
            monotonic: false,
        }
    );
}
