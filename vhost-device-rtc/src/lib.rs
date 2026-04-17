// SPDX-License-Identifier: Apache-2.0 or BSD-3-Clause
// Copyright 2026 Panasonic Automotive Systems Co., Ltd.
// Author: Manos Pitsidianakis <manos.pitsidianakis@linaro.org>

pub mod backend;
pub mod clocks;
pub mod virtio_rtc;

use std::sync::{Arc, RwLock};

use backend::VhostUserRtcBackend;
use thiserror::Error as ThisError;
use vhost::vhost_user::Listener;
use vhost_user_backend::VhostUserDaemon;
use vm_memory::{GuestMemoryAtomic, GuestMemoryMmap};

pub type Result<T> = core::result::Result<T, Error>;

#[derive(Debug, ThisError)]
/// Errors related to low level helpers
pub enum Error {
    #[error("Could not create backend: {0}")]
    CouldNotCreateBackend(#[from] backend::Error),
    #[error("Could not create daemon: {0}")]
    CouldNotCreateDaemon(vhost_user_backend::Error),
    #[error("Fatal error: {0}")]
    ServeFailed(vhost_user_backend::Error),
    #[error("Clock error: {0}")]
    Clock(#[from] clocks::Error),
}

#[derive(PartialEq, Clone, Copy, Debug)]
pub struct RtcConfiguration {
    pub offer_alarm: bool,
    pub utc: bool,
    pub tai: bool,
    pub monotonic: bool,
}

pub fn start_backend(listener: &mut Listener, config: RtcConfiguration) -> Result<()> {
    let RtcConfiguration {
        offer_alarm,
        utc,
        tai,
        monotonic,
    } = config;

    let mut clocks = vec![];

    if utc {
        clocks.push(clocks::Clock::new_utc()?);
    }
    if tai {
        clocks.push(clocks::Clock::new_tai()?);
    }
    if monotonic {
        clocks.push(clocks::Clock::new_monotonic()?);
    }
    // There isn't much value in complicating code here to return an error from the
    // threads, and so the code uses unwrap() instead. The panic on a thread
    // won't cause trouble to the main() function and should be safe for the
    // daemon.
    let backend = Arc::new(RwLock::new(VhostUserRtcBackend::new(offer_alarm, clocks)?));

    let mut daemon = VhostUserDaemon::new(
        String::from("vhost-device-rtc-backend"),
        backend.clone(),
        GuestMemoryAtomic::new(GuestMemoryMmap::new()),
    )
    .map_err(Error::CouldNotCreateDaemon)?;

    log::trace!("Starting daemon.");

    daemon.start(listener).map_err(Error::ServeFailed)?;
    let result = daemon.wait();

    backend.read().unwrap().exit_notifier.notify().unwrap();

    if !matches!(
        result,
        Err(vhost_user_backend::Error::HandleRequest(
            vhost::vhost_user::Error::Disconnected | vhost::vhost_user::Error::PartialMessage
        ))
    ) {
        return result.map_err(Error::ServeFailed);
    }
    Ok(())
}
