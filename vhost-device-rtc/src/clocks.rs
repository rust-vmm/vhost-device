// SPDX-License-Identifier: Apache-2.0 or BSD-3-Clause
// Copyright 2026 Panasonic Automotive Systems Co., Ltd.
// Author: Manos Pitsidianakis <manos.pitsidianakis@linaro.org>

//! Clock reading functionality
//!
//! Each clock has a specific type, leap second smearing, and optionally alarm
//! functionality (see [`crate::alarm`]).
//!
//! By default three kinds of clocks are available:
//!
//!
//! - `CLOCK_MONOTONIC` (POSIX)
//! - `CLOCK_REALTIME` (i.e. UTC clock) (POSIX)
//! - `CLOCK_TAI`
//!
//! A clock's value can be read with [`Clock::read`] method.
use nix::time::{clock_gettime, ClockId};
pub use nix::{errno::Errno, sys::time::TimeSpec};
use thiserror::Error as ThisError;

use crate::alarm::Alarm;

/// Clock error type alias.
pub type Result<T> = core::result::Result<T, Error>;

#[derive(Debug, ThisError)]
/// Clock errors
pub enum Error {
    #[error("Could not get time from {0}: {1}")]
    Get(ClockId, Errno),
    #[error("Could not create clock {0}: {1}")]
    Create(ClockId, Errno),
}

pub fn get_utc() -> Result<TimeSpec> {
    clock_gettime(ClockId::CLOCK_REALTIME).map_err(|err| Error::Get(ClockId::CLOCK_REALTIME, err))
}

pub fn get_tai() -> Result<TimeSpec> {
    clock_gettime(ClockId::CLOCK_TAI).map_err(|err| Error::Get(ClockId::CLOCK_TAI, err))
}

pub fn get_monotonic() -> Result<TimeSpec> {
    clock_gettime(ClockId::CLOCK_MONOTONIC).map_err(|err| Error::Get(ClockId::CLOCK_MONOTONIC, err))
}

#[derive(Debug)]
pub struct Clock {
    pub r#type: u8,
    pub leap_second_smearing: u8,
    pub alarm: Option<Alarm>,
    pub read_fn: fn() -> Result<TimeSpec>,
}

impl Clock {
    pub fn new_utc() -> Result<Self> {
        _ = nix::time::clock_getres(ClockId::CLOCK_REALTIME)
            .map_err(|err| Error::Create(ClockId::CLOCK_REALTIME, err))?;

        Ok(Self {
            r#type: crate::virtio_rtc::VIRTIO_RTC_CLOCK_UTC_SMEARED,
            leap_second_smearing: crate::virtio_rtc::VIRTIO_RTC_SMEAR_UNSPECIFIED,
            alarm: Some(Alarm::new()),
            read_fn: get_utc,
        })
    }

    pub fn new_tai() -> Result<Self> {
        _ = nix::time::clock_getres(ClockId::CLOCK_TAI)
            .map_err(|err| Error::Create(ClockId::CLOCK_TAI, err))?;
        Ok(Self {
            r#type: crate::virtio_rtc::VIRTIO_RTC_CLOCK_TAI,
            leap_second_smearing: crate::virtio_rtc::VIRTIO_RTC_SMEAR_UNSPECIFIED,
            alarm: None,
            read_fn: get_tai,
        })
    }

    pub fn new_monotonic() -> Result<Self> {
        _ = nix::time::clock_getres(ClockId::CLOCK_MONOTONIC)
            .map_err(|err| Error::Create(ClockId::CLOCK_MONOTONIC, err))?;
        Ok(Self {
            r#type: crate::virtio_rtc::VIRTIO_RTC_CLOCK_MONOTONIC,
            leap_second_smearing: crate::virtio_rtc::VIRTIO_RTC_SMEAR_UNSPECIFIED,
            alarm: None,
            read_fn: get_monotonic,
        })
    }

    pub fn read(&self) -> Result<u64> {
        let spec = (self.read_fn)()?;
        let nsec: u64 = spec.tv_nsec().try_into().unwrap_or(0);
        let sec: u64 = u64::try_from(spec.tv_sec())
            .unwrap_or(0)
            .saturating_mul(1_000_000_000);
        let total = nsec.saturating_add(sec);
        Ok(total)
    }
}

#[test]
fn test_clock() {
    for (clock_id, constructor_fn) in [
        (
            ClockId::CLOCK_REALTIME,
            Clock::new_utc as fn() -> Result<Clock>,
        ),
        (ClockId::CLOCK_TAI, Clock::new_tai),
        (ClockId::CLOCK_MONOTONIC, Clock::new_monotonic),
    ] {
        eprintln!("Creating clock {clock_id:?}");
        if nix::time::clock_getres(clock_id).is_ok() {
            let clock = constructor_fn().unwrap();
            _ = clock.read().unwrap();
        } else {
            constructor_fn().unwrap_err();
        }
    }
}
