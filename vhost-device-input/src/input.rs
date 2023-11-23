// Low level input device definitions
//
// Copyright 2023 Linaro Ltd. All Rights Reserved.
// Leo Yan <leo.yan@linaro.org>
//
// SPDX-License-Identifier: Apache-2.0 or BSD-3-Clause

use evdev::{Device, FetchEventsSynced, InputId};
use nix::ioctl_read_buf;
use std::io;
use std::os::fd::{AsRawFd, RawFd};
use std::path::PathBuf;

/// Trait that operates on input event device.  This main purpose for this
/// trait is to encapsulate a "Device" structure for accessing hardware
/// device or mock device for test.
pub trait InputDevice {
    /// Open the input device specified by the path.
    fn open(path: PathBuf) -> io::Result<Self>
    where
        Self: Sized;

    /// Fetch input events.
    fn fetch_events(&mut self) -> io::Result<FetchEventsSynced<'_>>;

    /// Return the raw file descriptor.
    fn get_raw_fd(&self) -> RawFd;

    /// Return the Input ID.
    fn input_id(&self) -> InputId;
}

impl InputDevice for Device {
    fn open(path: PathBuf) -> io::Result<Self> {
        Device::open(path)
    }

    fn fetch_events(&mut self) -> io::Result<FetchEventsSynced<'_>> {
        Device::fetch_events(self)
    }

    fn get_raw_fd(&self) -> RawFd {
        Device::as_raw_fd(self)
    }

    fn input_id(&self) -> InputId {
        Device::input_id(self)
    }
}

ioctl_read_buf!(eviocgname, b'E', 0x06, u8);
ioctl_read_buf!(eviocgbit_key, b'E', 0x21, u8);
ioctl_read_buf!(eviocgbit_relative, b'E', 0x22, u8);
ioctl_read_buf!(eviocgbit_absolute, b'E', 0x23, u8);
ioctl_read_buf!(eviocgbit_misc, b'E', 0x24, u8);
ioctl_read_buf!(eviocgbit_switch, b'E', 0x25, u8);
