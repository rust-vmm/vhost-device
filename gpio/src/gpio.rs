// GPIO backend device
//
// Copyright 2022 Linaro Ltd. All Rights Reserved.
//          Viresh Kumar <viresh.kumar@linaro.org>
//
// SPDX-License-Identifier: Apache-2.0

use thiserror::Error as ThisError;

type Result<T> = std::result::Result<T, Error>;

#[derive(Clone, Debug, PartialEq, ThisError)]
/// Errors related to low level gpio helpers
pub(crate) enum Error {
}

/// Trait that represents an GPIO Device.
///
/// This trait is introduced for development purposes only, and should not
/// be used outside of this crate. The purpose of this trait is to provide a
/// mock implementation for the GPIO driver so that we can test the GPIO
/// functionality without the need of a physical device.
pub(crate) trait GpioDevice {
    fn open(device: u32) -> Result<Self>
    where
        Self: Sized;
}

pub(crate) struct PhysDevice {}

impl GpioDevice for PhysDevice {
    fn open(_device: u32) -> Result<Self>
    where
        Self: Sized,
    {
        Ok(Self {})
    }
}

pub(crate) struct GpioController<D: GpioDevice> {
    device: D,
}

impl<D: GpioDevice> GpioController<D> {
    // Creates a new controller corresponding to `device`.
    pub(crate) fn new(device: D) -> Result<GpioController<D>> {
        Ok(GpioController {
            device,
        })
    }
}
