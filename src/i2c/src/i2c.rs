// Low level I2C definitions
//
// Copyright 2021 Linaro Ltd. All Rights Reserved.
//          Viresh Kumar <viresh.kumar@linaro.org>
//
// SPDX-License-Identifier: Apache-2.0

use std::io::Result;

/// I2C adapter and helpers
pub trait I2cAdapterTrait: Send + Sync + 'static {
}

pub struct I2cAdapter {
    bus: u32,
    smbus: bool,
}

impl I2cAdapterTrait for I2cAdapter {
}

/// I2C map and helpers
const MAX_I2C_VDEV: usize = 1 << 7;
const I2C_INVALID_ADAPTER: u32 = 0xFFFFFFFF;

pub struct I2cMap<A: I2cAdapterTrait> {
    adapters: Vec<A>,
    device_map: [u32; MAX_I2C_VDEV],
}

impl<A: I2cAdapterTrait> I2cMap<A> {
    pub fn new(_list: &str) -> Result<Self> {
        let device_map: [u32; MAX_I2C_VDEV] = [I2C_INVALID_ADAPTER; MAX_I2C_VDEV];
        let adapters: Vec<A> = Vec::new();

        Ok(I2cMap {
            adapters,
            device_map,
        })
    }
}
