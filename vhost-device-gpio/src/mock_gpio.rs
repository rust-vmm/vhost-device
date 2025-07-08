// Mock GPIO backend device for testing
//
// Copyright 2023 Linaro Ltd. All Rights Reserved.
//          Viresh Kumar <viresh.kumar@linaro.org>
//
// SPDX-License-Identifier: Apache-2.0 or BSD-3-Clause

use std::sync::RwLock;

use log::info;

use crate::{
    gpio::{Error, GpioDevice, GpioState, Result},
    virtio_gpio::*,
};

#[derive(Debug)]
pub(crate) struct MockGpioDevice {
    ngpio: u16,
    pub(crate) gpio_names: Vec<String>,
    state: RwLock<Vec<GpioState>>,
    pub num_gpios_result: Result<u16>,
    pub gpio_name_result: Result<String>,
    pub direction_result: Result<u8>,
    set_direction_result: Result<()>,
    value_result: Result<u8>,
    set_value_result: Result<()>,
    set_irq_type_result: Result<()>,
    pub(crate) wait_for_irq_result: Result<bool>,
}

impl MockGpioDevice {
    pub(crate) fn new(ngpio: u16) -> Self {
        let mut gpio_names = Vec::with_capacity(ngpio.into());
        for i in 0..ngpio {
            gpio_names.push(format!("dummy{}", i));
        }

        Self {
            ngpio,
            gpio_names,
            state: RwLock::new(vec![
                GpioState {
                    dir: VIRTIO_GPIO_DIRECTION_NONE,
                    val: None,
                    irq_type: VIRTIO_GPIO_IRQ_TYPE_NONE,
                };
                ngpio.into()
            ]),
            num_gpios_result: Ok(0),
            gpio_name_result: Ok("".to_string()),
            direction_result: Ok(0),
            set_direction_result: Ok(()),
            value_result: Ok(0),
            set_value_result: Ok(()),
            set_irq_type_result: Ok(()),
            wait_for_irq_result: Ok(true),
        }
    }
}

impl GpioDevice for MockGpioDevice {
    fn open(ngpios: u32) -> Result<Self>
    where
        Self: Sized,
    {
        Ok(MockGpioDevice::new(ngpios.try_into().unwrap()))
    }

    fn num_gpios(&self) -> Result<u16> {
        if self.num_gpios_result.is_err() {
            return self.num_gpios_result;
        }

        Ok(self.ngpio)
    }

    fn gpio_name(&self, gpio: u16) -> Result<String> {
        assert!((gpio as usize) < self.gpio_names.len());

        if self.gpio_name_result.is_err() {
            return self.gpio_name_result.clone();
        }

        Ok(self.gpio_names[gpio as usize].clone())
    }

    fn direction(&self, gpio: u16) -> Result<u8> {
        if self.direction_result.is_err() {
            return self.direction_result;
        }

        Ok(self.state.read().unwrap()[gpio as usize].dir)
    }

    fn set_direction(&self, gpio: u16, dir: u8, value: u32) -> Result<()> {
        info!(
            "gpio {} set direction to {}",
            self.gpio_names[gpio as usize], dir
        );

        if self.set_direction_result.is_err() {
            return self.set_direction_result;
        }

        self.state.write().unwrap()[gpio as usize].dir = dir;
        self.state.write().unwrap()[gpio as usize].val = match dir {
            VIRTIO_GPIO_DIRECTION_NONE => None,
            VIRTIO_GPIO_DIRECTION_IN => self.state.read().unwrap()[gpio as usize].val,
            VIRTIO_GPIO_DIRECTION_OUT => Some(value as u16),

            _ => return Err(Error::GpioDirectionInvalid(dir as u32)),
        };

        Ok(())
    }

    fn value(&self, gpio: u16) -> Result<u8> {
        if self.value_result.is_err() {
            return self.value_result;
        }

        if let Some(val) = self.state.read().unwrap()[gpio as usize].val {
            Ok(val as u8)
        } else {
            Err(Error::GpioCurrentValueInvalid)
        }
    }

    fn set_value(&self, gpio: u16, value: u32) -> Result<()> {
        info!(
            "gpio {} set value to {}",
            self.gpio_names[gpio as usize], value
        );

        if self.set_value_result.is_err() {
            return self.set_value_result;
        }

        self.state.write().unwrap()[gpio as usize].val = Some(value as u16);
        Ok(())
    }

    fn set_irq_type(&self, gpio: u16, value: u16) -> Result<()> {
        info!(
            "gpio {} set irq type to {}",
            self.gpio_name(gpio).unwrap(),
            value
        );
        if self.set_irq_type_result.is_err() {
            return self.set_irq_type_result;
        }

        Ok(())
    }

    fn wait_for_interrupt(&self, _gpio: u16) -> Result<bool> {
        if self.wait_for_irq_result.is_err() {
            return self.wait_for_irq_result;
        }

        Ok(true)
    }
}
