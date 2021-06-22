// GPIO backend device
//
// Copyright 2021 Linaro Ltd. All Rights Reserved.
//          Viresh Kumar <viresh.kumar@linaro.org>
//
// SPDX-License-Identifier: Apache-2.0

use log::error;
use std::mem::size_of_val;
use std::sync::RwLock;

use libgpiod::*;
use thiserror::Error as ThisError;
use vm_memory::{Le16, Le32};

type Result<T> = std::result::Result<T, Error>;

#[derive(Clone, Debug, PartialEq, ThisError)]
/// Errors related to low level gpio helpers
pub enum Error {
    #[error("Invalid gpio direction: {0}")]
    GpioDirectionInvalid(u32),
    #[error("Invalid current gpio value")]
    GpioCurrentValueInvalid,
    #[error("Invalid gpio value: {0}")]
    GpioValueInvalid(u32),
    #[error("Invalid gpio message type: {0}")]
    GpioMessageInvalid(u16),
    #[error("Gpiod operation failed {0:?}")]
    GpiodFailed(libgpiod::Error),
}

/// Virtio specification definitions
/// Virtio GPIO request types
pub(crate) const VIRTIO_GPIO_MSG_GET_LINE_NAMES: u16 = 0x0001;
pub(crate) const VIRTIO_GPIO_MSG_GET_DIRECTION: u16 = 0x0002;
pub(crate) const VIRTIO_GPIO_MSG_SET_DIRECTION: u16 = 0x0003;
pub(crate) const VIRTIO_GPIO_MSG_GET_VALUE: u16 = 0x0004;
pub(crate) const VIRTIO_GPIO_MSG_SET_VALUE: u16 = 0x0005;

/// Direction types
pub(crate) const VIRTIO_GPIO_DIRECTION_NONE: u8 = 0x00;
pub(crate) const VIRTIO_GPIO_DIRECTION_OUT: u8 = 0x01;
pub(crate) const VIRTIO_GPIO_DIRECTION_IN: u8 = 0x02;

/// Virtio GPIO Configuration
#[derive(Clone)]
#[repr(C)]
pub struct VirtioGpioConfig {
    ngpio: Le16,
    padding: Le16,
    gpio_names_size: Le32,
}

/// Trait that represents an GPIO Device.
///
/// This trait is introduced for development purposes only, and should not
/// be used outside of this crate. The purpose of this trait is to provide a
/// mock implementation for the GPIO driver so that we can test the GPIO
/// functionality without the need of a physical device.
pub trait GpioDevice {
    fn open(device: u32) -> Result<Self>
    where
        Self: Sized;

    fn get_num_lines(&self) -> Result<u16>;
    fn get_line_name(&self, gpio: u16) -> Result<String>;
    fn get_direction(&self, gpio: u16) -> Result<u8>;
    fn set_direction(&mut self, gpio: u16, dir: u8, value: u32) -> Result<()>;
    fn get_value(&self, gpio: u16) -> Result<u8>;
    fn set_value(&mut self, gpio: u16, value: u32) -> Result<()>;
}

pub struct PhysDevice {
    chip: GpiodChip,
    ngpio: u16,
    line_request: Vec<Option<GpiodLineRequest>>,
}

unsafe impl Send for PhysDevice {}
unsafe impl Sync for PhysDevice {}

impl GpioDevice for PhysDevice {
    fn open(device: u32) -> Result<Self>
    where
        Self: Sized,
    {
        let path = format!("/dev/gpiochip{}", device);
        let chip = GpiodChip::open(&path).map_err(Error::GpiodFailed)?;
        let ngpio = chip.get_num_lines() as u16;

        // Can't set a vector to all None easily
        let mut line_request: Vec<Option<GpiodLineRequest>> = Vec::new();
        line_request.resize_with(ngpio as usize, || None);

        Ok(PhysDevice {
            chip,
            ngpio,
            line_request,
        })
    }

    fn get_num_lines(&self) -> Result<u16> {
        Ok(self.ngpio)
    }

    fn get_line_name(&self, gpio: u16) -> Result<String> {
        let line_info = self
            .chip
            .line_info(gpio.into())
            .map_err(Error::GpiodFailed)?;

        Ok(line_info.get_name().unwrap_or("").to_string())
    }

    fn get_direction(&self, gpio: u16) -> Result<u8> {
        let line_info = self
            .chip
            .line_info(gpio.into())
            .map_err(Error::GpiodFailed)?;

        Ok(
            match line_info.get_direction().map_err(Error::GpiodFailed)? {
                Direction::AsIs => VIRTIO_GPIO_DIRECTION_NONE,
                Direction::Input => VIRTIO_GPIO_DIRECTION_IN,
                Direction::Output => VIRTIO_GPIO_DIRECTION_OUT,
            },
        )
    }

    fn set_direction(&mut self, gpio: u16, dir: u8, value: u32) -> Result<()> {
        let mut config = GpiodLineConfig::new().map_err(Error::GpiodFailed)?;
        let request = &mut self.line_request[gpio as usize];

        match dir {
            VIRTIO_GPIO_DIRECTION_NONE => {
                *request = None;
                return Ok(());
            }

            VIRTIO_GPIO_DIRECTION_IN => config.set_direction_offset(Direction::Input, gpio as u32),
            VIRTIO_GPIO_DIRECTION_OUT => {
                config.set_direction(Direction::Output);
                config.set_output_values(&mut vec![gpio as u32], &mut vec![value as i32]);
            }

            _ => return Err(Error::GpioDirectionInvalid(value)),
        };

        if let Some(line_request) = &request {
            line_request
                .reconfigure_lines(&config)
                .map_err(Error::GpiodFailed)?;
        } else {
            let rconfig = GpiodRequestConfig::new().map_err(Error::GpiodFailed)?;

            rconfig.set_consumer("vhu-gpio");
            rconfig.set_offsets(&mut vec![gpio as u32]);

            *request = Some(
                self.chip
                    .request_lines(&rconfig, &config)
                    .map_err(Error::GpiodFailed)?,
            );
        }

        Ok(())
    }

    fn get_value(&self, gpio: u16) -> Result<u8> {
        let request = &self.line_request[gpio as usize];

        if let Some(line_request) = request {
            Ok(line_request
                .get_value(gpio as u32)
                .map_err(Error::GpiodFailed)? as u8)
        } else {
            Err(Error::GpioDirectionInvalid(
                VIRTIO_GPIO_DIRECTION_NONE as u32,
            ))
        }
    }

    fn set_value(&mut self, gpio: u16, value: u32) -> Result<()> {
        let request = &self.line_request[gpio as usize];

        // Direction change can follow value change, don't fail here.
        if let Some(line_request) = request {
            line_request
                .set_value(gpio as u32, value as i32)
                .map_err(Error::GpiodFailed)?;
        }

        Ok(())
    }
}

struct LineState {
    dir: u8,
    val: Option<u16>,
}

struct DeviceState<D: GpioDevice> {
    device: D,
    line_state: Vec<LineState>,
}

pub struct GpioController<D: GpioDevice> {
    config: VirtioGpioConfig,
    state: RwLock<DeviceState<D>>,
    line_names: String,
}

impl<D: GpioDevice> GpioController<D> {
    // Creates a new controller corresponding to `device`.
    pub(crate) fn new(device: D) -> Result<GpioController<D>> {
        let ngpio = device.get_num_lines()? as u16;

        // Allocate enough capacity in the beginning, we can always extend it later.
        let mut line_names = String::with_capacity((ngpio * 10).into());
        let mut line_states = Vec::with_capacity(ngpio as usize);

        for offset in 0..ngpio {
            let name = device.get_line_name(offset)?;

            // Create line names
            line_names.push_str(&name);
            line_names.push('\0');

            line_states.push(LineState {
                dir: device.get_direction(offset)?,
                val: None,
            });
        }

        Ok(GpioController {
            config: VirtioGpioConfig {
                ngpio: From::from(ngpio),
                padding: From::from(0),
                gpio_names_size: From::from(size_of_val(&line_names) as u32),
            },
            state: RwLock::new(DeviceState {
                device,
                line_state: line_states,
            }),
            line_names,
        })
    }

    fn get_direction(&self, gpio: u16) -> Result<u8> {
        Ok(self.state.read().unwrap().line_state[gpio as usize].dir)
    }

    fn set_direction(&self, gpio: u16, dir: u32) -> Result<()> {
        let state = &mut self.state.write().unwrap();
        let mut line_state = &mut state.line_state[gpio as usize];

        let value = match dir as u8 {
            VIRTIO_GPIO_DIRECTION_NONE => {
                line_state.val = None;
                0
            }

            VIRTIO_GPIO_DIRECTION_IN => 0,
            VIRTIO_GPIO_DIRECTION_OUT => {
                if line_state.val.is_none() {
                    return Err(Error::GpioCurrentValueInvalid);
                }

                line_state.val.unwrap()
            }

            _ => return Err(Error::GpioDirectionInvalid(dir)),
        };

        state.device.set_direction(gpio, dir as u8, value as u32)?;
        state.line_state[gpio as usize].dir = dir as u8;
        Ok(())
    }

    fn get_value(&self, gpio: u16) -> Result<u8> {
        let device = &self.state.read().unwrap().device;

        device.get_value(gpio)
    }

    fn set_value(&self, gpio: u16, value: u32) -> Result<()> {
        if value > 1 {
            return Err(Error::GpioValueInvalid(value));
        }

        let state = &mut self.state.write().unwrap();

        state.device.set_value(gpio, value)?;
        state.line_state[gpio as usize].val = Some(value as u16);
        Ok(())
    }

    pub fn get_config(&self) -> &VirtioGpioConfig {
        &self.config
    }

    pub fn operation(&self, rtype: u16, gpio: u16, value: u32) -> Result<Vec<u8>> {
        Ok(match rtype {
            VIRTIO_GPIO_MSG_GET_LINE_NAMES => self.line_names.as_bytes().to_vec(),
            VIRTIO_GPIO_MSG_GET_DIRECTION => vec![self.get_direction(gpio)?],
            VIRTIO_GPIO_MSG_SET_DIRECTION => {
                self.set_direction(gpio, value)?;
                vec![0]
            }
            VIRTIO_GPIO_MSG_GET_VALUE => vec![self.get_value(gpio)?],
            VIRTIO_GPIO_MSG_SET_VALUE => {
                self.set_value(gpio, value)?;
                vec![0]
            }
            msg => return Err(Error::GpioMessageInvalid(msg)),
        })
    }
}
