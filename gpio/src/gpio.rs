// GPIO backend device
//
// Copyright 2022 Linaro Ltd. All Rights Reserved.
//          Viresh Kumar <viresh.kumar@linaro.org>
//
// SPDX-License-Identifier: Apache-2.0

use log::error;
use std::sync::RwLock;

use libgpiod::{Chip, Direction, Error as LibGpiodError, LineConfig, LineRequest, RequestConfig};
use thiserror::Error as ThisError;
use vm_memory::{Le16, Le32};

type Result<T> = std::result::Result<T, Error>;

#[derive(Clone, Debug, PartialEq, ThisError)]
/// Errors related to low level gpio helpers
pub(crate) enum Error {
    #[error("Invalid gpio direction: {0}")]
    GpioDirectionInvalid(u32),
    #[error("Invalid current gpio value")]
    GpioCurrentValueInvalid,
    #[error("Invalid gpio value: {0}")]
    GpioValueInvalid(u32),
    #[error("Invalid gpio message type: {0}")]
    GpioMessageInvalid(u16),
    #[error("Gpiod operation failed {0:?}")]
    GpiodFailed(LibGpiodError),
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
pub(crate) struct VirtioGpioConfig {
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
pub(crate) trait GpioDevice {
    fn open(device: u32) -> Result<Self>
    where
        Self: Sized;

    fn get_num_gpios(&self) -> Result<u16>;
    fn get_gpio_name(&self, gpio: u16) -> Result<String>;
    fn get_direction(&self, gpio: u16) -> Result<u8>;
    fn set_direction(&self, gpio: u16, dir: u8, value: u32) -> Result<()>;
    fn get_value(&self, gpio: u16) -> Result<u8>;
    fn set_value(&self, gpio: u16, value: u32) -> Result<()>;
}

pub(crate) struct PhysLineState {
    request: Option<LineRequest>,
}

pub(crate) struct PhysDevice {
    chip: Chip,
    ngpio: u16,
    state: Vec<RwLock<PhysLineState>>,
}

unsafe impl Send for PhysDevice {}
unsafe impl Sync for PhysDevice {}

impl GpioDevice for PhysDevice {
    fn open(device: u32) -> Result<Self>
    where
        Self: Sized,
    {
        let path = format!("/dev/gpiochip{}", device);
        let chip = Chip::open(&path).map_err(Error::GpiodFailed)?;
        let ngpio = chip.get_num_lines() as u16;

        // Can't set a vector to all None easily
        let mut state: Vec<RwLock<PhysLineState>> = Vec::new();
        state.resize_with(ngpio as usize, || {
            RwLock::new(PhysLineState {
                request: None,
            })
        });

        Ok(PhysDevice { chip, ngpio, state })
    }

    fn get_num_gpios(&self) -> Result<u16> {
        Ok(self.ngpio)
    }

    fn get_gpio_name(&self, gpio: u16) -> Result<String> {
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

    fn set_direction(&self, gpio: u16, dir: u8, value: u32) -> Result<()> {
        let mut config = LineConfig::new().map_err(Error::GpiodFailed)?;
        let state = &mut self.state[gpio as usize].write().unwrap();

        match dir {
            VIRTIO_GPIO_DIRECTION_NONE => {
                state.request = None;
                return Ok(());
            }

            VIRTIO_GPIO_DIRECTION_IN => config.set_direction_offset(Direction::Input, gpio as u32),
            VIRTIO_GPIO_DIRECTION_OUT => {
                config.set_direction(Direction::Output);
                config.set_output_value(gpio as u32, value);
            }

            _ => return Err(Error::GpioDirectionInvalid(value)),
        };

        if let Some(request) = &state.request {
            request
                .reconfigure_lines(&config)
                .map_err(Error::GpiodFailed)?;
        } else {
            let rconfig = RequestConfig::new().map_err(Error::GpiodFailed)?;

            rconfig.set_consumer("vhu-gpio");
            rconfig.set_offsets(&[gpio as u32]);

            state.request = Some(
                self.chip
                    .request_lines(&rconfig, &config)
                    .map_err(Error::GpiodFailed)?,
            );
        }

        Ok(())
    }

    fn get_value(&self, gpio: u16) -> Result<u8> {
        let state = &self.state[gpio as usize].read().unwrap();

        if let Some(request) = &state.request {
            Ok(request.get_value(gpio as u32).map_err(Error::GpiodFailed)? as u8)
        } else {
            Err(Error::GpioDirectionInvalid(
                VIRTIO_GPIO_DIRECTION_NONE as u32,
            ))
        }
    }

    fn set_value(&self, gpio: u16, value: u32) -> Result<()> {
        let state = &self.state[gpio as usize].read().unwrap();

        // Direction change can follow value change, don't fail here for invalid
        // direction.
        if let Some(request) = &state.request {
            request
                .set_value(gpio as u32, value as i32)
                .map_err(Error::GpiodFailed)?;
        }

        Ok(())
    }
}

struct GpioState {
    dir: u8,
    val: Option<u16>,
}

pub(crate) struct GpioController<D: GpioDevice> {
    config: VirtioGpioConfig,
    device: D,
    state: Vec<RwLock<GpioState>>,
    gpio_names: String,
}

impl<D: GpioDevice> GpioController<D> {
    // Creates a new controller corresponding to `device`.
    pub(crate) fn new(device: D) -> Result<GpioController<D>> {
        let ngpio = device.get_num_gpios()?;

        // The gpio's name can be of any length, we are just trying to allocate something
        // reasonable to start with, we can always extend it later.
        let mut gpio_names = String::with_capacity((ngpio * 10).into());
        let mut state = Vec::with_capacity(ngpio as usize);

        for offset in 0..ngpio {
            let name = device.get_gpio_name(offset)?;

            // Create line names
            gpio_names.push_str(&name);
            gpio_names.push('\0');

            state.push(RwLock::new(GpioState {
                dir: device.get_direction(offset)?,
                val: None,
            }));
        }

        Ok(GpioController {
            config: VirtioGpioConfig {
                ngpio: From::from(ngpio),
                padding: From::from(0),
                gpio_names_size: From::from(gpio_names.len() as u32),
            },
            device,
            state,
            gpio_names,
        })
    }

    fn get_direction(&self, gpio: u16) -> Result<u8> {
        self.device.get_direction(gpio)
    }

    fn set_direction(&self, gpio: u16, dir: u32) -> Result<()> {
        let state = &mut self.state[gpio as usize].write().unwrap();

        let value = match dir as u8 {
            VIRTIO_GPIO_DIRECTION_NONE => {
                state.val = None;
                0
            }

            VIRTIO_GPIO_DIRECTION_IN => 0,
            VIRTIO_GPIO_DIRECTION_OUT => match state.val {
                Some(val) => val,
                None => return Err(Error::GpioCurrentValueInvalid),
            },

            _ => return Err(Error::GpioDirectionInvalid(dir)),
        };

        self.device.set_direction(gpio, dir as u8, value as u32)?;
        state.dir = dir as u8;
        Ok(())
    }

    fn get_value(&self, gpio: u16) -> Result<u8> {
        self.device.get_value(gpio)
    }

    fn set_value(&self, gpio: u16, value: u32) -> Result<()> {
        if value > 1 {
            return Err(Error::GpioValueInvalid(value));
        }

        self.device.set_value(gpio, value)?;
        self.state[gpio as usize].write().unwrap().val = Some(value as u16);
        Ok(())
    }

    pub(crate) fn get_config(&self) -> &VirtioGpioConfig {
        &self.config
    }

    pub(crate) fn operation(&self, rtype: u16, gpio: u16, value: u32) -> Result<Vec<u8>> {
        Ok(match rtype {
            VIRTIO_GPIO_MSG_GET_LINE_NAMES => self.gpio_names.as_bytes().to_vec(),
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
