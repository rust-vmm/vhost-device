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

#[derive(Copy, Clone, Debug, PartialEq, ThisError)]
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
    #[cfg(test)]
    #[error("Gpio test Operation failed {0}")]
    GpioOperationFailed(&'static str),
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
#[derive(Clone, Debug, PartialEq)]
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

#[derive(Debug, Copy, Clone)]
struct LineState {
    dir: u8,
    val: Option<u16>,
}

#[derive(Debug)]
struct DeviceState<D: GpioDevice> {
    device: D,
    line_state: Vec<LineState>,
}

#[derive(Debug)]
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

#[cfg(test)]
pub mod tests {
    use super::Error;
    use super::*;

    #[derive(Debug)]
    pub(crate) struct DummyDevice {
        ngpio: u16,
        line_names: Vec<String>,
        line_state: Vec<LineState>,
        get_num_lines_result: Result<u16>,
        get_line_name_result: Result<String>,
        get_direction_result: Result<u8>,
        set_direction_result: Result<()>,
        get_value_result: Result<u8>,
        set_value_result: Result<()>,
    }

    impl DummyDevice {
        pub(crate) fn new(ngpio: u16) -> Self {
            Self {
                ngpio,
                line_names: vec!['\0'.to_string(); ngpio.into()],
                line_state: vec![
                    LineState {
                        dir: VIRTIO_GPIO_DIRECTION_NONE,
                        val: None,
                    };
                    ngpio.into()
                ],
                get_num_lines_result: Ok(0),
                get_line_name_result: Ok("".to_string()),
                get_direction_result: Ok(0),
                set_direction_result: Ok(()),
                get_value_result: Ok(0),
                set_value_result: Ok(()),
            }
        }
    }

    impl GpioDevice for DummyDevice {
        fn open(_device: u32) -> Result<Self>
        where
            Self: Sized,
        {
            Ok(DummyDevice::new(8))
        }

        fn get_num_lines(&self) -> Result<u16> {
            if self.get_num_lines_result.is_err() {
                return self.get_num_lines_result;
            }

            Ok(self.ngpio)
        }

        fn get_line_name(&self, gpio: u16) -> Result<String> {
            assert!((gpio as usize) < self.line_names.len());

            if self.get_line_name_result.is_err() {
                return self.get_line_name_result.clone();
            }

            Ok(self.line_names[gpio as usize].clone())
        }

        fn get_direction(&self, gpio: u16) -> Result<u8> {
            if self.get_direction_result.is_err() {
                return self.get_direction_result;
            }

            Ok(self.line_state[gpio as usize].dir)
        }

        fn set_direction(&mut self, gpio: u16, dir: u8, value: u32) -> Result<()> {
            if self.set_direction_result.is_err() {
                return self.set_direction_result;
            }

            self.line_state[gpio as usize].dir = dir;
            self.line_state[gpio as usize].val = match dir as u8 {
                VIRTIO_GPIO_DIRECTION_NONE => None,
                VIRTIO_GPIO_DIRECTION_IN => self.line_state[gpio as usize].val,
                VIRTIO_GPIO_DIRECTION_OUT => Some(value as u16),

                _ => return Err(Error::GpioDirectionInvalid(dir as u32)),
            };

            Ok(())
        }

        fn get_value(&self, gpio: u16) -> Result<u8> {
            if self.get_value_result.is_err() {
                return self.get_value_result;
            }

            if let Some(val) = self.line_state[gpio as usize].val {
                Ok(val as u8)
            } else {
                Err(Error::GpioCurrentValueInvalid)
            }
        }

        fn set_value(&mut self, gpio: u16, value: u32) -> Result<()> {
            if self.set_value_result.is_err() {
                return self.set_value_result;
            }

            self.line_state[gpio as usize].val = Some(value as u16);
            Ok(())
        }
    }

    #[test]
    fn test_verify_gpio_controller() {
        const NGPIO: u16 = 8;
        let line_names = vec![
            "gpio0".to_string(),
            '\0'.to_string(),
            "gpio2".to_string(),
            '\0'.to_string(),
            "gpio4".to_string(),
            '\0'.to_string(),
            "gpio6".to_string(),
            '\0'.to_string(),
        ];

        let mut device = DummyDevice::new(NGPIO);
        device.line_names.clear();
        device.line_names.append(&mut line_names.clone());
        let controller = GpioController::new(device).unwrap();

        assert_eq!(
            *controller.get_config(),
            VirtioGpioConfig {
                ngpio: From::from(NGPIO),
                padding: From::from(0),
                gpio_names_size: From::from(size_of_val(&line_names) as u32),
            }
        );

        let mut name = String::with_capacity(line_names.len());
        for i in line_names {
            name.push_str(&i);
            name.push('\0');
        }

        assert_eq!(
            controller
                .operation(VIRTIO_GPIO_MSG_GET_LINE_NAMES, 0, 0)
                .unwrap(),
            name.as_bytes()
        );

        for gpio in 0..NGPIO {
            // No initial value
            assert_eq!(
                controller
                    .operation(VIRTIO_GPIO_MSG_GET_VALUE, gpio, 0)
                    .unwrap_err(),
                Error::GpioCurrentValueInvalid
            );

            // No initial direction
            assert_eq!(
                controller
                    .operation(VIRTIO_GPIO_MSG_GET_DIRECTION, gpio, 0)
                    .unwrap(),
                vec![VIRTIO_GPIO_DIRECTION_NONE]
            );
        }
    }

    #[test]
    fn test_verify_gpio_operation() {
        const NGPIO: u16 = 256;
        let device = DummyDevice::new(NGPIO);
        let controller = GpioController::new(device).unwrap();

        for gpio in 0..NGPIO {
            // Set value first followed by direction
            controller
                .operation(VIRTIO_GPIO_MSG_SET_VALUE, gpio, 1)
                .unwrap();

            // Set direction OUT
            controller
                .operation(
                    VIRTIO_GPIO_MSG_SET_DIRECTION,
                    gpio,
                    VIRTIO_GPIO_DIRECTION_OUT as u32,
                )
                .unwrap();

            // Valid value
            assert_eq!(
                controller
                    .operation(VIRTIO_GPIO_MSG_GET_VALUE, gpio, 0)
                    .unwrap(),
                vec![1]
            );

            // Valid direction
            assert_eq!(
                controller
                    .operation(VIRTIO_GPIO_MSG_GET_DIRECTION, gpio, 0)
                    .unwrap(),
                vec![VIRTIO_GPIO_DIRECTION_OUT]
            );

            // Set direction IN
            controller
                .operation(
                    VIRTIO_GPIO_MSG_SET_DIRECTION,
                    gpio,
                    VIRTIO_GPIO_DIRECTION_IN as u32,
                )
                .unwrap();

            // Valid value retained here
            assert_eq!(
                controller
                    .operation(VIRTIO_GPIO_MSG_GET_VALUE, gpio, 0)
                    .unwrap(),
                vec![1]
            );

            // Valid direction
            assert_eq!(
                controller
                    .operation(VIRTIO_GPIO_MSG_GET_DIRECTION, gpio, 0)
                    .unwrap(),
                vec![VIRTIO_GPIO_DIRECTION_IN]
            );
        }
    }

    #[test]
    fn test_gpio_controller_new_failure() {
        const NGPIO: u16 = 256;
        // Get num lines failure
        let error = Error::GpioOperationFailed("get-num-lines");
        let mut device = DummyDevice::new(NGPIO);
        device.get_num_lines_result = Err(error);
        assert_eq!(GpioController::new(device).unwrap_err(), error);

        // Get line name failure
        let error = Error::GpioOperationFailed("get-line-name");
        let mut device = DummyDevice::new(NGPIO);
        device.get_line_name_result = Err(error);
        assert_eq!(GpioController::new(device).unwrap_err(), error);

        // Get direction failure
        let error = Error::GpioOperationFailed("get-direction");
        let mut device = DummyDevice::new(NGPIO);
        device.get_direction_result = Err(error);
        assert_eq!(GpioController::new(device).unwrap_err(), error);
    }

    #[test]
    fn test_gpio_set_direction_failure() {
        const NGPIO: u16 = 256;
        let device = DummyDevice::new(NGPIO);
        let controller = GpioController::new(device).unwrap();

        for gpio in 0..NGPIO {
            // Set direction out without setting value first
            assert_eq!(
                controller
                    .operation(
                        VIRTIO_GPIO_MSG_SET_DIRECTION,
                        gpio,
                        VIRTIO_GPIO_DIRECTION_OUT as u32,
                    )
                    .unwrap_err(),
                Error::GpioCurrentValueInvalid
            );

            // Set invalid direction
            let dir = 10;
            assert_eq!(
                controller
                    .operation(VIRTIO_GPIO_MSG_SET_DIRECTION, gpio, dir)
                    .unwrap_err(),
                Error::GpioDirectionInvalid(dir)
            );
        }
    }

    #[test]
    fn test_gpio_set_value_failure() {
        const NGPIO: u16 = 256;
        let device = DummyDevice::new(NGPIO);
        let controller = GpioController::new(device).unwrap();

        for gpio in 0..NGPIO {
            // Set invalid value
            let val = 10;
            assert_eq!(
                controller
                    .operation(VIRTIO_GPIO_MSG_SET_VALUE, gpio, val)
                    .unwrap_err(),
                Error::GpioValueInvalid(val)
            );
        }
    }

    #[test]
    fn test_gpio_operation_failure() {
        const NGPIO: u16 = 256;
        let device = DummyDevice::new(NGPIO);
        let controller = GpioController::new(device).unwrap();

        for gpio in 0..NGPIO {
            // Invalid operation
            assert_eq!(
                controller.operation(100, gpio, 0).unwrap_err(),
                Error::GpioMessageInvalid(100)
            );
        }
    }
}
