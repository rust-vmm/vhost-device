// GPIO backend device
//
// Copyright 2022 Linaro Ltd. All Rights Reserved.
//          Viresh Kumar <viresh.kumar@linaro.org>
//
// SPDX-License-Identifier: Apache-2.0 or BSD-3-Clause

use std::{
    sync::{Arc, Mutex, RwLock},
    time::Duration,
};

use libgpiod::{chip, line, request, Error as LibGpiodError};
use log::error;
use thiserror::Error as ThisError;
use vm_memory::{ByteValued, Le16, Le32};

use crate::virtio_gpio::*;

pub(crate) type Result<T> = std::result::Result<T, Error>;

#[derive(Copy, Clone, Debug, PartialEq, ThisError)]
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
    #[error("Gpio irq type invalid {0}")]
    GpioIrqTypeInvalid(u16),
    #[error("Gpio irq type not supported {0}")]
    GpioIrqTypeNotSupported(u16),
    #[error("Gpio irq type same as current {0}")]
    GpioIrqTypeNoChange(u16),
    #[error("Gpio irq not enabled yet")]
    GpioIrqNotEnabled,
    #[error(
        "Current Gpio irq type is valid, must configure to VIRTIO_GPIO_IRQ_TYPE_NONE first {0}"
    )]
    GpioOldIrqTypeValid(u16),
    #[error("Gpio line-request not configured")]
    GpioLineRequestNotConfigured,
    #[cfg(test)]
    #[error("Gpio test Operation failed {0}")]
    GpioOperationFailed(&'static str),
}

/// Virtio GPIO Configuration
#[derive(Copy, Clone, Debug, Default, PartialEq)]
#[repr(C)]
pub(crate) struct VirtioGpioConfig {
    pub(crate) ngpio: Le16,
    pub(crate) padding: Le16,
    pub(crate) gpio_names_size: Le32,
}

// SAFETY: The layout of the structure is fixed and can be initialized by
// reading its content from byte array.
unsafe impl ByteValued for VirtioGpioConfig {}

/// Trait that represents an GPIO Device.
///
/// This trait is introduced for development purposes only, and should not
/// be used outside of this crate. The purpose of this trait is to provide a
/// mock implementation for the GPIO driver so that we can test the GPIO
/// functionality without the need of a physical device.
pub(crate) trait GpioDevice: Send + Sync + 'static {
    fn open(device: u32) -> Result<Self>
    where
        Self: Sized;

    fn num_gpios(&self) -> Result<u16>;
    fn gpio_name(&self, gpio: u16) -> Result<String>;
    fn direction(&self, gpio: u16) -> Result<u8>;
    fn set_direction(&self, gpio: u16, dir: u8, value: u32) -> Result<()>;
    fn value(&self, gpio: u16) -> Result<u8>;
    fn set_value(&self, gpio: u16, value: u32) -> Result<()>;

    fn set_irq_type(&self, gpio: u16, value: u16) -> Result<()>;
    fn wait_for_interrupt(&self, gpio: u16) -> Result<bool>;
}

pub(crate) struct PhysLineState {
    // See wait_for_interrupt() for explanation of Arc.
    request: Option<Arc<Mutex<request::Request>>>,
    buffer: Option<request::Buffer>,
}

pub(crate) struct PhysDevice {
    chip: Mutex<chip::Chip>,
    ngpio: u16,
    state: Vec<Mutex<PhysLineState>>,
}

impl GpioDevice for PhysDevice {
    fn open(device: u32) -> Result<Self>
    where
        Self: Sized,
    {
        let path = format!("/dev/gpiochip{device}");
        let chip = chip::Chip::open(&path).map_err(Error::GpiodFailed)?;
        let ngpio = chip.info().map_err(Error::GpiodFailed)?.num_lines() as u16;

        // Can't set a vector to all None easily
        let mut state: Vec<Mutex<PhysLineState>> = Vec::new();
        state.resize_with(ngpio as usize, || {
            Mutex::new(PhysLineState {
                request: None,
                buffer: None,
            })
        });

        Ok(PhysDevice {
            chip: Mutex::new(chip),
            ngpio,
            state,
        })
    }

    fn num_gpios(&self) -> Result<u16> {
        Ok(self.ngpio)
    }

    fn gpio_name(&self, gpio: u16) -> Result<String> {
        let line_info = self
            .chip
            .lock()
            .unwrap()
            .line_info(gpio.into())
            .map_err(Error::GpiodFailed)?;

        Ok(line_info.name().unwrap_or("").to_string())
    }

    fn direction(&self, gpio: u16) -> Result<u8> {
        let line_info = self
            .chip
            .lock()
            .unwrap()
            .line_info(gpio.into())
            .map_err(Error::GpiodFailed)?;

        Ok(match line_info.direction().map_err(Error::GpiodFailed)? {
            line::Direction::AsIs => VIRTIO_GPIO_DIRECTION_NONE,
            line::Direction::Input => VIRTIO_GPIO_DIRECTION_IN,
            line::Direction::Output => VIRTIO_GPIO_DIRECTION_OUT,
        })
    }

    fn set_direction(&self, gpio: u16, dir: u8, value: u32) -> Result<()> {
        let mut lsettings = line::Settings::new().map_err(Error::GpiodFailed)?;
        let state = &mut self.state[gpio as usize].lock().unwrap();

        match dir {
            VIRTIO_GPIO_DIRECTION_NONE => {
                state.request = None;
                return Ok(());
            }

            VIRTIO_GPIO_DIRECTION_IN => {
                lsettings
                    .set_direction(line::Direction::Input)
                    .map_err(Error::GpiodFailed)?;
            }
            VIRTIO_GPIO_DIRECTION_OUT => {
                let value = line::Value::new(value as i32).map_err(Error::GpiodFailed)?;
                lsettings
                    .set_direction(line::Direction::Output)
                    .map_err(Error::GpiodFailed)?
                    .set_output_value(value)
                    .map_err(Error::GpiodFailed)?;
            }

            _ => return Err(Error::GpioDirectionInvalid(value)),
        };

        let mut lconfig = line::Config::new().map_err(Error::GpiodFailed)?;
        lconfig
            .add_line_settings(&[gpio as u32], lsettings)
            .map_err(Error::GpiodFailed)?;

        if let Some(request) = &mut state.request {
            request
                .lock()
                .unwrap()
                .reconfigure_lines(&lconfig)
                .map_err(Error::GpiodFailed)?;
        } else {
            let mut rconfig = request::Config::new().map_err(Error::GpiodFailed)?;

            rconfig
                .set_consumer("vhu-gpio")
                .map_err(Error::GpiodFailed)?;

            state.request = Some(Arc::new(Mutex::new(
                self.chip
                    .lock()
                    .unwrap()
                    .request_lines(Some(&rconfig), &lconfig)
                    .map_err(Error::GpiodFailed)?,
            )));
        }

        Ok(())
    }

    fn value(&self, gpio: u16) -> Result<u8> {
        let state = self.state[gpio as usize].lock().unwrap();

        if let Some(request) = &state.request {
            Ok(request
                .lock()
                .unwrap()
                .value(gpio as u32)
                .map_err(Error::GpiodFailed)? as u8)
        } else {
            Err(Error::GpioDirectionInvalid(
                VIRTIO_GPIO_DIRECTION_NONE as u32,
            ))
        }
    }

    fn set_value(&self, gpio: u16, value: u32) -> Result<()> {
        let mut state = self.state[gpio as usize].lock().unwrap();

        // Direction change can follow value change, don't fail here for invalid
        // direction.
        if let Some(request) = &mut state.request {
            let value = line::Value::new(value as i32).map_err(Error::GpiodFailed)?;
            request
                .lock()
                .unwrap()
                .set_value(gpio as u32, value)
                .map_err(Error::GpiodFailed)?;
        }

        Ok(())
    }

    fn set_irq_type(&self, gpio: u16, value: u16) -> Result<()> {
        let mut state = self.state[gpio as usize].lock().unwrap();

        let edge = match value {
            VIRTIO_GPIO_IRQ_TYPE_EDGE_RISING => line::Edge::Rising,
            VIRTIO_GPIO_IRQ_TYPE_EDGE_FALLING => line::Edge::Falling,
            VIRTIO_GPIO_IRQ_TYPE_EDGE_BOTH => line::Edge::Both,

            // Drop the buffer.
            VIRTIO_GPIO_IRQ_TYPE_NONE => {
                state.buffer = None;
                return Ok(());
            }

            // Only edge IRQs are supported for now.
            _ => return Err(Error::GpioIrqTypeNotSupported(value)),
        };

        if state.request.is_none() {
            return Err(Error::GpioLineRequestNotConfigured);
        }

        let mut lsettings = line::Settings::new().map_err(Error::GpiodFailed)?;
        lsettings
            .set_edge_detection(Some(edge))
            .map_err(Error::GpiodFailed)?;

        let mut lconfig = line::Config::new().map_err(Error::GpiodFailed)?;
        lconfig
            .add_line_settings(&[gpio as u32], lsettings)
            .map_err(Error::GpiodFailed)?;

        // Allocate the buffer and configure the line for interrupt.
        //
        // The GPIO Virtio specification allows a single interrupt event for each
        // `wait_for_interrupt()` message. And for that we need a single
        // `request::Buffer`.
        state.buffer = Some(request::Buffer::new(1).map_err(Error::GpiodFailed)?);

        state
            .request
            .as_mut()
            .unwrap()
            .lock()
            .unwrap()
            .reconfigure_lines(&lconfig)
            .map_err(Error::GpiodFailed)?;

        Ok(())
    }

    fn wait_for_interrupt(&self, gpio: u16) -> Result<bool> {
        // While waiting here for the interrupt to occur, it is possible that we receive
        // another request from the guest to disable the interrupt instead, via
        // a call to `set_irq_type()`.
        //
        // The interrupt design here should allow that call to return as soon as
        // possible, after disabling the interrupt and at the same time we need
        // to make sure that we don't end up freeing resources currently used by
        // `wait_for_interrupt()`.
        //
        // To allow that, the line state management is done via two resources: `request`
        // and `buffer`.
        //
        // The `request` is required by `wait_for_interrupt()` to query libgpiod and
        // must not get freed while we are waiting for an interrupt. This can
        // happen, for example, if another thread disables the interrupt, via
        // `set_irq_type(VIRTIO_GPIO_IRQ_TYPE_NONE)`, followed
        // by `set_direction(VIRTIO_GPIO_DIRECTION_NONE)`, where we drop the `request`.
        // For this reason, the `request` is implemented as an Arc instance.
        //
        // The `buffer` on the other hand is required only after we have sensed an
        // interrupt and need to read it. The design here takes advantage of
        // that and allows `set_irq_type()` to go and free the `buffer`, while
        // this routine is waiting for the interrupt. Once the waiting period is
        // over or an interrupt is sensed, `wait_for_interrupt() will find the
        // buffer being dropped and return an error which will be handled by
        // `Controller::wait_for_interrupt()`.
        //
        // This design also allows `wait_for_interrupt()` to not take a lock for the
        // entire duration, which can potentially also starve the other thread
        // trying to disable the interrupt.

        // Take the state lock, get the request and release the state lock again
        let request = {
            let mut state = self.state[gpio as usize].lock().unwrap();
            state
                .request
                .as_mut()
                .ok_or(Error::GpioIrqNotEnabled)?
                .clone()
        };

        // Only take the request lock now
        let request = request.lock().unwrap();

        // Wait for the interrupt for a second while only taking the request lock
        if !request
            .wait_edge_events(Some(Duration::new(1, 0)))
            .map_err(Error::GpiodFailed)?
        {
            return Ok(false);
        }

        // The interrupt has already occurred, we can lock the state again.
        let mut state = self.state[gpio as usize].lock().unwrap();
        if let Some(buffer) = &mut state.buffer {
            request
                .read_edge_events(buffer)
                .map_err(Error::GpiodFailed)?;

            Ok(true)
        } else {
            Err(Error::GpioLineRequestNotConfigured)
        }
    }
}

#[derive(Debug, Copy, Clone)]
pub(crate) struct GpioState {
    pub dir: u8,
    pub val: Option<u16>,
    pub irq_type: u16,
}

#[derive(Debug)]
pub(crate) struct GpioController<D: GpioDevice> {
    config: VirtioGpioConfig,
    device: D,
    state: Vec<RwLock<GpioState>>,
    gpio_names: String,
}

impl<D: GpioDevice> GpioController<D> {
    // Creates a new controller corresponding to `device`.
    pub(crate) fn new(device: D) -> Result<GpioController<D>> {
        let ngpio = device.num_gpios()?;

        // The gpio's name can be of any length, we are just trying to allocate
        // something reasonable to start with, we can always extend it later.
        let mut gpio_names = String::with_capacity((ngpio * 10).into());
        let mut state = Vec::with_capacity(ngpio as usize);

        for offset in 0..ngpio {
            let name = device.gpio_name(offset)?;

            // Create line names
            gpio_names.push_str(&name);
            gpio_names.push('\0');

            state.push(RwLock::new(GpioState {
                dir: device.direction(offset)?,
                val: None,
                irq_type: VIRTIO_GPIO_IRQ_TYPE_NONE,
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

    pub(crate) fn num_gpios(&self) -> u16 {
        self.device.num_gpios().unwrap()
    }

    fn direction(&self, gpio: u16) -> Result<u8> {
        self.device.direction(gpio)
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

    fn value(&self, gpio: u16) -> Result<u8> {
        self.device.value(gpio)
    }

    fn set_value(&self, gpio: u16, value: u32) -> Result<()> {
        if value > 1 {
            return Err(Error::GpioValueInvalid(value));
        }

        self.device.set_value(gpio, value)?;
        self.state[gpio as usize].write().unwrap().val = Some(value as u16);
        Ok(())
    }

    pub(crate) fn irq_type(&self, gpio: u16) -> u16 {
        self.state[gpio as usize].read().unwrap().irq_type
    }

    fn set_irq_type(&self, gpio: u16, value: u32) -> Result<()> {
        let irq_type = value as u16;

        // Invalid irq type
        if (irq_type & !VIRTIO_GPIO_IRQ_TYPE_ALL) != 0 {
            return Err(Error::GpioIrqTypeInvalid(irq_type));
        }

        // Begin critical section
        let state = &mut self.state[gpio as usize].write().unwrap();
        let prev_irq_type = state.irq_type;

        // New irq type same as current one.
        if irq_type == prev_irq_type {
            return Err(Error::GpioIrqTypeNoChange(irq_type));
        }

        // Must configure to VIRTIO_GPIO_IRQ_TYPE_NONE first before changing irq type.
        if prev_irq_type != VIRTIO_GPIO_IRQ_TYPE_NONE && irq_type != VIRTIO_GPIO_IRQ_TYPE_NONE {
            return Err(Error::GpioOldIrqTypeValid(prev_irq_type));
        }

        self.device.set_irq_type(gpio, irq_type)?;
        state.irq_type = irq_type;
        Ok(())
    }

    pub(crate) fn wait_for_interrupt(&self, gpio: u16) -> Result<()> {
        loop {
            if !self.device.wait_for_interrupt(gpio)? {
                continue;
            }

            // Event found
            return Ok(());
        }
    }

    pub(crate) fn config(&self) -> &VirtioGpioConfig {
        &self.config
    }

    pub(crate) fn operation(&self, rtype: u16, gpio: u16, value: u32) -> Result<Vec<u8>> {
        Ok(match rtype {
            VIRTIO_GPIO_MSG_GET_LINE_NAMES => self.gpio_names.as_bytes().to_vec(),
            VIRTIO_GPIO_MSG_GET_DIRECTION => vec![self.direction(gpio)?],
            VIRTIO_GPIO_MSG_SET_DIRECTION => {
                self.set_direction(gpio, value)?;
                vec![0]
            }
            VIRTIO_GPIO_MSG_GET_VALUE => vec![self.value(gpio)?],
            VIRTIO_GPIO_MSG_SET_VALUE => {
                self.set_value(gpio, value)?;
                vec![0]
            }
            VIRTIO_GPIO_MSG_IRQ_TYPE => {
                self.set_irq_type(gpio, value)?;
                vec![0]
            }
            msg => return Err(Error::GpioMessageInvalid(msg)),
        })
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use std::mem::size_of_val;

    use super::{Error, *};
    use crate::mock_gpio::MockGpioDevice;

    #[test]
    fn test_verify_gpio_controller() {
        const NGPIO: u16 = 8;
        let gpio_names = vec![
            "gpio0".to_string(),
            '\0'.to_string(),
            "gpio2".to_string(),
            '\0'.to_string(),
            "gpio4".to_string(),
            '\0'.to_string(),
            "gpio6".to_string(),
            '\0'.to_string(),
        ];

        // Controller adds '\0' for each line.
        let names_size = size_of_val(&gpio_names) + gpio_names.len();

        let mut device = MockGpioDevice::new(NGPIO);
        device.gpio_names.clear();
        device.gpio_names.append(&mut gpio_names.clone());
        let controller = GpioController::new(device).unwrap();

        assert_eq!(
            *controller.config(),
            VirtioGpioConfig {
                ngpio: From::from(NGPIO),
                padding: From::from(0),
                gpio_names_size: From::from(names_size as u32),
            }
        );

        let mut name = String::with_capacity(gpio_names.len());
        for i in gpio_names {
            name.push_str(&i);
            name.push('\0');
        }

        assert_eq!(controller.num_gpios(), NGPIO);

        assert_eq!(
            controller
                .operation(VIRTIO_GPIO_MSG_GET_LINE_NAMES, 0, 0)
                .unwrap(),
            name.as_bytes().to_vec()
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

            // No initial irq type
            assert_eq!(controller.irq_type(gpio), VIRTIO_GPIO_IRQ_TYPE_NONE);
        }
    }

    #[test]
    fn test_verify_gpio_operation() {
        const NGPIO: u16 = 256;
        let device = MockGpioDevice::new(NGPIO);
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

            // Set irq type rising
            controller
                .operation(
                    VIRTIO_GPIO_MSG_IRQ_TYPE,
                    gpio,
                    VIRTIO_GPIO_IRQ_TYPE_EDGE_RISING as u32,
                )
                .unwrap();

            // Verify interrupt type
            assert_eq!(controller.irq_type(gpio), VIRTIO_GPIO_IRQ_TYPE_EDGE_RISING);

            // Set irq type none
            controller
                .operation(
                    VIRTIO_GPIO_MSG_IRQ_TYPE,
                    gpio,
                    VIRTIO_GPIO_IRQ_TYPE_NONE as u32,
                )
                .unwrap();

            // Verify interrupt type
            assert_eq!(controller.irq_type(gpio), VIRTIO_GPIO_IRQ_TYPE_NONE);

            // Set irq type falling
            controller
                .operation(
                    VIRTIO_GPIO_MSG_IRQ_TYPE,
                    gpio,
                    VIRTIO_GPIO_IRQ_TYPE_EDGE_FALLING as u32,
                )
                .unwrap();

            // Verify interrupt type
            assert_eq!(controller.irq_type(gpio), VIRTIO_GPIO_IRQ_TYPE_EDGE_FALLING);

            // Set irq type none
            controller
                .operation(
                    VIRTIO_GPIO_MSG_IRQ_TYPE,
                    gpio,
                    VIRTIO_GPIO_IRQ_TYPE_NONE as u32,
                )
                .unwrap();

            // Verify interrupt type
            assert_eq!(controller.irq_type(gpio), VIRTIO_GPIO_IRQ_TYPE_NONE);

            // Set irq type both
            controller
                .operation(
                    VIRTIO_GPIO_MSG_IRQ_TYPE,
                    gpio,
                    VIRTIO_GPIO_IRQ_TYPE_EDGE_BOTH as u32,
                )
                .unwrap();

            // Verify interrupt type
            assert_eq!(controller.irq_type(gpio), VIRTIO_GPIO_IRQ_TYPE_EDGE_BOTH);
        }
    }

    #[test]
    fn test_gpio_controller_new_failure() {
        const NGPIO: u16 = 256;
        // Get num lines failure
        let error = Error::GpioOperationFailed("get-num-lines");
        let mut device = MockGpioDevice::new(NGPIO);
        device.num_gpios_result = Err(error);
        assert_eq!(GpioController::new(device).unwrap_err(), error);

        // Get line name failure
        let error = Error::GpioOperationFailed("get-line-name");
        let mut device = MockGpioDevice::new(NGPIO);
        device.gpio_name_result = Err(error);
        assert_eq!(GpioController::new(device).unwrap_err(), error);

        // Get direction failure
        let error = Error::GpioOperationFailed("get-direction");
        let mut device = MockGpioDevice::new(NGPIO);
        device.direction_result = Err(error);
        assert_eq!(GpioController::new(device).unwrap_err(), error);
    }

    #[test]
    fn test_gpio_set_direction_failure() {
        const NGPIO: u16 = 256;
        let device = MockGpioDevice::new(NGPIO);
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
        let device = MockGpioDevice::new(NGPIO);
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
    fn test_gpio_set_irq_type_failure() {
        const NGPIO: u16 = 256;
        let device = MockGpioDevice::new(NGPIO);
        let controller = GpioController::new(device).unwrap();

        for gpio in 0..NGPIO {
            // Set invalid irq type
            assert_eq!(
                controller
                    .operation(
                        VIRTIO_GPIO_MSG_IRQ_TYPE,
                        gpio,
                        (VIRTIO_GPIO_IRQ_TYPE_ALL + 1) as u32,
                    )
                    .unwrap_err(),
                Error::GpioIrqTypeInvalid(VIRTIO_GPIO_IRQ_TYPE_ALL + 1)
            );

            // Set irq type level none -> none
            assert_eq!(
                controller
                    .operation(
                        VIRTIO_GPIO_MSG_IRQ_TYPE,
                        gpio,
                        VIRTIO_GPIO_IRQ_TYPE_NONE as u32,
                    )
                    .unwrap_err(),
                Error::GpioIrqTypeNoChange(VIRTIO_GPIO_IRQ_TYPE_NONE)
            );

            // Set irq type level rising -> falling, without intermediate none
            controller
                .operation(
                    VIRTIO_GPIO_MSG_IRQ_TYPE,
                    gpio,
                    VIRTIO_GPIO_IRQ_TYPE_EDGE_RISING as u32,
                )
                .unwrap();

            assert_eq!(
                controller
                    .operation(
                        VIRTIO_GPIO_MSG_IRQ_TYPE,
                        gpio,
                        VIRTIO_GPIO_IRQ_TYPE_EDGE_FALLING as u32,
                    )
                    .unwrap_err(),
                Error::GpioOldIrqTypeValid(VIRTIO_GPIO_IRQ_TYPE_EDGE_RISING)
            );
        }
    }

    #[test]
    fn test_gpio_wait_for_interrupt_failure() {
        const NGPIO: u16 = 256;
        let err = Error::GpioIrqTypeInvalid(0);
        let mut device = MockGpioDevice::new(NGPIO);

        device.wait_for_irq_result = Err(err);

        let controller = GpioController::new(device).unwrap();

        for gpio in 0..NGPIO {
            assert_eq!(controller.wait_for_interrupt(gpio).unwrap_err(), err);
        }
    }

    #[test]
    fn test_gpio_operation_failure() {
        const NGPIO: u16 = 256;
        let device = MockGpioDevice::new(NGPIO);
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
