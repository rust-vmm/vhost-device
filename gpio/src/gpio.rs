// GPIO backend device
//
// Copyright 2022 Linaro Ltd. All Rights Reserved.
//          Viresh Kumar <viresh.kumar@linaro.org>
//
// SPDX-License-Identifier: Apache-2.0

use log::error;
use std::sync::{Arc, RwLock};
use std::time::Duration;

use libgpiod::{
    Chip, Direction, Edge, EdgeEventBuffer, Error as LibGpiodError, LineConfig, LineRequest,
    RequestConfig,
};
use thiserror::Error as ThisError;
use vm_memory::{ByteValued, Le16, Le32};

type Result<T> = std::result::Result<T, Error>;

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
    #[error("Gpio irq operation timed out")]
    GpioIrqOpTimedOut,
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

/// Virtio specification definitions
/// Virtio GPIO request types
pub(crate) const VIRTIO_GPIO_MSG_GET_LINE_NAMES: u16 = 0x0001;
pub(crate) const VIRTIO_GPIO_MSG_GET_DIRECTION: u16 = 0x0002;
pub(crate) const VIRTIO_GPIO_MSG_SET_DIRECTION: u16 = 0x0003;
pub(crate) const VIRTIO_GPIO_MSG_GET_VALUE: u16 = 0x0004;
pub(crate) const VIRTIO_GPIO_MSG_SET_VALUE: u16 = 0x0005;
pub(crate) const VIRTIO_GPIO_MSG_IRQ_TYPE: u16 = 0x0006;

/// Direction types
pub(crate) const VIRTIO_GPIO_DIRECTION_NONE: u8 = 0x00;
pub(crate) const VIRTIO_GPIO_DIRECTION_OUT: u8 = 0x01;
pub(crate) const VIRTIO_GPIO_DIRECTION_IN: u8 = 0x02;

/// Virtio GPIO IRQ types
pub(crate) const VIRTIO_GPIO_IRQ_TYPE_NONE: u16 = 0x00;
pub(crate) const VIRTIO_GPIO_IRQ_TYPE_EDGE_RISING: u16 = 0x01;
pub(crate) const VIRTIO_GPIO_IRQ_TYPE_EDGE_FALLING: u16 = 0x02;
pub(crate) const VIRTIO_GPIO_IRQ_TYPE_EDGE_BOTH: u16 =
    VIRTIO_GPIO_IRQ_TYPE_EDGE_RISING | VIRTIO_GPIO_IRQ_TYPE_EDGE_FALLING;
pub(crate) const VIRTIO_GPIO_IRQ_TYPE_LEVEL_HIGH: u16 = 0x04;
pub(crate) const VIRTIO_GPIO_IRQ_TYPE_LEVEL_LOW: u16 = 0x08;
const VIRTIO_GPIO_IRQ_TYPE_ALL: u16 = VIRTIO_GPIO_IRQ_TYPE_EDGE_BOTH
    | VIRTIO_GPIO_IRQ_TYPE_LEVEL_HIGH
    | VIRTIO_GPIO_IRQ_TYPE_LEVEL_LOW;

/// Virtio GPIO Configuration
#[derive(Copy, Clone, Debug, Default, PartialEq)]
#[repr(C)]
pub(crate) struct VirtioGpioConfig {
    pub(crate) ngpio: Le16,
    pub(crate) padding: Le16,
    pub(crate) gpio_names_size: Le32,
}

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

    fn get_num_gpios(&self) -> Result<u16>;
    fn get_gpio_name(&self, gpio: u16) -> Result<String>;
    fn get_direction(&self, gpio: u16) -> Result<u8>;
    fn set_direction(&self, gpio: u16, dir: u8, value: u32) -> Result<()>;
    fn get_value(&self, gpio: u16) -> Result<u8>;
    fn set_value(&self, gpio: u16, value: u32) -> Result<()>;

    fn set_irq_type(&self, gpio: u16, value: u16) -> Result<()>;
    fn wait_for_interrupt(&self, gpio: u16) -> Result<()>;
}

pub(crate) struct PhysLineState {
    // See wait_for_interrupt() for explanation of Arc.
    request: Option<Arc<LineRequest>>,
    buffer: Option<EdgeEventBuffer>,
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
                buffer: None,
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

            state.request = Some(Arc::new(
                self.chip
                    .request_lines(&rconfig, &config)
                    .map_err(Error::GpiodFailed)?,
            ));
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

    fn set_irq_type(&self, gpio: u16, value: u16) -> Result<()> {
        let state = &mut self.state[gpio as usize].write().unwrap();
        let mut config = LineConfig::new().map_err(Error::GpiodFailed)?;

        match value as u16 {
            VIRTIO_GPIO_IRQ_TYPE_EDGE_RISING => config.set_edge_detection(Edge::Rising),
            VIRTIO_GPIO_IRQ_TYPE_EDGE_FALLING => config.set_edge_detection(Edge::Falling),
            VIRTIO_GPIO_IRQ_TYPE_EDGE_BOTH => config.set_edge_detection(Edge::Both),

            // Drop the buffer.
            VIRTIO_GPIO_IRQ_TYPE_NONE => {
                state.buffer = None;
                return Ok(());
            }

            // Only edge IRQs are supported for now.
            _ => return Err(Error::GpioIrqTypeNotSupported(value)),
        };

        // Allocate the buffer and configure the line for interrupt.
        if state.request.is_none() {
            Err(Error::GpioLineRequestNotConfigured)
        } else {
            // The GPIO Virtio specification allows a single interrupt event for each
            // `wait_for_interrupt()` message. And for that we need a single `EdgeEventBuffer`.
            state.buffer = Some(EdgeEventBuffer::new(1).map_err(Error::GpiodFailed)?);

            state
                .request
                .as_ref()
                .unwrap()
                .reconfigure_lines(&config)
                .map_err(Error::GpiodFailed)
        }
    }

    fn wait_for_interrupt(&self, gpio: u16) -> Result<()> {
        // While waiting here for the interrupt to occur, it is possible that we receive another
        // request from the guest to disable the interrupt instead, via a call to `set_irq_type()`.
        //
        // The interrupt design here should allow that call to return as soon as possible, after
        // disabling the interrupt and at the same time we need to make sure that we don't end up
        // freeing resources currently used by `wait_for_interrupt()`.
        //
        // To allow that, the line state management is done via two resources: `request` and
        // `buffer`.
        //
        // The `request` is required by `wait_for_interrupt()` to query libgpiod and must not get
        // freed while we are waiting for an interrupt. This can happen, for example, if another
        // thread disables the interrupt, via `set_irq_type(VIRTIO_GPIO_IRQ_TYPE_NONE)`, followed
        // by `set_direction(VIRTIO_GPIO_DIRECTION_NONE)`, where we drop the `request`. For this
        // reason, the `request` is implemented as an Arc instance.
        //
        // The `buffer` on the other hand is required only after we have sensed an interrupt and
        // need to read it. The design here takes advantage of that and allows `set_irq_type()` to
        // go and free the `buffer`, while this routine is waiting for the interrupt. Once the
        // waiting period is over or an interrupt is sensed, `wait_for_interrupt() will find the
        // buffer being dropped and return an error which will be handled by
        // `Controller::wait_for_interrupt()`.
        //
        // This design also allows `wait_for_interrupt()` to not take a lock for the entire
        // duration, which can potentially also starve the other thread trying to disable the
        // interrupt.
        let request = {
            let state = &self.state[gpio as usize].write().unwrap();

            match &state.request {
                Some(x) => x.clone(),
                None => return Err(Error::GpioIrqNotEnabled),
            }
        };

        // Wait for the interrupt for a second.
        match request.edge_event_wait(Duration::new(1, 0)) {
            Err(LibGpiodError::OperationTimedOut) => return Err(Error::GpioIrqOpTimedOut),
            x => x.map_err(Error::GpiodFailed)?,
        }

        // The interrupt has already occurred, we can lock now just fine.
        let state = &self.state[gpio as usize].write().unwrap();
        if let Some(buffer) = &state.buffer {
            request
                .edge_event_read(buffer, 1)
                .map_err(Error::GpiodFailed)?;

            Ok(())
        } else {
            Err(Error::GpioLineRequestNotConfigured)
        }
    }
}

#[derive(Debug, Copy, Clone)]
struct GpioState {
    dir: u8,
    val: Option<u16>,
    irq_type: u16,
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

    pub(crate) fn get_num_gpios(&self) -> u16 {
        self.device.get_num_gpios().unwrap()
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

    pub(crate) fn get_irq_type(&self, gpio: u16) -> u16 {
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
            match self.device.wait_for_interrupt(gpio) {
                Err(Error::GpioIrqOpTimedOut) => continue,
                Ok(_) => return Ok(()),
                x => x?,
            }
        }
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

    use super::Error;
    use super::*;

    #[derive(Debug)]
    pub(crate) struct DummyDevice {
        ngpio: u16,
        pub(crate) gpio_names: Vec<String>,
        state: RwLock<Vec<GpioState>>,
        get_num_gpios_result: Result<u16>,
        get_gpio_name_result: Result<String>,
        get_direction_result: Result<u8>,
        set_direction_result: Result<()>,
        get_value_result: Result<u8>,
        set_value_result: Result<()>,
        set_irq_type_result: Result<()>,
        pub(crate) wait_for_irq_result: Result<()>,
    }

    impl DummyDevice {
        pub(crate) fn new(ngpio: u16) -> Self {
            Self {
                ngpio,
                gpio_names: vec!['\0'.to_string(); ngpio.into()],
                state: RwLock::new(vec![
                    GpioState {
                        dir: VIRTIO_GPIO_DIRECTION_NONE,
                        val: None,
                        irq_type: VIRTIO_GPIO_IRQ_TYPE_NONE,
                    };
                    ngpio.into()
                ]),
                get_num_gpios_result: Ok(0),
                get_gpio_name_result: Ok("".to_string()),
                get_direction_result: Ok(0),
                set_direction_result: Ok(()),
                get_value_result: Ok(0),
                set_value_result: Ok(()),
                set_irq_type_result: Ok(()),
                wait_for_irq_result: Ok(()),
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

        fn get_num_gpios(&self) -> Result<u16> {
            if self.get_num_gpios_result.is_err() {
                return self.get_num_gpios_result;
            }

            Ok(self.ngpio)
        }

        fn get_gpio_name(&self, gpio: u16) -> Result<String> {
            assert!((gpio as usize) < self.gpio_names.len());

            if self.get_gpio_name_result.is_err() {
                return self.get_gpio_name_result.clone();
            }

            Ok(self.gpio_names[gpio as usize].clone())
        }

        fn get_direction(&self, gpio: u16) -> Result<u8> {
            if self.get_direction_result.is_err() {
                return self.get_direction_result;
            }

            Ok(self.state.read().unwrap()[gpio as usize].dir)
        }

        fn set_direction(&self, gpio: u16, dir: u8, value: u32) -> Result<()> {
            if self.set_direction_result.is_err() {
                return self.set_direction_result;
            }

            self.state.write().unwrap()[gpio as usize].dir = dir;
            self.state.write().unwrap()[gpio as usize].val = match dir as u8 {
                VIRTIO_GPIO_DIRECTION_NONE => None,
                VIRTIO_GPIO_DIRECTION_IN => self.state.read().unwrap()[gpio as usize].val,
                VIRTIO_GPIO_DIRECTION_OUT => Some(value as u16),

                _ => return Err(Error::GpioDirectionInvalid(dir as u32)),
            };

            Ok(())
        }

        fn get_value(&self, gpio: u16) -> Result<u8> {
            if self.get_value_result.is_err() {
                return self.get_value_result;
            }

            if let Some(val) = self.state.read().unwrap()[gpio as usize].val {
                Ok(val as u8)
            } else {
                Err(Error::GpioCurrentValueInvalid)
            }
        }

        fn set_value(&self, gpio: u16, value: u32) -> Result<()> {
            if self.set_value_result.is_err() {
                return self.set_value_result;
            }

            self.state.write().unwrap()[gpio as usize].val = Some(value as u16);
            Ok(())
        }

        fn set_irq_type(&self, _gpio: u16, _value: u16) -> Result<()> {
            if self.set_irq_type_result.is_err() {
                return self.set_irq_type_result;
            }

            Ok(())
        }

        fn wait_for_interrupt(&self, _gpio: u16) -> Result<()> {
            if self.wait_for_irq_result.is_err() {
                return self.wait_for_irq_result;
            }

            Ok(())
        }
    }

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

        let mut device = DummyDevice::new(NGPIO);
        device.gpio_names.clear();
        device.gpio_names.append(&mut gpio_names.clone());
        let controller = GpioController::new(device).unwrap();

        assert_eq!(
            *controller.get_config(),
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

        assert_eq!(controller.get_num_gpios(), NGPIO);

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
            assert_eq!(controller.get_irq_type(gpio), VIRTIO_GPIO_IRQ_TYPE_NONE);
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

            // Set irq type rising
            controller
                .operation(
                    VIRTIO_GPIO_MSG_IRQ_TYPE,
                    gpio,
                    VIRTIO_GPIO_IRQ_TYPE_EDGE_RISING as u32,
                )
                .unwrap();

            // Verify interrupt type
            assert_eq!(
                controller.get_irq_type(gpio),
                VIRTIO_GPIO_IRQ_TYPE_EDGE_RISING,
            );

            // Set irq type none
            controller
                .operation(
                    VIRTIO_GPIO_MSG_IRQ_TYPE,
                    gpio,
                    VIRTIO_GPIO_IRQ_TYPE_NONE as u32,
                )
                .unwrap();

            // Verify interrupt type
            assert_eq!(controller.get_irq_type(gpio), VIRTIO_GPIO_IRQ_TYPE_NONE);

            // Set irq type falling
            controller
                .operation(
                    VIRTIO_GPIO_MSG_IRQ_TYPE,
                    gpio,
                    VIRTIO_GPIO_IRQ_TYPE_EDGE_FALLING as u32,
                )
                .unwrap();

            // Verify interrupt type
            assert_eq!(
                controller.get_irq_type(gpio),
                VIRTIO_GPIO_IRQ_TYPE_EDGE_FALLING,
            );

            // Set irq type none
            controller
                .operation(
                    VIRTIO_GPIO_MSG_IRQ_TYPE,
                    gpio,
                    VIRTIO_GPIO_IRQ_TYPE_NONE as u32,
                )
                .unwrap();

            // Verify interrupt type
            assert_eq!(controller.get_irq_type(gpio), VIRTIO_GPIO_IRQ_TYPE_NONE);

            // Set irq type both
            controller
                .operation(
                    VIRTIO_GPIO_MSG_IRQ_TYPE,
                    gpio,
                    VIRTIO_GPIO_IRQ_TYPE_EDGE_BOTH as u32,
                )
                .unwrap();

            // Verify interrupt type
            assert_eq!(
                controller.get_irq_type(gpio),
                VIRTIO_GPIO_IRQ_TYPE_EDGE_BOTH,
            );
        }
    }

    #[test]
    fn test_gpio_controller_new_failure() {
        const NGPIO: u16 = 256;
        // Get num lines failure
        let error = Error::GpioOperationFailed("get-num-lines");
        let mut device = DummyDevice::new(NGPIO);
        device.get_num_gpios_result = Err(error);
        assert_eq!(GpioController::new(device).unwrap_err(), error);

        // Get line name failure
        let error = Error::GpioOperationFailed("get-line-name");
        let mut device = DummyDevice::new(NGPIO);
        device.get_gpio_name_result = Err(error);
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
    fn test_gpio_set_irq_type_failure() {
        const NGPIO: u16 = 256;
        let device = DummyDevice::new(NGPIO);
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
        let mut device = DummyDevice::new(NGPIO);

        device.wait_for_irq_result = Err(err);

        let controller = GpioController::new(device).unwrap();

        for gpio in 0..NGPIO {
            assert_eq!(controller.wait_for_interrupt(gpio).unwrap_err(), err);
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
