// SPDX-FileCopyrightText: Red Hat, Inc.
// SPDX-License-Identifier: Apache-2.0

use std::collections::HashMap;

use log::debug;

use crate::{
    scmi::{
        DeviceResult, MessageId, MessageValue, MessageValues, ProtocolId, ScmiDevice,
        ScmiDeviceError, MAX_SIMPLE_STRING_LENGTH, SENSOR_AXIS_DESCRIPTION_GET, SENSOR_CONFIG_GET,
        SENSOR_CONFIG_SET, SENSOR_CONTINUOUS_UPDATE_NOTIFY, SENSOR_DESCRIPTION_GET,
        SENSOR_PROTOCOL_ID, SENSOR_READING_GET, SENSOR_UNIT_METERS_PER_SECOND_SQUARED,
    },
    DeviceProperties,
};

type DeviceSpecification = fn() -> Box<dyn ScmiDevice>;
type NameDeviceMapping = HashMap<String, DeviceSpecification>;

pub fn available_devices() -> NameDeviceMapping {
    let mut devices: NameDeviceMapping = HashMap::new();
    devices.insert("fake".to_owned(), FakeSensor::new);
    devices
}

// Common sensor infrastructure

pub struct Sensor {
    name: String,
    enabled: bool,
}

impl Sensor {
    const fn new(default_name: String) -> Self {
        Self {
            name: default_name,
            enabled: false,
        }
    }
}

trait SensorT: Send {
    fn sensor(&self) -> &Sensor;
    fn sensor_mut(&mut self) -> &mut Sensor;

    fn protocol(&self) -> ProtocolId {
        SENSOR_PROTOCOL_ID
    }

    fn invalid_property(&self, name: &String) -> Result<(), String> {
        Result::Err(format!("Invalid device option: {name}"))
    }

    fn process_property(&mut self, name: &String, _value: &str) -> Result<(), String> {
        self.invalid_property(name)
    }

    fn configure(&mut self, properties: &DeviceProperties) -> Result<(), String> {
        for (name, value) in properties {
            if name == "name" {
                // TODO: Check for duplicate names
                self.sensor_mut().name = String::from(value);
            } else {
                self.process_property(name, value)?;
            }
        }
        Ok(())
    }

    fn number_of_axes(&self) -> u32 {
        1
    }

    fn description_get(&self) -> DeviceResult {
        // Continuous update required by Linux SCMI IIO driver
        let low = 1 << 30;
        let high = self.number_of_axes() << 16 | 1 << 8;
        let name = self.sensor().name.clone();
        let values: MessageValues = vec![
            // attributes low
            MessageValue::Unsigned(low),
            // attributes high
            MessageValue::Unsigned(high),
            // name, up to 16 bytes with final NULL (non-extended version)
            MessageValue::String(name, MAX_SIMPLE_STRING_LENGTH),
        ];
        Ok(values)
    }

    fn axis_unit(&self) -> u32;

    fn axis_name_prefix(&self) -> String {
        "axis".to_owned()
    }

    fn axis_name_suffix(&self, axis: u32) -> char {
        match axis {
            0 => 'X',
            1 => 'Y',
            2 => 'Z',
            _ => 'N', // shouldn't be reached currently
        }
    }

    fn axis_description(&self, axis: u32) -> Vec<MessageValue> {
        let mut values = vec![];
        values.push(MessageValue::Unsigned(axis)); // axis id
        values.push(MessageValue::Unsigned(0)); // attributes low
        values.push(MessageValue::Unsigned(self.axis_unit())); // attributes high

        // Name in the recommended format, 16 bytes:
        let prefix = self.axis_name_prefix();
        let suffix = self.axis_name_suffix(axis);
        values.push(MessageValue::String(
            format!("{prefix}_{suffix}"),
            MAX_SIMPLE_STRING_LENGTH,
        ));
        values
    }

    fn config_get(&self) -> DeviceResult {
        let config = u32::from(self.sensor().enabled);
        Ok(vec![MessageValue::Unsigned(config)])
    }

    fn config_set(&mut self, config: u32) -> DeviceResult {
        if config & 0xFFFFFFFE != 0 {
            return Result::Err(ScmiDeviceError::UnsupportedRequest);
        }
        self.sensor_mut().enabled = config != 0;
        debug!("Sensor enabled: {}", self.sensor().enabled);
        Ok(vec![])
    }

    fn reading_get(&mut self) -> DeviceResult;

    fn handle(&mut self, message_id: MessageId, parameters: &[MessageValue]) -> DeviceResult {
        match message_id {
            SENSOR_DESCRIPTION_GET => self.description_get(),
            SENSOR_AXIS_DESCRIPTION_GET => {
                let n_sensor_axes = self.number_of_axes();
                let axis_desc_index = parameters[0].get_unsigned();
                if axis_desc_index >= n_sensor_axes {
                    return Result::Err(ScmiDeviceError::InvalidParameters);
                }
                let mut values = vec![MessageValue::Unsigned(n_sensor_axes - axis_desc_index)];
                for i in axis_desc_index..n_sensor_axes {
                    let mut description = self.axis_description(i);
                    values.append(&mut description);
                }
                Ok(values)
            }
            SENSOR_CONFIG_GET => self.config_get(),
            SENSOR_CONFIG_SET => {
                let config = parameters[0].get_unsigned();
                self.config_set(config)
            }
            SENSOR_CONTINUOUS_UPDATE_NOTIFY => {
                // Linux VIRTIO SCMI insists on this.
                // We can accept it and ignore it, the sensor will be still working.
                Ok(vec![])
            }
            SENSOR_READING_GET => {
                if !self.sensor().enabled {
                    return Result::Err(ScmiDeviceError::NotEnabled);
                }
                self.reading_get()
            }
            _ => Result::Err(ScmiDeviceError::UnsupportedRequest),
        }
    }
}

// It's possible to impl ScmiDevice for SensorT but it is not very useful
// because it doesn't allow to pass SensorT as ScmiDevice directly.
// Hence this wrapper.
struct SensorDevice(Box<dyn SensorT>);

impl ScmiDevice for SensorDevice {
    fn configure(&mut self, properties: &DeviceProperties) -> Result<(), String> {
        self.0.configure(properties)
    }

    fn protocol(&self) -> ProtocolId {
        self.0.protocol()
    }

    fn handle(&mut self, message_id: MessageId, parameters: &[MessageValue]) -> DeviceResult {
        self.0.handle(message_id, parameters)
    }
}

// Particular sensor implementations

pub struct FakeSensor {
    sensor: Sensor,
    value: u8,
}

impl SensorT for FakeSensor {
    // TODO: Define a macro for this boilerplate?
    fn sensor(&self) -> &Sensor {
        &self.sensor
    }
    fn sensor_mut(&mut self) -> &mut Sensor {
        &mut self.sensor
    }

    fn number_of_axes(&self) -> u32 {
        3
    }

    fn axis_unit(&self) -> u32 {
        // The sensor type is "Meters per second squared", since this is the
        // only, together with "Radians per second", what Google Linux IIO
        // supports (accelerometers and gyroscopes only).
        SENSOR_UNIT_METERS_PER_SECOND_SQUARED
    }

    fn axis_name_prefix(&self) -> String {
        "acc".to_owned()
    }

    fn reading_get(&mut self) -> DeviceResult {
        let value = self.value;
        self.value = self.value.overflowing_add(1).0;
        let mut result = vec![];
        for i in 0..3 {
            result.push(MessageValue::Unsigned(u32::from(value) + 100 * i));
            result.push(MessageValue::Unsigned(0));
            result.push(MessageValue::Unsigned(0));
            result.push(MessageValue::Unsigned(0));
        }
        Ok(result)
    }
}

impl FakeSensor {
    #[allow(clippy::new_ret_no_self)]
    pub fn new() -> Box<dyn ScmiDevice> {
        let sensor = Sensor::new("fake".to_owned());
        let fake_sensor = Self { sensor, value: 0 };
        let sensor_device = SensorDevice(Box::new(fake_sensor));
        Box::new(sensor_device)
    }
}
