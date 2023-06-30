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
    devices.insert(String::from("fake"), FakeSensor::new);
    devices
}

pub struct FakeSensor {
    enabled: bool,
    value: u8,
    name: String,
}

impl FakeSensor {
    const NUMBER_OF_AXES: u32 = 3;

    #[allow(clippy::new_ret_no_self)]
    pub fn new() -> Box<dyn ScmiDevice> {
        let name = String::from("fake");
        let sensor = Self {
            enabled: false,
            value: 0,
            name,
        };
        Box::new(sensor)
    }
}

impl ScmiDevice for FakeSensor {
    fn configure(&mut self, properties: &DeviceProperties) -> Result<(), String> {
        for (k, v) in properties {
            if k == "name" {
                // TODO: Check for duplicate names
                self.name = String::from(v);
            } else {
                return Result::Err(format!("Invalid device option: {k}"));
            }
        }
        Ok(())
    }

    fn protocol(&self) -> ProtocolId {
        SENSOR_PROTOCOL_ID
    }

    fn handle(&mut self, message_id: MessageId, parameters: &[MessageValue]) -> DeviceResult {
        match message_id {
            SENSOR_DESCRIPTION_GET => {
                // Continuous update required by Linux SCMI IIO driver
                let low = 1 << 30;
                let high = Self::NUMBER_OF_AXES << 16 | 1 << 8;
                let name = self.name.clone();
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
            SENSOR_AXIS_DESCRIPTION_GET => {
                let axis_desc_index = parameters[0].get_unsigned();
                if axis_desc_index >= Self::NUMBER_OF_AXES {
                    return Result::Err(ScmiDeviceError::InvalidParameters);
                }
                let mut values = vec![MessageValue::Unsigned(
                    Self::NUMBER_OF_AXES - axis_desc_index,
                )];
                for i in axis_desc_index..Self::NUMBER_OF_AXES {
                    values.push(MessageValue::Unsigned(i)); // axis id
                    values.push(MessageValue::Unsigned(0)); // attributes low

                    // The sensor type is "Meters per second squared", since this is the
                    // only, together with "Radians per second", what Google Linux IIO
                    // supports (accelerometers and gyroscopes only).
                    values.push(MessageValue::Unsigned(
                        SENSOR_UNIT_METERS_PER_SECOND_SQUARED,
                    )); // attributes high

                    // Name in the recommended format, 16 bytes:
                    let axis = match i {
                        0 => 'X',
                        1 => 'Y',
                        2 => 'Z',
                        _ => 'N', // shouldn't be reached currently
                    };
                    values.push(MessageValue::String(format!("acc_{axis}").to_string(), 16));
                }
                Ok(values)
            }
            SENSOR_CONFIG_GET => {
                let config = u32::from(self.enabled);
                Ok(vec![MessageValue::Unsigned(config)])
            }
            SENSOR_CONFIG_SET => {
                let config = parameters[0].get_unsigned();
                if config & 0xFFFFFFFE != 0 {
                    return Result::Err(ScmiDeviceError::UnsupportedRequest);
                }
                self.enabled = config != 0;
                debug!("Sensor enabled: {}", self.enabled);
                Ok(vec![])
            }
            SENSOR_CONTINUOUS_UPDATE_NOTIFY => {
                // Linux VIRTIO SCMI insists on this.
                // We can accept it and ignore it, the sensor will be still working.
                Ok(vec![])
            }
            SENSOR_READING_GET => {
                if !self.enabled {
                    return Result::Err(ScmiDeviceError::NotEnabled);
                }
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
            _ => Result::Err(ScmiDeviceError::UnsupportedRequest),
        }
    }
}
