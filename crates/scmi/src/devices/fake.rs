// SPDX-FileCopyrightText: Red Hat, Inc.
// SPDX-License-Identifier: Apache-2.0

// Fake sensor

use crate::scmi::{DeviceResult, MessageValue, SENSOR_UNIT_METERS_PER_SECOND_SQUARED};

use super::common::{DeviceProperties, MaybeDevice, Sensor, SensorDevice, SensorT};

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
    pub fn new(properties: &DeviceProperties) -> MaybeDevice {
        properties.check(&[], &["name"])?;
        let sensor = Sensor::new(properties, "fake");
        let fake_sensor = Self { sensor, value: 0 };
        let sensor_device = SensorDevice(Box::new(fake_sensor));
        Ok(Box::new(sensor_device))
    }
}
