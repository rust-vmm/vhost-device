// SPDX-FileCopyrightText: Red Hat, Inc.
// SPDX-License-Identifier: Apache-2.0

use std::collections::{HashMap, HashSet};
use std::ffi::OsString;
use std::fmt::Write;
use std::process::exit;

use itertools::Itertools;
use log::debug;
use thiserror::Error as ThisError;

use crate::scmi::{
    self, DeviceResult, MessageId, MessageValue, MessageValues, ProtocolId, ScmiDevice,
    ScmiDeviceError, MAX_SIMPLE_STRING_LENGTH, SENSOR_AXIS_DESCRIPTION_GET, SENSOR_CONFIG_GET,
    SENSOR_CONFIG_SET, SENSOR_CONTINUOUS_UPDATE_NOTIFY, SENSOR_DESCRIPTION_GET, SENSOR_PROTOCOL_ID,
    SENSOR_READING_GET,
};

use super::{fake, iio};

enum ExitCodes {
    Help = 1,
}

#[derive(Debug, ThisError)]
pub enum DeviceError {
    #[error("{0}")]
    GenericError(String),
    #[error("Invalid device parameter: {0}")]
    InvalidProperty(String),
    #[error("I/O error on {0:?}: {1}")]
    IOError(OsString, std::io::Error),
    #[error("Missing device parameters: {}", .0.join(", "))]
    MissingDeviceProperties(Vec<String>),
    #[error("Unexpected device parameters: {}", .0.join(", "))]
    UnexpectedDeviceProperties(Vec<String>),
}

// [(NAME, [(PROPERTY, VALUE), ...]), ...]
pub type DeviceDescription = Vec<(String, DeviceProperties)>;
type PropertyPairs = Vec<(String, String)>;

#[derive(Debug, Eq, PartialEq, Hash)]
pub struct DeviceProperties(PropertyPairs);

impl DeviceProperties {
    pub(crate) fn new(properties: PropertyPairs) -> Self {
        Self(properties)
    }

    pub(crate) fn get(&self, name: &str) -> Option<&str> {
        self.0
            .iter()
            .find(|(n, _)| n == name)
            .map(|(_, v)| v.as_str())
    }

    fn names(&self) -> HashSet<&str> {
        self.0.iter().map(|(n, _)| -> &str { n.as_str() }).collect()
    }

    fn extra<'a>(&'a self, allowed: &[&'a str]) -> HashSet<&str> {
        let allowed_set: HashSet<&str> = HashSet::from_iter(allowed.iter().copied());
        self.names().difference(&allowed_set).copied().collect()
    }

    fn missing<'a>(&'a self, required: &[&'a str]) -> HashSet<&str> {
        let required_set: HashSet<&str> = HashSet::from_iter(required.iter().copied());
        required_set.difference(&self.names()).copied().collect()
    }

    pub(crate) fn check(&self, required: &[&str], optional: &[&str]) -> Result<(), DeviceError> {
        let missing = self.missing(required);
        if !missing.is_empty() {
            return Err(DeviceError::MissingDeviceProperties(
                missing
                    .iter()
                    .sorted()
                    .map(|s| (*s).to_owned())
                    .collect::<Vec<String>>(),
            ));
        }
        let mut all_allowed = Vec::from(required);
        all_allowed.extend(optional.iter());
        let extra = self.extra(&all_allowed);
        if !extra.is_empty() {
            return Err(DeviceError::UnexpectedDeviceProperties(
                extra
                    .iter()
                    .sorted()
                    .map(|s| (*s).to_owned())
                    .collect::<Vec<String>>(),
            ));
        }
        Ok(())
    }
}

pub type MaybeDevice = Result<Box<dyn ScmiDevice>, DeviceError>;
type DeviceConstructor = fn(&DeviceProperties) -> MaybeDevice;

pub struct DeviceSpecification {
    pub(crate) constructor: DeviceConstructor,
    short_help: String,
    long_help: String,
    parameters_help: Vec<String>,
}

impl DeviceSpecification {
    fn new(
        constructor: DeviceConstructor,
        short_help: &str,
        long_help: &str,
        parameters_help: &[&str],
    ) -> Self {
        Self {
            constructor,
            short_help: short_help.to_owned(),
            long_help: long_help.to_owned(),
            parameters_help: parameters_help
                .iter()
                .map(|s| String::from(*s))
                .collect::<Vec<String>>(),
        }
    }
}

type NameDeviceMapping = HashMap<&'static str, DeviceSpecification>;

pub fn available_devices() -> NameDeviceMapping {
    let mut devices: NameDeviceMapping = HashMap::new();
    devices.insert(
        "fake",
        DeviceSpecification::new(
            fake::FakeSensor::new_device,
            "fake accelerometer",
            "A simple 3-axes sensor providing fake pre-defined values.",
            &["name: an optional name of the sensor, max. 15 characters"],
        ),
    );
    devices.insert(
        "iio",
        DeviceSpecification::new(
            iio::IIOSensor::new_device,
            "industrial I/O sensor",
            "",
            &[
                "path: path to the device directory (e.g. /sys/bus/iio/devices/iio:device0)",
                "channel: prefix of the device type (e.g. in_accel)",
                "name: an optional name of the sensor, max. 15 characters",
            ],
        ),
    );
    devices
}

fn devices_help() -> String {
    let mut help = String::new();
    writeln!(help, "Available devices:").unwrap();
    for (name, specification) in available_devices().iter() {
        let short_help = &specification.short_help;
        let long_help = &specification.long_help;
        let parameters_help = &specification.parameters_help;
        writeln!(help, "\n- {name}: {short_help}").unwrap();
        for line in long_help.lines() {
            writeln!(help, "  {line}").unwrap();
        }
        if !parameters_help.is_empty() {
            writeln!(help, "  Parameters:").unwrap();
            for parameter in parameters_help {
                writeln!(help, "  - {parameter}").unwrap();
            }
        }
    }
    writeln!(help, "\nDevice specification example:").unwrap();
    writeln!(
        help,
        "--device iio,path=/sys/bus/iio/devices/iio:device0,channel=in_accel"
    )
    .unwrap();
    help
}

pub fn print_devices_help() {
    let help = devices_help();
    println!("{}", help);
    exit(ExitCodes::Help as i32);
}

// Common sensor infrastructure

#[derive(Debug)]
pub struct Sensor {
    pub name: String,
    enabled: bool,
}

impl Sensor {
    pub fn new(properties: &DeviceProperties, default_name: &str) -> Self {
        let name = properties.get("name").unwrap_or(default_name);
        Self {
            name: name.to_owned(),
            enabled: false,
        }
    }
}

pub trait SensorT: Send {
    fn sensor(&self) -> &Sensor;
    fn sensor_mut(&mut self) -> &mut Sensor;

    fn initialize(&mut self) -> Result<(), DeviceError> {
        Ok(())
    }

    fn protocol(&self) -> ProtocolId {
        SENSOR_PROTOCOL_ID
    }

    fn invalid_property(&self, name: &str) -> Result<(), DeviceError> {
        Result::Err(DeviceError::InvalidProperty(name.to_owned()))
    }

    fn process_property(&mut self, name: &str, _value: &str) -> Result<(), DeviceError> {
        self.invalid_property(name)
    }

    fn number_of_axes(&self) -> u32 {
        0
    }

    fn format_unit(&self, axis: u32) -> u32 {
        (self.unit_exponent(axis) as u32 & 0x1F) << 11 | u32::from(self.unit())
    }

    fn description_get(&self) -> DeviceResult {
        // Continuous update required by Linux SCMI IIO driver
        let low = 1 << 30;
        let n_axes = self.number_of_axes();
        let high = if n_axes > 0 {
            n_axes << 16 | 1 << 8
        } else {
            self.format_unit(0)
        };
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

    fn unit(&self) -> u8 {
        scmi::SENSOR_UNIT_UNSPECIFIED
    }

    fn unit_exponent(&self, _axis: u32) -> i8 {
        0
    }

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
        values.push(MessageValue::Unsigned(self.format_unit(axis))); // attributes high

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
pub struct SensorDevice(pub(crate) Box<dyn SensorT>);

impl ScmiDevice for SensorDevice {
    fn initialize(&mut self) -> Result<(), DeviceError> {
        self.0.initialize()
    }

    fn protocol(&self) -> ProtocolId {
        self.0.protocol()
    }

    fn handle(&mut self, message_id: MessageId, parameters: &[MessageValue]) -> DeviceResult {
        self.0.handle(message_id, parameters)
    }
}

#[cfg(test)]
mod tests {
    use std::assert_eq;

    use super::*;

    #[test]
    fn test_help() {
        let help = devices_help();
        assert!(
            help.contains("Available devices:\n"),
            "global label missing"
        );
        assert!(help.contains("fake:"), "sensor name missing");
        assert!(
            help.contains("fake accelerometer"),
            "short description missing"
        );
        assert!(help.contains("3-axes sensor"), "long description missing");
        assert!(help.contains("Parameters:\n"), "parameter label missing");
        assert!(help.contains("- name:"), "parameter `name' missing");
    }

    fn device_properties() -> DeviceProperties {
        DeviceProperties::new(vec![
            ("foo".to_owned(), "val1".to_owned()),
            ("def".to_owned(), "val2".to_owned()),
            ("bar".to_owned(), "val3".to_owned()),
        ])
    }

    #[test]
    fn test_device_properties() {
        let properties = device_properties();
        assert_eq!(properties.get("bar"), Some("val3"));
        assert_eq!(properties.get("baz"), None);
        assert_eq!(properties.names(), HashSet::from(["foo", "def", "bar"]));
        let expected = ["abc", "def", "ghi"];
        let missing = properties.missing(&expected);
        assert_eq!(missing, HashSet::from(["abc", "ghi"]));
        let extra = properties.extra(&expected);
        assert_eq!(extra, HashSet::from(["foo", "bar"]));
    }

    #[test]
    fn test_check_device_properties() {
        let properties = device_properties();
        match properties.check(&["abc", "def", "ghi"], &["foo", "baz"]) {
            Err(DeviceError::MissingDeviceProperties(missing)) => {
                assert_eq!(missing, vec!["abc".to_owned(), "ghi".to_owned()])
            }
            other => panic!("Unexpected result: {:?}", other),
        }
        match properties.check(&["def"], &["foo", "baz"]) {
            Err(DeviceError::UnexpectedDeviceProperties(unexpected)) => {
                assert_eq!(unexpected, vec!["bar".to_owned()])
            }
            other => panic!("Unexpected result: {:?}", other),
        }
        match properties.check(&["def"], &["foo", "bar"]) {
            Ok(()) => (),
            other => panic!("Unexpected result: {:?}", other),
        }
    }
}
