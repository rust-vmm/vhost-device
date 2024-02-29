// SPDX-FileCopyrightText: Red Hat, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Common functionality for SCMI bindings to host devices.
//!
//! A new kind of devices can be added in [available_devices] using
//! [DeviceSpecification::new] calls.
//!
//! The module also defines common infrastructure to provide sensor devices to
//! SCMI, see [SensorT].

use std::collections::{HashMap, HashSet};
use std::ffi::OsString;
use std::fmt::Write;

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

/// Non-SCMI related device errors.
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

/// Definition of a device kind.
///
/// Use [DeviceSpecification::new] to create it.
pub struct DeviceSpecification {
    /// Function to call to create the device.
    ///
    /// The device properties are those provided on the command line by the
    /// user.
    pub(crate) constructor: DeviceConstructor,
    /// Short description of the device.
    ///
    /// Single line, not a complete sentence.
    short_help: String,
    /// Long description of the device.
    ///
    /// Complete sentences, can span multiple lines.
    long_help: String,
    /// Description of the device parameters available to the user.
    ///
    /// Each item in the vector corresponds to a single parameter description
    /// and should start with the parameter name and a followup colon.
    parameters_help: Vec<String>,
}

impl DeviceSpecification {
    /// Creates a new device specification.
    ///
    /// See [DeviceSpecification] for the meaning of the arguments.
    /// The device specification must be used in [available_devices] to
    /// actually add the device.
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

/// Mapping of device identifiers (names) to device specifications.
///
/// The string keys correspond to device identifiers specified on the command
/// line.
type NameDeviceMapping = HashMap<&'static str, DeviceSpecification>;

/// Creates device mapping and adds all the supported devices to it.
///
/// If you want to introduce a new kind of host device bindings, insert a
/// device identifier + [DeviceSpecification] to [NameDeviceMapping] here.
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

pub fn devices_help() -> String {
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

// Common sensor infrastructure

/// Basic information about the sensor.
///
/// It is typically used as a field in structs implementing sensor devices.
#[derive(Debug)]
pub struct Sensor {
    /// The sensor name (possibly truncated) as reported to the guest.
    pub name: Option<String>,
    /// Whether the sensor is enabled.
    ///
    /// Sensors can be enabled and disabled using SCMI.  [Sensor]s created
    /// using [Sensor::new] are disabled initially.
    enabled: bool,
}

impl Sensor {
    pub fn new(properties: &DeviceProperties) -> Self {
        Self {
            name: properties.get("name").map(|s| (*s).to_owned()),
            enabled: false,
        }
    }
}

/// Common base that sensor devices can use to simplify their implementation.
///
/// To add a new kind of sensor bindings, you must implement
/// [crate::scmi::ScmiDevice], define [DeviceSpecification] and add it to
/// [NameDeviceMapping] created in [available_devices].  You can do it fully
/// yourself or use this trait to simplify the implementation.
///
/// The trait is typically used as follows:
///
/// ```rust
/// struct MySensor {
///     sensor: Sensor,
///     // other fields as needed
/// }
///
/// impl SensorT for MySensor {
///     // provide trait functions implementation as needed
/// }
///
/// impl MySensor {
///     pub fn new_device(properties: &DeviceProperties) -> MaybeDevice {
///         check_device_properties(properties, &[], &["name"])?;
///         let sensor = Sensor::new(properties, "mydevice");
///         let my_sensor = MySensor { sensor };
///         let sensor_device = SensorDevice(Box::new(my_sensor));
///         Ok(Box::new(sensor_device))
///     }
/// }
/// ```
///
/// See [crate::devices::fake::FakeSensor] implementation for an example.
pub trait SensorT: Send {
    /// Returns the inner [Sensor] instance, immutable.
    fn sensor(&self) -> &Sensor;
    /// Returns the inner [Sensor] instance, mutable.
    fn sensor_mut(&mut self) -> &mut Sensor;

    /// Performs any non-default initialization on the sensor.
    ///
    /// If the initialization fails, a corresponding error message is
    /// returned.
    fn initialize(&mut self) -> Result<(), DeviceError> {
        Ok(())
    }

    /// Returns the id of the SCMI protocol used to communicate with the
    /// sensor.
    ///
    /// Usually no need to redefine this.
    fn protocol(&self) -> ProtocolId {
        SENSOR_PROTOCOL_ID
    }

    /// Returns the number of axes of the given sensor.
    ///
    /// If the sensor provides just a scalar value, 0 must be returned (the
    /// default return value here).  Otherwise a non-zero value must be
    /// returned, even for vector sensors with a single access.
    fn number_of_axes(&self) -> u32 {
        0
    }

    /// Formats the unit of the given `axis` for SCMI protocol.
    ///
    /// Usually no need to redefine this.
    fn format_unit(&self, axis: u32) -> u32 {
        (self.unit_exponent(axis) as u32 & 0x1F) << 11 | u32::from(self.unit())
    }

    /// Returns SCMI description of the sensor.
    ///
    /// Usually no need to redefine this.
    fn description_get(&self) -> DeviceResult {
        // Continuous update required by Linux SCMI IIO driver
        let low = 1 << 30;
        let n_axes = self.number_of_axes();
        let high = if n_axes > 0 {
            n_axes << 16 | 1 << 8
        } else {
            self.format_unit(0)
        };
        // During initialization, sensor name has be set.
        let name = self.sensor().name.clone().unwrap();
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

    /// Returns the SCMI unit of the sensor.
    fn unit(&self) -> u8 {
        scmi::SENSOR_UNIT_UNSPECIFIED
    }

    /// Returns the decadic exponent to apply to the sensor values.
    fn unit_exponent(&self, _axis: u32) -> i8 {
        0
    }

    /// Returns the prefix of axes names.
    ///
    /// Usually no need to redefine this.
    fn axis_name_prefix(&self) -> String {
        "axis".to_owned()
    }

    /// Returns the suffix of the given axis.
    ///
    /// Usually no need to redefine this.
    fn axis_name_suffix(&self, axis: u32) -> char {
        match axis {
            0 => 'X',
            1 => 'Y',
            2 => 'Z',
            _ => 'N', // shouldn't be reached currently
        }
    }

    /// Returns the SCMI description of the given axis.
    ///
    /// Usually no need to redefine this.
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

    /// Returns the SCMI configuration of the sensor.
    ///
    /// The default implementation here returns just whether the sensor is
    /// enabled or not.
    fn config_get(&self) -> DeviceResult {
        let config = u32::from(self.sensor().enabled);
        Ok(vec![MessageValue::Unsigned(config)])
    }

    /// Processes the SCMI configuration of the sensor.
    ///
    /// The default implementation here permits and implements only enabling
    /// and disabling the sensor.
    fn config_set(&mut self, config: u32) -> DeviceResult {
        if config & 0xFFFFFFFE != 0 {
            return Result::Err(ScmiDeviceError::UnsupportedRequest);
        }
        self.sensor_mut().enabled = config != 0;
        debug!("Sensor enabled: {}", self.sensor().enabled);
        Ok(vec![])
    }

    /// Returns SCMI reading of the sensor values.
    ///
    /// It is a sequence of [MessageValue::Unsigned] values, 4 of them for each
    /// sensor axis.  See the SCMI standard for the exact specification of the
    /// result.
    fn reading_get(&mut self) -> DeviceResult;

    /// Handles the given protocol message with the given parameters.
    ///
    /// Usually no need to redefine this, unless more than the basic
    /// functionality is needed, in which case it would be probably better to
    /// enhance this trait with additional functions and improved
    /// implementation.
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
