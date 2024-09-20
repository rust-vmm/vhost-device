// SPDX-FileCopyrightText: Red Hat, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Industrial I/O (IIO) sensors bindings.
//!
//! Basic functionality for exposing `/sys/bus/iio/devices/` stuff as guest
//! SCMI devices.  Only some typical cases are supported.  If you want more
//! functionality, you must enhance the implementation here.
//!
//! For some entry points, see [IIOSensor] and [Axis].

use std::cmp::{max, min};
use std::ffi::{OsStr, OsString};
use std::fs;
use std::io::ErrorKind;
use std::path::{Path, PathBuf};
use std::str::FromStr;

use log::{debug, error, warn};

use crate::scmi::{self, DeviceResult, MessageValue, ScmiDeviceError, MAX_SIMPLE_STRING_LENGTH};

use super::common::{DeviceError, DeviceProperties, MaybeDevice, Sensor, SensorDevice, SensorT};

/// Information about units used by the given Linux IIO channel.
struct UnitMapping<'a> {
    /// IIO sysfs channel prefix, e.g. "in_accel".
    channel: &'a str,
    /// One of the SCMI unit constants from [crate::scmi] (enum is not used to
    /// avoid type conversions everywhere).
    unit: u8,
    /// Decadic exponent to be used to convert the given unit to the SCMI unit.
    /// For example, the exponent is 0 for no conversion, -3 to convert
    /// milliamps here to amps in SCMI, or 3 to convert kilopascals here to
    /// pascals in SCMI.
    unit_exponent: i8, // max. 5 bits actually
}

/// Specification of IIO channel units.
///
/// Based on
/// <https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/Documentation/ABI/testing/sysfs-bus-iio>.
/// Not everything from there is present -- channels here with more complicated
/// unit transformations (beyond using a decadic exponent; e.g. degrees to
/// radians or units not defined in SCMI) are omitted.  If an IIO channel
/// doesn't have unit specification here, it can be still used by the unit
/// reported in SCMI will be [crate::scmi::SENSOR_UNIT_UNSPECIFIED].
// TODO: Make some macro(s) for this?
const UNIT_MAPPING: &[UnitMapping] = &[
    UnitMapping {
        channel: "in_accel",
        unit: scmi::SENSOR_UNIT_METERS_PER_SECOND_SQUARED,
        unit_exponent: 0,
    },
    UnitMapping {
        channel: "in_angle",
        unit: scmi::SENSOR_UNIT_RADIANS,
        unit_exponent: 0,
    },
    UnitMapping {
        channel: "in_anglevel",
        unit: scmi::SENSOR_UNIT_RADIANS_PER_SECOND,
        unit_exponent: 0,
    },
    UnitMapping {
        channel: "in_concentration",
        unit: scmi::SENSOR_UNIT_PERCENTAGE,
        unit_exponent: 0,
    },
    UnitMapping {
        channel: "in_current",
        unit: scmi::SENSOR_UNIT_AMPS,
        unit_exponent: -3,
    },
    UnitMapping {
        channel: "in_capacitance",
        unit: scmi::SENSOR_UNIT_FARADS,
        unit_exponent: -9,
    },
    UnitMapping {
        channel: "in_distance",
        unit: scmi::SENSOR_UNIT_METERS,
        unit_exponent: 0,
    },
    UnitMapping {
        channel: "in_electricalconductivity",
        unit: scmi::SENSOR_UNIT_SIEMENS, // per meter
        unit_exponent: 0,
    },
    UnitMapping {
        channel: "in_energy",
        unit: scmi::SENSOR_UNIT_JOULS,
        unit_exponent: 0,
    },
    UnitMapping {
        channel: "in_gravity",
        unit: scmi::SENSOR_UNIT_METERS_PER_SECOND_SQUARED,
        unit_exponent: 0,
    },
    UnitMapping {
        channel: "in_humidityrelative",
        unit: scmi::SENSOR_UNIT_PERCENTAGE,
        unit_exponent: -3,
    },
    UnitMapping {
        channel: "in_illuminance",
        unit: scmi::SENSOR_UNIT_LUX,
        unit_exponent: 0,
    },
    UnitMapping {
        channel: "in_magn",
        unit: scmi::SENSOR_UNIT_GAUSS,
        unit_exponent: 0,
    },
    UnitMapping {
        channel: "in_ph",
        unit: scmi::SENSOR_UNIT_UNSPECIFIED, // SCMI doesn't define pH
        unit_exponent: -3,
    },
    UnitMapping {
        channel: "in_positionrelative",
        unit: scmi::SENSOR_UNIT_PERCENTAGE,
        unit_exponent: -3,
    },
    UnitMapping {
        channel: "in_power",
        unit: scmi::SENSOR_UNIT_WATTS,
        unit_exponent: -3,
    },
    UnitMapping {
        channel: "in_pressure",
        unit: scmi::SENSOR_UNIT_PASCALS,
        unit_exponent: 3,
    },
    UnitMapping {
        channel: "in_proximity",
        unit: scmi::SENSOR_UNIT_METERS,
        unit_exponent: 0,
    },
    UnitMapping {
        channel: "in_resistance",
        unit: scmi::SENSOR_UNIT_OHMS,
        unit_exponent: 0,
    },
    UnitMapping {
        channel: "in_temp",
        unit: scmi::SENSOR_UNIT_DEGREES_C,
        unit_exponent: -3,
    },
    UnitMapping {
        channel: "in_velocity_sqrt(x^2+y^2+z^2)",
        unit: scmi::SENSOR_UNIT_METERS_PER_SECOND,
        unit_exponent: -3,
    },
    UnitMapping {
        channel: "in_voltage",
        unit: scmi::SENSOR_UNIT_VOLTS,
        unit_exponent: -3,
    },
];

/// Representation of an IIO channel axis.
///
/// Used also for scalar values.
#[derive(PartialEq, Debug)]
struct Axis {
    /// Full sysfs path to the axis value file stripped of "_raw".
    path: OsString, // without "_raw" suffix
    /// Axis unit exponent, see [UnitMapping::unit_exponent] and [UNIT_MAPPING].
    unit_exponent: i8,
    /// Additional exponent to apply to the axis values.  It is computed from
    /// the axis value scaling (see [IIOSensor::custom_exponent] to provide a
    /// sufficiently accurate SCMI value that is represented by an integer (not
    /// a float) + decadic exponent.
    custom_exponent: i8,
}

/// Particular IIO sensor specification.
///
/// An IIO sensor is specified by an IIO sysfs device directory and a channel
/// prefix within the directory (i.e. more devices can be defined for a single
/// IIO device directory).  All other information about the sensor is retrieved
/// from the device directory and from [UNIT_MAPPING].
#[derive(Debug)]
pub struct IIOSensor {
    /// Common sensor instance.
    sensor: Sensor,
    /// Full sysfs path to the device directory.
    ///
    /// Provided by the user.
    path: OsString,
    /// Prefix of the device type in the device directory, e.g. "in_accel".
    ///
    /// Provided by the user.
    channel: OsString,
    /// Whether the sensor is scalar or has one or more axes.
    ///
    /// Determined automatically by looking for presence of `*_[xyz]_raw` files
    /// with the given channel prefix.
    scalar: bool,
    /// Axes descriptions, see [Axis] for more details.
    axes: Vec<Axis>,
}

impl SensorT for IIOSensor {
    // TODO: Define a macro for this boilerplate?
    fn sensor(&self) -> &Sensor {
        &self.sensor
    }
    fn sensor_mut(&mut self) -> &mut Sensor {
        &mut self.sensor
    }

    fn initialize(&mut self) -> Result<(), DeviceError> {
        let mut axes: Vec<Axis> = vec![];
        match fs::read_dir(&self.path) {
            Ok(iter) => {
                for dir_entry in iter {
                    match dir_entry {
                        Ok(entry) => self.register_iio_file(entry, &mut axes),
                        Err(error) => return Err(DeviceError::IOError(self.path.clone(), error)),
                    }
                }
            }
            Err(error) => return Err(DeviceError::IOError(self.path.clone(), error)),
        }
        if axes.is_empty() {
            return Err(DeviceError::GenericError(format!(
                "No {:?} channel found in {:?}",
                &self.channel, &self.path
            )));
        }
        axes.sort_by(|a1, a2| a1.path.cmp(&a2.path));
        self.axes = axes;
        Ok(())
    }

    fn unit(&self) -> u8 {
        UNIT_MAPPING
            .iter()
            .find(|mapping| mapping.channel == self.channel)
            .map_or(scmi::SENSOR_UNIT_UNSPECIFIED, |mapping| mapping.unit)
    }

    fn unit_exponent(&self, axis_index: u32) -> i8 {
        let axis: &Axis = self.axes.get(axis_index as usize).unwrap();
        axis.unit_exponent + axis.custom_exponent
    }

    fn number_of_axes(&self) -> u32 {
        if self.scalar {
            0
        } else {
            self.axes.len() as u32
        }
    }

    fn axis_name_prefix(&self) -> String {
        let channel = self.channel.to_str().unwrap();
        let in_prefix = "in_";
        let out_prefix = "out_";
        let name: &str = if channel.starts_with(in_prefix) {
            channel.strip_prefix(in_prefix).unwrap()
        } else if channel.starts_with(out_prefix) {
            channel.strip_prefix(out_prefix).unwrap()
        } else {
            channel
        };
        let len = min(name.len(), MAX_SIMPLE_STRING_LENGTH - 1);
        String::from(&name[..len])
    }

    fn reading_get(&mut self) -> DeviceResult {
        let mut result = vec![];
        for axis in &self.axes {
            let value = self.read_axis(axis)?;
            result.push(MessageValue::Unsigned((value & 0xFFFFFFFF) as u32));
            result.push(MessageValue::Unsigned((value >> 32) as u32));
            result.push(MessageValue::Unsigned(0));
            result.push(MessageValue::Unsigned(0));
        }
        Ok(result)
    }
}

fn read_number_from_file<F: FromStr>(path: &Path) -> Result<Option<F>, ScmiDeviceError> {
    match fs::read_to_string(path) {
        Ok(string) => match string.trim().parse() {
            Ok(value) => Ok(Some(value)),
            _ => {
                error!(
                    "Failed to parse IIO numeric value from {}: {string}",
                    path.display()
                );
                Err(ScmiDeviceError::GenericError)
            }
        },
        Err(error) => match error.kind() {
            ErrorKind::NotFound => {
                let raw = path.ends_with("_raw");
                let format = || {
                    format!(
                        "IIO {} file {} not found",
                        if raw { "value" } else { "data" },
                        path.display()
                    )
                };
                if raw {
                    error!("{}", format());
                    Err(ScmiDeviceError::GenericError)
                } else {
                    debug!("{}", format());
                    Ok(None)
                }
            }
            other_error => {
                error!(
                    "Failed to read IIO data from {}: {}",
                    path.display(),
                    other_error
                );
                Err(ScmiDeviceError::GenericError)
            }
        },
    }
}

impl IIOSensor {
    #[allow(clippy::new_ret_no_self)]
    pub fn new(properties: &DeviceProperties) -> Result<Self, DeviceError> {
        properties.check(&["path", "channel"], &["name"])?;
        let sensor = Sensor::new(properties, "iio");
        Ok(Self {
            sensor,
            path: OsString::from(properties.get("path").unwrap()),
            channel: OsString::from(properties.get("channel").unwrap()),
            scalar: true,
            axes: vec![],
        })
    }

    pub fn new_device(properties: &DeviceProperties) -> MaybeDevice {
        let iio_sensor = Self::new(properties)?;
        let sensor_device = SensorDevice(Box::new(iio_sensor));
        Ok(Box::new(sensor_device))
    }

    fn set_sensor_name_from_file(&mut self, path: &PathBuf) {
        match fs::read_to_string(path) {
            Ok(name) => self.sensor_mut().name = name,
            Err(error) => warn!(
                "Error reading IIO device name from {}: {}",
                path.display(),
                error
            ),
        }
    }

    fn custom_exponent(&self, path: &OsStr, unit_exponent: i8) -> i8 {
        let mut custom_exponent: i8 = 0;
        if let Ok(Some(scale)) = self.read_axis_scale(path) {
            // Crash completely OK if *this* doesn't fit:
            custom_exponent = scale.log10() as i8;
            if scale < 1.0 {
                // The logarithm is truncated towards zero, we need floor
                custom_exponent -= 1;
            }
            // The SCMI exponent (unit_exponent + custom_exponent) can have max. 5 bits:
            custom_exponent = min(15 - unit_exponent, custom_exponent);
            custom_exponent = max(-16 - unit_exponent, custom_exponent);
            debug!(
                "Setting custom scaling coefficient for {:?}: {}",
                &path, custom_exponent
            );
        }
        custom_exponent
    }

    fn add_axis(&self, axes: &mut Vec<Axis>, path: &OsStr) {
        let unit_exponent = UNIT_MAPPING
            .iter()
            .find(|mapping| mapping.channel == self.channel)
            .map_or(0, |mapping| mapping.unit_exponent);
        // To get meaningful integer values, we must adjust exponent to
        // the provided scale if any.
        let custom_exponent = self.custom_exponent(path, unit_exponent);
        axes.push(Axis {
            path: OsString::from(path),
            unit_exponent,
            custom_exponent,
        });
    }

    fn register_iio_file(&mut self, file: fs::DirEntry, axes: &mut Vec<Axis>) {
        let channel = self.channel.to_str().unwrap();
        let os_file_name = file.file_name();
        let file_name = os_file_name.to_str().unwrap_or_default();
        let raw_suffix = "_raw";
        if file_name == "name" {
            self.set_sensor_name_from_file(&file.path());
        } else if file_name.starts_with(channel) && file_name.ends_with(raw_suffix) {
            let infix = &file_name[channel.len()..file_name.len() - raw_suffix.len()];
            let infix_len = infix.len();
            if infix_len == 0 || (infix_len == 2 && infix.starts_with('_')) {
                let raw_axis_path = Path::new(&self.path)
                    .join(Path::new(&file_name))
                    .to_str()
                    .unwrap()
                    .to_string();
                let axis_path = raw_axis_path.strip_suffix(raw_suffix).unwrap();
                self.add_axis(axes, &OsString::from(axis_path));
                if infix_len > 0 {
                    self.scalar = false;
                }
            }
        }
    }

    fn read_axis_file<T: FromStr>(
        &self,
        path: &OsStr,
        name: &str,
    ) -> Result<Option<T>, ScmiDeviceError> {
        for value_path in [
            Path::new(&(String::from(path.to_str().unwrap()) + "_" + name)),
            &Path::new(&path).parent().unwrap().join(name),
        ]
        .iter()
        {
            let value: Option<T> = read_number_from_file(value_path)?;
            if value.is_some() {
                return Ok(value);
            }
        }
        Ok(None)
    }

    fn read_axis_offset(&self, path: &OsStr) -> Result<Option<i64>, ScmiDeviceError> {
        self.read_axis_file(path, "offset")
    }

    fn read_axis_scale(&self, path: &OsStr) -> Result<Option<f64>, ScmiDeviceError> {
        self.read_axis_file(path, "scale")
    }

    fn read_axis(&self, axis: &Axis) -> Result<i64, ScmiDeviceError> {
        let path_result = axis.path.clone().into_string();
        let mut value: i64 =
            read_number_from_file(Path::new(&(path_result.unwrap() + "_raw")))?.unwrap();
        let offset: Option<i64> = self.read_axis_offset(&axis.path)?;
        if let Some(offset_value) = offset {
            match value.checked_add(offset_value) {
                Some(new_value) => value = new_value,
                None => {
                    error!(
                        "IIO offset overflow in {:?}: {} + {}",
                        &axis.path,
                        value,
                        offset.unwrap()
                    );
                    return Err(ScmiDeviceError::GenericError);
                }
            }
        }
        let scale: Option<f64> = self.read_axis_scale(&axis.path)?;
        if let Some(scale_value) = scale {
            let exponent_scale = 10.0_f64.powi(i32::from(axis.custom_exponent));
            value = (value as f64 * (scale_value / exponent_scale)).round() as i64;
        }
        Ok(value)
    }
}

#[cfg(test)]
mod tests {
    use crate::scmi::ScmiDevice;

    use super::*;
    use std::{
        assert_eq, fs,
        path::{Path, PathBuf},
    };

    fn make_directory(prefix: &str) -> PathBuf {
        for i in 1..100 {
            let path = Path::new(".").join(format!("{prefix}{i}"));
            if fs::create_dir(&path).is_ok() {
                return path;
            }
        }
        panic!("Couldn't create test directory");
    }

    struct IIODirectory {
        path: PathBuf,
    }

    impl IIODirectory {
        fn new(files: &[(&str, &str)]) -> Self {
            let path = make_directory("_test");
            let directory = Self { path };
            for (file, content) in files.iter() {
                fs::write(directory.path.join(file), content).unwrap();
            }
            directory
        }
    }

    impl Drop for IIODirectory {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.path);
        }
    }

    fn directory_path(directory: &IIODirectory) -> String {
        directory
            .path
            .clone()
            .into_os_string()
            .into_string()
            .unwrap()
    }

    fn device_properties(path: String, channel: String, name: Option<String>) -> DeviceProperties {
        let mut pairs = vec![("path".to_owned(), path), ("channel".to_owned(), channel)];
        if let Some(name) = name {
            pairs.push(("name".to_owned(), name));
        }
        DeviceProperties::new(pairs)
    }

    fn make_iio_sensor_from_path(path: String, channel: String, name: Option<String>) -> IIOSensor {
        let properties = device_properties(path, channel, name);
        IIOSensor::new(&properties).unwrap()
    }

    fn make_iio_sensor(
        directory: &IIODirectory,
        channel: String,
        name: Option<String>,
    ) -> IIOSensor {
        let path = directory_path(directory);
        make_iio_sensor_from_path(path, channel, name)
    }

    fn make_scmi_sensor_from_path(
        path: String,
        channel: String,
        name: Option<String>,
    ) -> MaybeDevice {
        let properties = device_properties(path, channel, name);
        IIOSensor::new_device(&properties)
    }

    fn make_scmi_sensor(
        directory: &IIODirectory,
        channel: String,
        name: Option<String>,
    ) -> Box<dyn ScmiDevice> {
        let path = directory_path(directory);
        make_scmi_sensor_from_path(path, channel, name).unwrap()
    }

    #[test]
    fn test_missing_property() {
        let properties = DeviceProperties::new(vec![("path".to_owned(), ".".to_owned())]);
        let result = IIOSensor::new(&properties);
        match result {
            Ok(_) => panic!("Should fail on a missing property"),
            Err(DeviceError::MissingDeviceProperties(missing)) => {
                assert_eq!(missing, vec!["channel".to_owned()])
            }
            other => panic!("Unexpected result: {:?}", other),
        }
    }

    #[test]
    fn test_extra_property() {
        let properties = DeviceProperties::new(vec![
            ("path".to_owned(), ".".to_owned()),
            ("name".to_owned(), "test".to_owned()),
            ("channel".to_owned(), "in_accel".to_owned()),
            ("foo".to_owned(), "something".to_owned()),
            ("bar".to_owned(), "baz".to_owned()),
        ]);
        let result = IIOSensor::new(&properties);
        match result {
            Ok(_) => panic!("Should fail on an extra property"),
            Err(DeviceError::UnexpectedDeviceProperties(extra)) => {
                assert_eq!(extra, ["bar".to_owned(), "foo".to_owned()])
            }
            other => panic!("Unexpected result: {:?}", other),
        }
    }

    #[test]
    fn test_iio_init() {
        let directory = IIODirectory::new(&[("foo", "bar"), ("in_accel_raw", "123")]);
        let mut sensor =
            make_scmi_sensor(&directory, "in_accel".to_owned(), Some("accel".to_owned()));
        sensor.initialize().unwrap();
    }

    #[test]
    fn test_iio_init_no_directory() {
        let mut sensor =
            make_scmi_sensor_from_path("non-existent".to_owned(), "".to_owned(), None).unwrap();
        match sensor.initialize() {
            Ok(_) => panic!("Should fail on an inaccessible path"),
            Err(DeviceError::IOError(path, std::io::Error { .. })) => {
                assert_eq!(path, "non-existent")
            }
            other => panic!("Unexpected result: {:?}", other),
        }
    }

    #[test]
    fn test_iio_init_no_channel() {
        let directory = IIODirectory::new(&[("foo", "bar")]);
        let mut sensor = make_scmi_sensor(&directory, "in_accel".to_owned(), None);
        match sensor.initialize() {
            Ok(_) => panic!("Should fail on an inaccessible channel"),
            Err(DeviceError::GenericError(message)) => {
                assert!(
                    message.starts_with("No \"in_accel\" channel found in \"./_test"),
                    "Unexpected error: {}",
                    message
                )
            }
            other => panic!("Unexpected result: {:?}", other),
        }
    }

    #[test]
    fn test_sensor_name_from_fs() {
        let directory = IIODirectory::new(&[("in_accel_raw", "123"), ("name", "foo")]);
        let mut sensor =
            make_iio_sensor(&directory, "in_accel".to_owned(), Some("accel".to_owned()));
        sensor.initialize().unwrap();
        assert_eq!(sensor.sensor.name, "foo");
    }

    #[test]
    fn test_sensor_name_from_params() {
        let directory = IIODirectory::new(&[("in_accel_raw", "123")]);
        let mut sensor = make_iio_sensor(&directory, "in_accel".to_owned(), Some("foo".to_owned()));
        sensor.initialize().unwrap();
        assert_eq!(sensor.sensor.name, "foo");
    }

    #[test]
    fn test_default_sensor_name() {
        let directory = IIODirectory::new(&[("in_accel_raw", "123")]);
        let mut sensor = make_iio_sensor(&directory, "in_accel".to_owned(), None);
        sensor.initialize().unwrap();
        assert_eq!(sensor.sensor.name, "iio");
    }

    #[test]
    fn test_units() {
        let directory = IIODirectory::new(&[
            ("in_foo_raw", "123"),
            ("in_accel_raw", "123"),
            ("in_voltage_raw", "123"),
        ]);
        for (name, unit) in [
            ("foo", scmi::SENSOR_UNIT_UNSPECIFIED),
            ("accel", scmi::SENSOR_UNIT_METERS_PER_SECOND_SQUARED),
            ("voltage", scmi::SENSOR_UNIT_VOLTS),
        ]
        .iter()
        {
            let sensor =
                make_iio_sensor(&directory, "in_".to_owned() + name, Some(name.to_string()));
            assert_eq!(sensor.unit(), *unit);
        }
    }

    #[test]
    fn test_unit_exponent() {
        for (channel, scale, exponent) in [
            ("in_accel", 1.23, 0),
            ("in_accel", 0.000123, -4),
            ("in_accel", 123.0, 2),
            ("in_voltage", 123.0, -1),
        ]
        .iter()
        {
            let raw_file = format!("{channel}_raw");
            let scale_file = format!("{channel}_scale");
            let directory =
                IIODirectory::new(&[(&raw_file, "123"), (&scale_file, &scale.to_string())]);
            let mut sensor = make_iio_sensor(&directory, channel.to_string(), None);
            sensor.initialize().unwrap();
            assert_eq!(sensor.unit_exponent(0), *exponent);
        }
    }

    #[test]
    fn test_unit_exponent_multiple_axes() {
        let directory = IIODirectory::new(&[
            ("in_accel_x_raw", "123"),
            ("in_accel_x_scale", "0.123"),
            ("in_accel_y_raw", "123"),
            ("in_accel_y_scale", "12.3"),
        ]);
        let mut sensor = make_iio_sensor(&directory, "in_accel".to_owned(), None);
        sensor.initialize().unwrap();
        assert_eq!(sensor.unit_exponent(0), -1);
        assert_eq!(sensor.unit_exponent(1), 1);
    }

    #[test]
    fn test_unit_exponent_single_scale() {
        let directory = IIODirectory::new(&[("in_accel_raw", "123"), ("scale", "0.123")]);
        let mut sensor = make_iio_sensor(&directory, "in_accel".to_owned(), None);
        sensor.initialize().unwrap();
        assert_eq!(sensor.unit_exponent(0), -1);
    }

    #[test]
    fn test_number_of_axes_scalar() {
        let directory = IIODirectory::new(&[("in_accel_raw", "123"), ("in_accel_scale", "123")]);
        let mut sensor = make_iio_sensor(&directory, "in_accel".to_owned(), None);
        sensor.initialize().unwrap();
        assert_eq!(sensor.number_of_axes(), 0);
    }

    #[test]
    fn test_number_of_axes_1() {
        let directory = IIODirectory::new(&[("in_accel_x_raw", "123"), ("in_accel_scale", "123")]);
        let mut sensor = make_iio_sensor(&directory, "in_accel".to_owned(), None);
        sensor.initialize().unwrap();
        assert_eq!(sensor.number_of_axes(), 1);
    }

    #[test]
    fn test_number_of_axes_3() {
        let directory = IIODirectory::new(&[
            ("in_accel_x_raw", "123"),
            ("in_accel_y_raw", "123"),
            ("in_accel_z_raw", "123"),
            ("in_accel_x_scale", "123"),
        ]);
        let mut sensor = make_iio_sensor(&directory, "in_accel".to_owned(), None);
        sensor.initialize().unwrap();
        assert_eq!(sensor.number_of_axes(), 3);
    }

    #[test]
    fn test_axis_name_prefix() {
        for (channel, prefix) in [
            ("in_accel", "accel"),
            ("out_voltage", "voltage"),
            ("foo", "foo"),
            ("name-longer-than-fifteen-characters", "name-longer-tha"),
        ]
        .iter()
        {
            let sensor = make_iio_sensor_from_path("".to_owned(), channel.to_string(), None);
            assert_eq!(&sensor.axis_name_prefix(), prefix);
        }
    }

    #[test]
    fn test_iio_reading_scalar() {
        let directory = IIODirectory::new(&[
            ("in_voltage_raw", "9876543210"),
            ("in_voltage_offset", "123"),
            ("in_voltage_scale", "456"),
        ]);
        let mut sensor = make_iio_sensor(&directory, "in_voltage".to_owned(), None);
        sensor.initialize().unwrap();
        let result = sensor.reading_get().unwrap();
        // (9876543210 + 123) * 456 = 4503703759848
        // custom exponent = 2
        // applied and rounded: 45037037598 = 0xA7C6AA81E
        assert_eq!(result.len(), 4);
        assert_eq!(result.first().unwrap(), &MessageValue::Unsigned(0x7C6AA81E));
        assert_eq!(result.get(1).unwrap(), &MessageValue::Unsigned(0xA));
        assert_eq!(result.get(2).unwrap(), &MessageValue::Unsigned(0));
        assert_eq!(result.get(3).unwrap(), &MessageValue::Unsigned(0));
    }

    #[test]
    fn test_iio_reading_scalar_whitespace() {
        let directory = IIODirectory::new(&[
            ("in_accel_raw", "10\n"),
            ("in_accel_offset", "20\n"),
            ("in_accel_scale", "0.3\n"),
        ]);
        let mut sensor = make_iio_sensor(&directory, "in_accel".to_owned(), None);
        sensor.initialize().unwrap();
        let result = sensor.reading_get().unwrap();
        assert_eq!(result.len(), 4);
        assert_eq!(result.first().unwrap(), &MessageValue::Unsigned(0x5A));
        assert_eq!(result.get(1).unwrap(), &MessageValue::Unsigned(0));
        assert_eq!(result.get(2).unwrap(), &MessageValue::Unsigned(0));
        assert_eq!(result.get(3).unwrap(), &MessageValue::Unsigned(0));
    }

    #[test]
    fn test_iio_reading_axes() {
        let directory = IIODirectory::new(&[
            ("in_accel_x_raw", "10"),
            ("in_accel_x_offset", "1"),
            ("in_accel_y_raw", "20"),
            ("in_accel_y_offset", "10"),
            ("in_accel_z_raw", "30"),
            ("in_accel_z_offset", "20"),
            ("in_accel_z_scale", "0.3"),
            ("scale", "0.02"),
        ]);
        let mut sensor = make_iio_sensor(&directory, "in_accel".to_owned(), None);
        sensor.initialize().unwrap();
        let result = sensor.reading_get().unwrap();
        assert_eq!(result.len(), 12);
        assert_eq!(result.first().unwrap(), &MessageValue::Unsigned(22));
        assert_eq!(result.get(4).unwrap(), &MessageValue::Unsigned(60));
        assert_eq!(result.get(8).unwrap(), &MessageValue::Unsigned(150));
        for i in 0..12 {
            if i % 4 != 0 {
                assert_eq!(result.get(i).unwrap(), &MessageValue::Unsigned(0));
            }
        }
    }
}
