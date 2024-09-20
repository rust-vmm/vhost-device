// SPDX-FileCopyrightText: Red Hat, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Implementation of SCMI and some of its protocols.
//!
//! This module implements SCMI infrastructure and some of the SCMI protocols.
//! See [HandlerMap::new] how to add support for another SCMI protocol or to add
//! more functionality to an already implemented SCMI protocol.
//!
//! If you want to add new devices (e.g. SCMI bindings to some kinds of host
//! devices), see [crate::devices] modules.

use std::{
    cmp::min,
    collections::HashMap,
    sync::{Arc, Mutex},
};

use itertools::Itertools;
use log::{debug, error, info, warn};
use thiserror::Error as ThisError;

use crate::devices::common::DeviceError;

pub type MessageHeader = u32;

pub const MAX_SIMPLE_STRING_LENGTH: usize = 16; // incl. NULL terminator

/// Wrapper around SCMI values of the basic types SCMI defines.
///
/// Everything communicating to/from SCMI must be composed of them.
// SCMI specification talks about Le32 parameter and return values.
// VirtIO SCMI specification talks about u8 SCMI values.
// Let's stick with SCMI specification for implementation simplicity.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum MessageValue {
    Signed(i32),
    Unsigned(u32),
    String(String, usize), // string, expected characters
}

impl MessageValue {
    pub(crate) fn get_unsigned(&self) -> u32 {
        match self {
            Self::Unsigned(value) => *value,
            _ => panic!("Wrong parameter"),
        }
    }
}

pub type MessageValues = Vec<MessageValue>;

/// Enumeration of SCMI message types, mapped to the corresponding SCMI codes.
///
/// The only one we currently support is [MessageType::Command].
#[derive(Debug, PartialEq)]
enum MessageType {
    // 4-bit unsigned integer
    Command,     // 0
    Unsupported, // anything else
}
pub type MessageId = u8;
pub type ProtocolId = u8;
type NParameters = u8;

/// Mapping of return values to SCMI return status codes.
#[derive(Clone, Copy)]
// Not all the codes are currently used but let's have a complete return status
// enumeration from the SCMI specification here.
#[allow(dead_code)]
enum ReturnStatus {
    // 32-bit signed integer
    Success = 0,
    NotSupported = -1,
    InvalidParameters = -2,
    Denied = -3,
    NotFound = -4,
    OutOfRange = -5,
    Busy = -6,
    CommsError = -7,
    GenericError = -8,
    HardwareError = -9,
    ProtocolError = -10,
    // -11..-127: reserved
    // <-127: vendor specific
}

impl ReturnStatus {
    const fn as_value(&self) -> MessageValue {
        MessageValue::Signed(*self as i32)
    }
}

/// Representation of [MessageValue] sequence used to construct [ScmiResponse].
///
/// The sequence includes the response code (see the helper constructors for
/// adding them) but it doesn't include the SCMI message header.  The header is
/// added in [ScmiResponse].
struct Response {
    values: MessageValues,
}

impl From<ReturnStatus> for Response {
    fn from(value: ReturnStatus) -> Self {
        Self {
            values: vec![value.as_value()],
        }
    }
}

impl From<MessageValue> for Response {
    fn from(value: MessageValue) -> Self {
        Self {
            values: vec![ReturnStatus::Success.as_value(), value],
        }
    }
}

impl From<&MessageValues> for Response {
    fn from(value: &MessageValues) -> Self {
        let mut response_values = vec![ReturnStatus::Success.as_value()];
        response_values.extend_from_slice(value.as_slice());
        Self {
            values: response_values,
        }
    }
}

/// SCMI response in SCMI representation byte.
///
/// Use [ScmiResponse::from] function to construct it.
#[derive(Debug)]
pub struct ScmiResponse {
    header: MessageHeader,
    ret_bytes: Vec<u8>,
}

impl ScmiResponse {
    /// Creates [ScmiResponse] instance from the (unchanged) SCMI request
    /// `header` and a [Response] composed of [MessageValue]s.
    fn from(header: MessageHeader, response: Response) -> Self {
        debug!("response arguments: {:?}", response.values);
        let mut ret_bytes: Vec<u8> = vec![];
        ret_bytes.extend_from_slice(&header.to_le_bytes());
        for v in response.values {
            let mut bytes = match v {
                MessageValue::Signed(n) => n.to_le_bytes().to_vec(),
                MessageValue::Unsigned(n) => n.to_le_bytes().to_vec(),
                // Strings can be UTF-8 or ASCII and they must be
                // null-terminated in either case.  Let's put the
                // null-terminator here rather than having to put it
                // to all the strings anywhere.
                MessageValue::String(s, size) => {
                    let mut v = s.as_bytes().to_vec();
                    let v_len = v.len();
                    // The string must be NULL terminated, at least one NULL must be present.
                    assert!(
                        v_len < size,
                        "String longer than specified: {v_len} >= {size}"
                    );
                    v.resize(size, b'\0');
                    v
                }
            };
            ret_bytes.append(&mut bytes)
        }
        debug!("ret bytes: {:?}", ret_bytes);
        Self { header, ret_bytes }
    }

    pub(crate) fn as_slice(&self) -> &[u8] {
        self.ret_bytes.as_slice()
    }

    pub(crate) fn len(&self) -> usize {
        self.ret_bytes.len()
    }

    pub(crate) fn communication_error(&self) -> Self {
        Self::from(self.header, Response::from(ReturnStatus::CommsError))
    }
}

/// Representation of a parsed SCMI request.
///
/// Use [ScmiRequest::get_unsigned] and [ScmiRequest::get_usize] functions to
/// retrieve its parameters as `u32` and `usize` values respectively.
pub struct ScmiRequest {
    header: MessageHeader,     // 32-bit unsigned integer, split below:
    message_id: MessageId,     // bits 7:0
    message_type: MessageType, // bits 9:8
    protocol_id: ProtocolId,   // bits 17:10
    // token: u16,             // bits 27:18
    // bits 31:28 are reserved, must be 0
    parameters: Option<MessageValues>, // set later based on the number of parameters
}

impl ScmiRequest {
    pub(crate) fn new(header: MessageHeader) -> Self {
        let protocol_id: u8 = ((header >> 10) & 0xFF).try_into().unwrap();
        let message_id: u8 = (header & 0xFF).try_into().unwrap();
        // Token is an arbitrary info, the Linux SCMI driver uses it as a sequence number.
        // No actual meaning for vhost except copying the unchanged header in the response
        // as required by SCMI specification. We extract it here only for debugging purposes.
        let token: u16 = ((header >> 18) & 0x3FF).try_into().unwrap();
        let message_type = match (header >> 8) & 0x3 {
            0 => MessageType::Command,
            _ => MessageType::Unsupported,
        };
        debug!(
            "SCMI request: protocol id={}, message id={}, message_type={:?}, token={}",
            protocol_id, message_id, message_type, token
        );
        Self {
            header,
            message_id,
            message_type,
            protocol_id,
            parameters: None,
        }
    }

    fn get_unsigned(&self, parameter: usize) -> u32 {
        self.parameters.as_ref().expect("Missing parameters")[parameter].get_unsigned()
    }

    fn get_usize(&self, parameter: usize) -> usize {
        self.get_unsigned(parameter) as usize
    }
}

const BASE_PROTOCOL_ID: ProtocolId = 0x10;
const BASE_VERSION: MessageId = 0x0;
const BASE_PROTOCOL_ATTRIBUTES: MessageId = 0x1;
const BASE_MESSAGE_ATTRIBUTES: MessageId = 0x2;
const BASE_DISCOVER_VENDOR: MessageId = 0x3;
const BASE_DISCOVER_IMPLEMENTATION_VERSION: MessageId = 0x5;
const BASE_DISCOVER_LIST_PROTOCOLS: MessageId = 0x6;

pub const SENSOR_PROTOCOL_ID: ProtocolId = 0x15;
const SENSOR_VERSION: MessageId = 0x0;
const SENSOR_ATTRIBUTES: MessageId = 0x1;
const SENSOR_MESSAGE_ATTRIBUTES: MessageId = 0x2;
pub const SENSOR_DESCRIPTION_GET: MessageId = 0x3;
pub const SENSOR_READING_GET: MessageId = 0x6;
pub const SENSOR_AXIS_DESCRIPTION_GET: MessageId = 0x7;
pub const SENSOR_CONFIG_GET: MessageId = 0x9;
pub const SENSOR_CONFIG_SET: MessageId = 0xA;
pub const SENSOR_CONTINUOUS_UPDATE_NOTIFY: MessageId = 0xB;

#[allow(dead_code)]
pub const SENSOR_UNIT_NONE: u8 = 0;
pub const SENSOR_UNIT_UNSPECIFIED: u8 = 1;
pub const SENSOR_UNIT_DEGREES_C: u8 = 2;
pub const SENSOR_UNIT_VOLTS: u8 = 5;
pub const SENSOR_UNIT_AMPS: u8 = 6;
pub const SENSOR_UNIT_WATTS: u8 = 7;
pub const SENSOR_UNIT_JOULS: u8 = 8;
pub const SENSOR_UNIT_LUX: u8 = 13;
pub const SENSOR_UNIT_METERS: u8 = 31;
pub const SENSOR_UNIT_RADIANS: u8 = 36;
pub const SENSOR_UNIT_GAUSS: u8 = 45;
pub const SENSOR_UNIT_FARADS: u8 = 48;
pub const SENSOR_UNIT_OHMS: u8 = 49;
pub const SENSOR_UNIT_SIEMENS: u8 = 50;
pub const SENSOR_UNIT_PERCENTAGE: u8 = 65;
pub const SENSOR_UNIT_PASCALS: u8 = 66;
pub const SENSOR_UNIT_RADIANS_PER_SECOND: u8 = 87;
pub const SENSOR_UNIT_METERS_PER_SECOND: u8 = 90;
pub const SENSOR_UNIT_METERS_PER_SECOND_SQUARED: u8 = 89;

enum ParameterType {
    _SignedInt32,
    UnsignedInt32,
}
type ParameterSpecification = Vec<ParameterType>;

type HandlerFunction = fn(&ScmiHandler, &ScmiRequest) -> Response;

/// Specification of an SCMI message handler.
///
/// No need to create this directly, use [HandlerMap::bind] to add message
/// handlers.
struct HandlerInfo {
    name: String,
    parameters: ParameterSpecification,
    function: HandlerFunction,
}

/// Mapping of SCMI protocols and messages to handlers.
///
/// See [HandlerMap::new] and [HandlerMap::bind] how to add new handlers.
// HandlerMap layout is suboptimal but let's prefer simplicity for now.
struct HandlerMap(HashMap<(ProtocolId, MessageId), HandlerInfo>);

impl HandlerMap {
    fn new() -> Self {
        let mut map = Self(HashMap::new());
        map.make_base_handlers();
        map.make_sensor_handlers();
        map
    }

    fn keys(&self) -> std::collections::hash_map::Keys<(u8, u8), HandlerInfo> {
        self.0.keys()
    }

    fn get(&self, protocol_id: ProtocolId, message_id: MessageId) -> Option<&HandlerInfo> {
        self.0.get(&(protocol_id, message_id))
    }

    /// Add a handler for a SCMI protocol message.
    ///
    /// `protocol_id` & `message_id` specify the corresponding SCMI protocol
    /// and message codes identifying the request to handle using `function`.
    /// Expected SCMI parameters (unsigned or signed 32-bit integers) are
    /// specified in `parameters`.  `name` serves just for identifying the
    /// handlers easily in logs and error messages.
    fn bind(
        &mut self,
        protocol_id: ProtocolId,
        message_id: MessageId,
        name: &str,
        parameters: ParameterSpecification,
        function: HandlerFunction,
    ) {
        assert!(
            self.get(protocol_id, message_id).is_none(),
            "Multiple handlers defined for SCMI message {}/{}",
            protocol_id,
            message_id
        );
        self.0.insert(
            (protocol_id, message_id),
            HandlerInfo {
                name: name.to_string(),
                parameters,
                function,
            },
        );
    }

    /// Adds SCMI base protocol handlers.
    fn make_base_handlers(&mut self) {
        self.bind(
            BASE_PROTOCOL_ID,
            BASE_VERSION,
            "base/version",
            vec![],
            |_, _| -> Response {
                // 32-bit unsigned integer
                // major: upper 16 bits
                // minor: lower 16 bits
                Response::from(MessageValue::Unsigned(0x20000))
            },
        );
        self.bind(
            BASE_PROTOCOL_ID,
            BASE_PROTOCOL_ATTRIBUTES,
            "base/protocol_attributes",
            vec![],
            |handler, _| -> Response {
                // The base protocol doesn't count.
                Response::from(MessageValue::Unsigned(handler.number_of_protocols() - 1))
            },
        );
        self.bind(
            BASE_PROTOCOL_ID,
            BASE_MESSAGE_ATTRIBUTES,
            "base/message_attributes",
            vec![ParameterType::UnsignedInt32],
            ScmiHandler::message_attributes,
        );
        self.bind(
            BASE_PROTOCOL_ID,
            BASE_DISCOVER_VENDOR,
            "base/discover_vendor",
            vec![],
            |_, _| -> Response {
                Response::from(MessageValue::String(
                    "rust-vmm".to_string(),
                    MAX_SIMPLE_STRING_LENGTH,
                ))
            },
        );
        self.bind(
            BASE_PROTOCOL_ID,
            BASE_DISCOVER_IMPLEMENTATION_VERSION,
            "base/discover_implementation_version",
            vec![],
            |_, _| -> Response { Response::from(MessageValue::Unsigned(0)) },
        );
        self.bind(
            BASE_PROTOCOL_ID,
            BASE_DISCOVER_LIST_PROTOCOLS,
            "base/discover_list_protocols",
            vec![ParameterType::UnsignedInt32],
            ScmiHandler::discover_list_protocols,
        );
    }

    /// Adds SCMI sensor protocol handlers.
    fn make_sensor_handlers(&mut self) {
        self.bind(
            SENSOR_PROTOCOL_ID,
            SENSOR_VERSION,
            "sensor/version",
            vec![],
            |_, _| -> Response {
                // 32-bit unsigned integer
                // major: upper 16 bits
                // minor: lower 16 bits
                Response::from(MessageValue::Unsigned(0x30000))
            },
        );

        self.bind(
            SENSOR_PROTOCOL_ID,
            SENSOR_ATTRIBUTES,
            "sensor/attributes",
            vec![],
            |handler: &ScmiHandler, _| -> Response {
                let n_sensors = u32::from(handler.devices.number_of_devices(SENSOR_PROTOCOL_ID));
                let values: MessageValues = vec![
                    MessageValue::Unsigned(n_sensors), // # of sensors, no async commands
                    MessageValue::Unsigned(0), // lower shared memory address -- not supported
                    MessageValue::Unsigned(0), // higer shared memory address -- not supported
                    MessageValue::Unsigned(0), // length of shared memory -- not supported
                ];
                Response::from(&values)
            },
        );

        self.bind(
            SENSOR_PROTOCOL_ID,
            SENSOR_MESSAGE_ATTRIBUTES,
            "sensor/message_attributes",
            vec![ParameterType::UnsignedInt32],
            ScmiHandler::message_attributes,
        );

        self.bind(
            SENSOR_PROTOCOL_ID,
            SENSOR_DESCRIPTION_GET,
            "sensor/description_get",
            vec![ParameterType::UnsignedInt32],
            |handler: &ScmiHandler, request: &ScmiRequest| -> Response {
                let first_index = request.get_usize(0);
                let n_sensors = handler.devices.number_of_devices(SENSOR_PROTOCOL_ID) as usize;
                if first_index >= n_sensors {
                    return Response::from(ReturnStatus::InvalidParameters);
                }
                // Let's use something reasonable to fit into the available VIRTIO buffers:
                let max_sensors_to_return = 256;
                let sensors_to_return = min(n_sensors - first_index, max_sensors_to_return);
                let last_non_returned_sensor = first_index + sensors_to_return;
                let remaining_sensors = if n_sensors > last_non_returned_sensor {
                    n_sensors - last_non_returned_sensor
                } else {
                    0
                };
                let mut values = vec![MessageValue::Unsigned(
                    sensors_to_return as u32 | (remaining_sensors as u32) << 16,
                )];
                for index in first_index..last_non_returned_sensor {
                    values.push(MessageValue::Unsigned(index as u32));
                    let result = handler.handle_device(
                        index,
                        SENSOR_PROTOCOL_ID,
                        SENSOR_DESCRIPTION_GET,
                        &[],
                    );
                    if result.is_err() {
                        return handler.device_response(result, index);
                    }
                    let mut sensor_values = result.unwrap();
                    values.append(&mut sensor_values);
                }
                Response::from(&values)
            },
        );

        self.bind(
            SENSOR_PROTOCOL_ID,
            SENSOR_READING_GET,
            "sensor/reading_get",
            vec![ParameterType::UnsignedInt32, ParameterType::UnsignedInt32],
            |handler: &ScmiHandler, request: &ScmiRequest| -> Response {
                // Check flags
                if request.get_unsigned(1) != 0 {
                    // Asynchronous reporting not supported
                    return Response::from(ReturnStatus::NotSupported);
                }
                handler.handle_device_response(request, &[])
            },
        );

        self.bind(
            SENSOR_PROTOCOL_ID,
            SENSOR_AXIS_DESCRIPTION_GET,
            "sensor/axis_description_get",
            vec![ParameterType::UnsignedInt32, ParameterType::UnsignedInt32],
            |handler: &ScmiHandler, request: &ScmiRequest| -> Response {
                handler.handle_device_response(request, &[1])
            },
        );

        self.bind(
            SENSOR_PROTOCOL_ID,
            SENSOR_CONFIG_GET,
            "sensor/config_get",
            vec![ParameterType::UnsignedInt32],
            |handler: &ScmiHandler, request: &ScmiRequest| -> Response {
                handler.handle_device_response(request, &[])
            },
        );

        self.bind(
            SENSOR_PROTOCOL_ID,
            SENSOR_CONFIG_SET,
            "sensor/config_set",
            vec![ParameterType::UnsignedInt32, ParameterType::UnsignedInt32],
            |handler: &ScmiHandler, request: &ScmiRequest| -> Response {
                handler.handle_device_response(request, &[1])
            },
        );

        // Linux VIRTIO SCMI seems to insist on presence of this:
        self.bind(
            SENSOR_PROTOCOL_ID,
            SENSOR_CONTINUOUS_UPDATE_NOTIFY,
            "sensor/continuous_update_notify",
            vec![ParameterType::UnsignedInt32, ParameterType::UnsignedInt32],
            |handler: &ScmiHandler, request: &ScmiRequest| -> Response {
                handler.handle_device_response(request, &[1])
            },
        );
    }
}

#[derive(Debug, PartialEq, Eq, ThisError)]
pub enum ScmiDeviceError {
    #[error("Generic error")]
    GenericError,
    #[error("Invalid parameters")]
    InvalidParameters,
    #[error("No such device")]
    NoSuchDevice,
    #[error("Device not enabled")]
    NotEnabled,
    #[error("Unsupported request")]
    UnsupportedRequest,
}

/// The highest representation of an SCMI device.
///
/// A device is an entity bound to a SCMI protocol that can take an SCMI
/// message id and parameters and respond with [MessageValue]s.  See
/// [crate::devices] how devices are defined and created.
pub trait ScmiDevice: Send {
    /// Initializes the device (if needed).
    ///
    /// If any error occurs preventing the operation of the device, a
    /// corresponding error message must be returned.
    fn initialize(&mut self) -> Result<(), DeviceError>;
    /// Returns the SCMI protocol id that the device is attached to.
    fn protocol(&self) -> ProtocolId;
    /// Handles an SCMI request.
    ///
    /// `message_id` is an SCMI message id from the
    /// given SCMI protocol and `parameters` are the SCMI request parameters
    /// already represented as [MessageValue]s.
    fn handle(
        &mut self,
        message_id: MessageId,
        parameters: &[MessageValue],
    ) -> Result<MessageValues, ScmiDeviceError>;
}

type DeviceList = Vec<Box<dyn ScmiDevice>>;

/// Mapping of SCMI protocols to devices that can handle them.
struct DeviceMap(Arc<Mutex<HashMap<ProtocolId, DeviceList>>>);

impl DeviceMap {
    fn new() -> Self {
        Self(Arc::new(Mutex::new(HashMap::new())))
    }

    // This is the maximum number of the remaining sensors
    // SENSOR_DESCRIPTION_GET supports -- the upper 16 bits of the response.
    const MAX_NUMBER_OF_PROTOCOL_DEVICES: usize = 0xFFFF;

    fn insert(&self, device: Box<dyn ScmiDevice>) {
        let mut device_map = self.0.lock().unwrap();
        let devices = device_map.entry(device.protocol()).or_default();
        if devices.len() >= Self::MAX_NUMBER_OF_PROTOCOL_DEVICES {
            panic!(
                "Too many devices defined for protocol {}",
                device.protocol()
            );
        }
        devices.push(device);
    }

    fn number_of_devices(&self, protocol_id: ProtocolId) -> u16 {
        match self.0.lock().unwrap().get(&protocol_id) {
            Some(devices) => devices.len() as u16,
            None => 0,
        }
    }

    fn handle(
        &self,
        device_index: usize,
        protocol_id: ProtocolId,
        message_id: MessageId,
        parameters: &[MessageValue],
    ) -> Result<MessageValues, ScmiDeviceError> {
        match self.0.lock().unwrap().get_mut(&protocol_id) {
            Some(devices) => match devices.get_mut(device_index) {
                Some(device) => device.handle(message_id, parameters),
                None => Result::Err(ScmiDeviceError::NoSuchDevice),
            },
            None => Result::Err(ScmiDeviceError::NoSuchDevice),
        }
    }
}

pub type DeviceResult = Result<MessageValues, ScmiDeviceError>;

pub struct ScmiHandler {
    handlers: HandlerMap,
    devices: DeviceMap,
}

impl ScmiHandler {
    /// Creates an instance for handling SCMI requests.
    ///
    /// The function also defines handlers for particular SCMI protocols.
    /// It creates a [HandlerMap] and then adds SCMI message handlers to
    /// it using [HandlerMap::bind] function.  This is the place (i.e. the
    /// functions called from here) where to add bindings for SCMI protocols and
    /// messages.
    pub fn new() -> Self {
        Self {
            handlers: HandlerMap::new(),
            devices: DeviceMap::new(),
        }
    }

    fn request_handler(&self, request: &ScmiRequest) -> Option<&HandlerInfo> {
        self.handlers.get(request.protocol_id, request.message_id)
    }

    pub fn handle(&self, request: ScmiRequest) -> ScmiResponse {
        let response = match request.message_type {
            MessageType::Command => match self.request_handler(&request) {
                Some(info) => {
                    debug!(
                        "Calling handler for {}({:?})",
                        info.name,
                        request.parameters.as_ref().unwrap_or(&vec![])
                    );
                    (info.function)(self, &request)
                }
                _ => Response::from(ReturnStatus::NotSupported),
            },
            MessageType::Unsupported => Response::from(ReturnStatus::NotSupported),
        };
        ScmiResponse::from(request.header, response)
    }

    pub fn number_of_parameters(&self, request: &ScmiRequest) -> Option<NParameters> {
        self.request_handler(request).map(|info| {
            info.parameters
                .len()
                .try_into()
                .expect("Invalid parameter specification")
        })
    }

    pub fn store_parameters(&self, request: &mut ScmiRequest, buffer: &[u8]) {
        let handler = &self
            .request_handler(request)
            .expect("Attempt to process an unsupported SCMI message");
        let n_parameters = handler.parameters.len();
        debug!(
            "SCMI request {}/{} parameters length: {}, buffer length: {}",
            request.message_id,
            request.protocol_id,
            n_parameters,
            buffer.len()
        );
        let value_size = 4;
        assert!(
            buffer.len() == n_parameters * value_size,
            "Unexpected parameters buffer size: buffer={} parameters={}",
            buffer.len(),
            n_parameters
        );
        let mut values: MessageValues = Vec::with_capacity(n_parameters);
        for n in 0..n_parameters {
            let slice: [u8; 4] = buffer[4 * n..4 * (n + 1)]
                .try_into()
                .expect("Insufficient data for parameters");
            let v = match handler.parameters[n] {
                ParameterType::_SignedInt32 => MessageValue::Signed(i32::from_le_bytes(slice)),
                ParameterType::UnsignedInt32 => MessageValue::Unsigned(u32::from_le_bytes(slice)),
            };
            debug!("SCMI parameter {}: {:?}", n, v);
            values.push(v);
        }
        request.parameters = Some(values);
    }

    fn number_of_protocols(&self) -> u32 {
        let n: usize = self.handlers.keys().unique_by(|k| k.0).count();
        n.try_into()
            .expect("Impossibly large number of SCMI protocols")
    }

    pub fn register_device(&self, device: Box<dyn ScmiDevice>) {
        self.devices.insert(device);
    }

    fn handle_device(
        &self,
        device_index: usize,
        protocol_id: ProtocolId,
        message_id: MessageId,
        parameters: &[MessageValue],
    ) -> DeviceResult {
        self.devices
            .handle(device_index, protocol_id, message_id, parameters)
    }

    fn device_response(&self, result: DeviceResult, device_index: usize) -> Response {
        match result {
            Ok(values) => Response::from(&values),
            Err(error) => match error {
                ScmiDeviceError::NoSuchDevice
                | ScmiDeviceError::NotEnabled
                | ScmiDeviceError::InvalidParameters => {
                    info!("Invalid device access: {}, {}", device_index, error);
                    Response::from(ReturnStatus::InvalidParameters)
                }
                ScmiDeviceError::UnsupportedRequest => {
                    info!("Unsupported request for {}", device_index);
                    Response::from(ReturnStatus::NotSupported)
                }
                ScmiDeviceError::GenericError => {
                    warn!("Device error in {}", device_index);
                    Response::from(ReturnStatus::GenericError)
                }
            },
        }
    }

    fn handle_device_response(&self, request: &ScmiRequest, parameters: &[usize]) -> Response {
        let device_index = request.get_usize(0);
        let protocol_id = request.protocol_id;
        let message_id = request.message_id;
        let parameter_values: Vec<MessageValue> = parameters
            .iter()
            .map(|i| MessageValue::Unsigned(request.get_unsigned(*i)))
            .collect();
        let result = self.handle_device(
            device_index,
            protocol_id,
            message_id,
            parameter_values.as_slice(),
        );
        self.device_response(result, device_index)
    }

    fn discover_list_protocols(&self, request: &ScmiRequest) -> Response {
        // Base protocol is skipped
        let skip: usize = request
            .get_unsigned(0)
            .try_into()
            .expect("Extremely many protocols");
        let protocols: Vec<ProtocolId> = self
            .handlers
            .keys()
            .filter(|(protocol_id, _)| *protocol_id != BASE_PROTOCOL_ID)
            .map(|(protocol_id, _)| *protocol_id)
            .unique()
            .sorted()
            .skip(skip)
            .collect();
        let n_protocols = protocols.len();
        debug!("Number of listed protocols after {}: {}", skip, n_protocols);
        let mut values: Vec<MessageValue> = vec![MessageValue::Unsigned(n_protocols as u32)];
        if n_protocols > 0 {
            let mut compressed: Vec<u32> = vec![0; 1 + (n_protocols - 1) / 4];
            for i in 0..n_protocols {
                debug!("Adding protocol: {}", protocols[i]);
                compressed[i % 4] |= u32::from(protocols[i]) << ((i % 4) * 8);
            }
            for item in compressed {
                values.push(MessageValue::Unsigned(item));
            }
        }
        Response::from(&values)
    }

    fn message_attributes(&self, request: &ScmiRequest) -> Response {
        let message_id: Result<MessageId, _> = request.get_unsigned(0).try_into();
        if message_id.is_err() {
            return Response::from(ReturnStatus::InvalidParameters);
        }
        match self.handlers.get(request.protocol_id, message_id.unwrap()) {
            Some(_) => Response::from(MessageValue::Unsigned(0)),
            None => Response::from(ReturnStatus::NotFound),
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::devices::{common::DeviceProperties, fake::FakeSensor};

    use super::*;

    #[test]
    fn test_response_from_status() {
        let status = ReturnStatus::Busy;
        let response = Response::from(status);
        assert_eq!(response.values.len(), 1);
        assert_eq!(response.values[0], MessageValue::Signed(status as i32));
    }

    #[test]
    fn test_response_from_value() {
        let value = MessageValue::Unsigned(28);
        let status = ReturnStatus::Success;
        let response = Response::from(value.clone());
        assert_eq!(response.values.len(), 2);
        assert_eq!(response.values[0], MessageValue::Signed(status as i32));
        assert_eq!(response.values[1], value);
    }

    #[test]
    fn test_response_from_values() {
        let status = ReturnStatus::Success;
        let values = vec![
            MessageValue::Signed(-2),
            MessageValue::Unsigned(8),
            MessageValue::String("foo".to_owned(), MAX_SIMPLE_STRING_LENGTH),
        ];
        let len = values.len() + 1;
        let response = Response::from(&values);
        assert_eq!(response.values.len(), len);
        assert_eq!(response.values[0], MessageValue::Signed(status as i32));
        for i in 1..len {
            assert_eq!(response.values[i], values[i - 1]);
        }
    }

    fn make_response(header: MessageHeader) -> ScmiResponse {
        let values = vec![
            MessageValue::Signed(-2),
            MessageValue::Unsigned(800_000_000),
            MessageValue::String("foo".to_owned(), MAX_SIMPLE_STRING_LENGTH),
        ];
        let response = Response::from(&values);
        ScmiResponse::from(header, response)
    }

    #[test]
    fn test_response() {
        let header: MessageHeader = 1_000_000;
        let scmi_response = make_response(header);
        assert_eq!(scmi_response.header, header);
        let bytes: Vec<u8> = vec![
            0x40, 0x42, 0x0F, 0x00, // header
            0x00, 0x00, 0x00, 0x00, // SUCCESS
            0xFE, 0xFF, 0xFF, 0xFF, // -2
            0x00, 0x08, 0xAF, 0x2F, // 800 000 000
            0x66, 0x6F, 0x6F, 0x00, // "foo" + NULLs
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];
        assert_eq!(scmi_response.ret_bytes, bytes);
        assert_eq!(scmi_response.len(), bytes.len());
        assert_eq!(scmi_response.as_slice(), bytes.as_slice());
    }

    #[test]
    fn test_communication_error_response() {
        let header: MessageHeader = 1_000_000;
        let scmi_response = make_response(header).communication_error();
        assert_eq!(scmi_response.header, header);
        let bytes: Vec<u8> = vec![
            0x40, 0x42, 0x0F, 0x00, // header
            0xF9, 0xFF, 0xFF, 0xFF, // ComsError
        ];
        assert_eq!(scmi_response.ret_bytes, bytes);
    }

    #[test]
    fn test_request() {
        let header: MessageHeader = 0x000304AB;
        let request = ScmiRequest::new(header);
        assert_eq!(request.header, header);
        assert_eq!(request.message_id, 0xAB);
        assert_eq!(request.message_type, MessageType::Command);
        assert_eq!(request.protocol_id, 0xC1);
    }

    #[test]
    fn test_request_unsupported() {
        let header: MessageHeader = 0x000102AB;
        let request = ScmiRequest::new(header);
        assert_eq!(request.header, header);
        assert_eq!(request.message_id, 0xAB);
        assert_eq!(request.message_type, MessageType::Unsupported);
        assert_eq!(request.protocol_id, 0x40);
    }

    fn make_request(protocol_id: ProtocolId, message_id: MessageId) -> ScmiRequest {
        let header: MessageHeader = u32::from(message_id) | (u32::from(protocol_id) << 10);
        ScmiRequest::new(header)
    }

    fn store_parameters(
        handler: &ScmiHandler,
        request: &mut ScmiRequest,
        parameters: &[MessageValue],
    ) {
        let mut bytes: Vec<u8> = vec![];
        for p in parameters {
            let value = match p {
                MessageValue::Unsigned(n) => u32::to_le_bytes(*n),
                MessageValue::Signed(n) => i32::to_le_bytes(*n),
                _ => panic!("Unsupported parameter type"),
            };
            bytes.append(&mut value.to_vec());
        }
        handler.store_parameters(request, bytes.as_slice());
    }

    #[test]
    fn test_handler_parameters() {
        let handler = ScmiHandler::new();
        let mut request = make_request(BASE_PROTOCOL_ID, BASE_DISCOVER_LIST_PROTOCOLS);
        assert_eq!(handler.number_of_parameters(&request), Some(1));

        let value: u32 = 1234567890;
        let parameters = [MessageValue::Unsigned(value)];
        store_parameters(&handler, &mut request, &parameters);
        assert_eq!(request.parameters, Some(parameters.to_vec()));
        assert_eq!(request.get_unsigned(0), value);
    }

    #[test]
    fn test_unsupported_parameters() {
        let handler = ScmiHandler::new();
        let request = make_request(BASE_PROTOCOL_ID, 0x4);
        assert_eq!(handler.number_of_parameters(&request), None);
    }

    fn make_handler() -> ScmiHandler {
        let handler = ScmiHandler::new();
        for i in 0..2 {
            let properties = DeviceProperties::new(vec![("name".to_owned(), format!("fake{i}"))]);
            let fake_sensor = FakeSensor::new_device(&properties).unwrap();
            handler.register_device(fake_sensor);
        }
        handler
    }

    fn test_message(
        protocol_id: ProtocolId,
        message_id: MessageId,
        parameters: Vec<MessageValue>,
        result_code: ReturnStatus,
        result_values: Vec<MessageValue>,
    ) {
        test_message_with_handler(
            protocol_id,
            message_id,
            parameters,
            result_code,
            result_values,
            &make_handler(),
        );
    }

    fn test_message_with_handler(
        protocol_id: ProtocolId,
        message_id: MessageId,
        parameters: Vec<MessageValue>,
        result_code: ReturnStatus,
        result_values: Vec<MessageValue>,
        handler: &ScmiHandler,
    ) {
        let mut request = make_request(protocol_id, message_id);
        let header = request.header;
        if !parameters.is_empty() {
            let parameter_slice = parameters.as_slice();
            store_parameters(handler, &mut request, parameter_slice);
        }

        let response = handler.handle(request);
        assert_eq!(response.header, header);
        let mut bytes: Vec<u8> = vec![];
        bytes.append(&mut header.to_le_bytes().to_vec());
        bytes.append(&mut (result_code as i32).to_le_bytes().to_vec());
        for value in result_values {
            let mut value_vec = match value {
                MessageValue::Unsigned(n) => n.to_le_bytes().to_vec(),
                MessageValue::Signed(n) => n.to_le_bytes().to_vec(),
                MessageValue::String(s, size) => {
                    let mut v = s.as_bytes().to_vec();
                    let v_len = v.len();
                    assert!(
                        v_len < size,
                        "String longer than specified: {v_len} >= {size}"
                    );
                    v.resize(size, b'\0');
                    v
                }
            };
            bytes.append(&mut value_vec);
        }
        assert_eq!(response.ret_bytes, bytes.as_slice());
    }

    #[test]
    fn test_base_version() {
        let values = vec![MessageValue::Unsigned(0x20000)];
        test_message(
            BASE_PROTOCOL_ID,
            BASE_VERSION,
            vec![],
            ReturnStatus::Success,
            values,
        );
    }

    #[test]
    fn test_base_protocol_attributes() {
        let result = vec![MessageValue::Unsigned(1)];
        test_message(
            BASE_PROTOCOL_ID,
            BASE_PROTOCOL_ATTRIBUTES,
            vec![],
            ReturnStatus::Success,
            result,
        );
    }

    #[test]
    fn test_base_protocol_message_attributes_supported() {
        let parameters = vec![MessageValue::Unsigned(u32::from(BASE_DISCOVER_VENDOR))];
        let result = vec![MessageValue::Unsigned(0)];
        test_message(
            BASE_PROTOCOL_ID,
            BASE_MESSAGE_ATTRIBUTES,
            parameters,
            ReturnStatus::Success,
            result,
        );
    }

    #[test]
    fn test_base_protocol_message_attributes_unsupported() {
        let parameters = vec![MessageValue::Unsigned(0x4)];
        test_message(
            BASE_PROTOCOL_ID,
            BASE_MESSAGE_ATTRIBUTES,
            parameters,
            ReturnStatus::NotFound,
            vec![],
        );
    }

    #[test]
    fn test_base_protocol_message_attributes_invalid() {
        let parameters = vec![MessageValue::Unsigned(0x100)];
        test_message(
            BASE_PROTOCOL_ID,
            BASE_MESSAGE_ATTRIBUTES,
            parameters,
            ReturnStatus::InvalidParameters,
            vec![],
        );
    }

    #[test]
    fn test_base_discover_vendor() {
        let result = vec![MessageValue::String(
            "rust-vmm".to_owned(),
            MAX_SIMPLE_STRING_LENGTH,
        )];
        test_message(
            BASE_PROTOCOL_ID,
            BASE_DISCOVER_VENDOR,
            vec![],
            ReturnStatus::Success,
            result,
        );
    }

    #[test]
    fn test_base_discover_implementation_version() {
        let values = vec![MessageValue::Unsigned(0)];
        test_message(
            BASE_PROTOCOL_ID,
            BASE_DISCOVER_IMPLEMENTATION_VERSION,
            vec![],
            ReturnStatus::Success,
            values,
        );
    }

    #[test]
    fn test_base_discover_list_protocols() {
        let parameters = vec![MessageValue::Unsigned(0)];
        let result = vec![MessageValue::Unsigned(1), MessageValue::Unsigned(21)];
        test_message(
            BASE_PROTOCOL_ID,
            BASE_DISCOVER_LIST_PROTOCOLS,
            parameters,
            ReturnStatus::Success,
            result,
        );
    }

    #[test]
    fn test_sensor_version() {
        let values = vec![MessageValue::Unsigned(0x30000)];
        test_message(
            SENSOR_PROTOCOL_ID,
            SENSOR_VERSION,
            vec![],
            ReturnStatus::Success,
            values,
        );
    }

    #[test]
    fn test_sensor_attributes() {
        let result = vec![
            MessageValue::Unsigned(2),
            MessageValue::Unsigned(0),
            MessageValue::Unsigned(0),
            MessageValue::Unsigned(0),
        ];
        test_message(
            SENSOR_PROTOCOL_ID,
            SENSOR_ATTRIBUTES,
            vec![],
            ReturnStatus::Success,
            result,
        );
    }

    #[test]
    fn test_sensor_message_attributes_supported() {
        let parameters = vec![MessageValue::Unsigned(u32::from(SENSOR_DESCRIPTION_GET))];
        let result = vec![MessageValue::Unsigned(0)];
        test_message(
            SENSOR_PROTOCOL_ID,
            SENSOR_MESSAGE_ATTRIBUTES,
            parameters,
            ReturnStatus::Success,
            result,
        );
    }

    #[test]
    fn test_sensor_message_attributes_unsupported() {
        let parameters = vec![MessageValue::Unsigned(0x5)];
        test_message(
            SENSOR_PROTOCOL_ID,
            SENSOR_MESSAGE_ATTRIBUTES,
            parameters,
            ReturnStatus::NotFound,
            vec![],
        );
    }

    #[test]
    fn test_sensor_protocol_message_attributes_invalid() {
        let parameters = vec![MessageValue::Unsigned(0x100)];
        test_message(
            SENSOR_PROTOCOL_ID,
            SENSOR_MESSAGE_ATTRIBUTES,
            parameters,
            ReturnStatus::InvalidParameters,
            vec![],
        );
    }

    fn check_sensor_description(sensor_index: u32) {
        let n_sensors = 2;
        let parameters = vec![MessageValue::Unsigned(sensor_index)];
        let mut result = vec![MessageValue::Unsigned(n_sensors - sensor_index)];
        for i in sensor_index..n_sensors {
            let mut description = vec![
                MessageValue::Unsigned(i),
                MessageValue::Unsigned(1 << 30),
                MessageValue::Unsigned(3 << 16 | 1 << 8),
                MessageValue::String(format!("fake{i}"), MAX_SIMPLE_STRING_LENGTH),
            ];
            result.append(&mut description);
        }
        test_message(
            SENSOR_PROTOCOL_ID,
            SENSOR_DESCRIPTION_GET,
            parameters,
            ReturnStatus::Success,
            result,
        );
    }

    #[test]
    fn test_sensor_description_get() {
        check_sensor_description(0);
        check_sensor_description(1);
    }

    #[test]
    fn test_sensor_description_get_invalid() {
        let parameters = vec![MessageValue::Unsigned(2)];
        test_message(
            SENSOR_PROTOCOL_ID,
            SENSOR_DESCRIPTION_GET,
            parameters,
            ReturnStatus::InvalidParameters,
            vec![],
        );
    }

    fn check_sensor_axis_description(axis_index: u32) {
        let n_axes = 3;
        let parameters = vec![
            MessageValue::Unsigned(0),
            MessageValue::Unsigned(axis_index),
        ];
        let mut result = vec![MessageValue::Unsigned(n_axes - axis_index)];
        for i in axis_index..n_axes {
            let name = format!("acc_{}", char::from_u32('X' as u32 + i).unwrap()).to_string();
            let mut description = vec![
                MessageValue::Unsigned(i),
                MessageValue::Unsigned(0),
                MessageValue::Unsigned(u32::from(SENSOR_UNIT_METERS_PER_SECOND_SQUARED)),
                MessageValue::String(name, MAX_SIMPLE_STRING_LENGTH),
            ];
            result.append(&mut description);
        }
        test_message(
            SENSOR_PROTOCOL_ID,
            SENSOR_AXIS_DESCRIPTION_GET,
            parameters,
            ReturnStatus::Success,
            result,
        );
    }

    #[test]
    fn test_sensor_axis_description_get() {
        check_sensor_axis_description(0);
        check_sensor_axis_description(1);
        check_sensor_axis_description(2);
    }

    #[test]
    fn test_sensor_axis_description_get_invalid() {
        let parameters = vec![MessageValue::Unsigned(0), MessageValue::Unsigned(3)];
        test_message(
            SENSOR_PROTOCOL_ID,
            SENSOR_AXIS_DESCRIPTION_GET,
            parameters,
            ReturnStatus::InvalidParameters,
            vec![],
        );
    }

    fn check_enabled(sensor: u32, enabled: bool, handler: &ScmiHandler) {
        let enabled_flag = u32::from(enabled);
        let parameters = vec![MessageValue::Unsigned(sensor)];
        let result = vec![MessageValue::Unsigned(enabled_flag)];
        test_message_with_handler(
            SENSOR_PROTOCOL_ID,
            SENSOR_CONFIG_GET,
            parameters,
            ReturnStatus::Success,
            result,
            handler,
        );
    }

    #[test]
    fn test_sensor_config_get() {
        let handler = make_handler();
        check_enabled(0, false, &handler);
    }

    fn enable_sensor(sensor: u32, enable: bool, handler: &ScmiHandler) {
        let enable_flag = u32::from(enable);
        let parameters = vec![
            MessageValue::Unsigned(sensor),
            MessageValue::Unsigned(enable_flag),
        ];
        let result = vec![];
        test_message_with_handler(
            SENSOR_PROTOCOL_ID,
            SENSOR_CONFIG_SET,
            parameters,
            ReturnStatus::Success,
            result,
            handler,
        );
    }

    #[test]
    fn test_sensor_config_set() {
        let handler = make_handler();
        enable_sensor(0, true, &handler);
        check_enabled(0, true, &handler);
        check_enabled(1, false, &handler);
        enable_sensor(1, true, &handler);
        check_enabled(1, true, &handler);
        enable_sensor(0, true, &handler);
        check_enabled(0, true, &handler);
        enable_sensor(0, false, &handler);
        check_enabled(0, false, &handler);
    }

    #[test]
    fn test_sensor_config_set_invalid() {
        let parameters = vec![MessageValue::Unsigned(0), MessageValue::Unsigned(3)];
        test_message(
            SENSOR_PROTOCOL_ID,
            SENSOR_CONFIG_SET,
            parameters,
            ReturnStatus::NotSupported,
            vec![],
        );
    }

    #[test]
    fn test_sensor_reading_get() {
        let handler = make_handler();
        for sensor in 0..2 {
            enable_sensor(sensor, true, &handler);
        }
        for iteration in 0..2 {
            for sensor in 0..2 {
                let parameters = vec![MessageValue::Unsigned(sensor), MessageValue::Unsigned(0)];
                let result = vec![
                    MessageValue::Unsigned(iteration),
                    MessageValue::Unsigned(0),
                    MessageValue::Unsigned(0),
                    MessageValue::Unsigned(0),
                    MessageValue::Unsigned(iteration + 100),
                    MessageValue::Unsigned(0),
                    MessageValue::Unsigned(0),
                    MessageValue::Unsigned(0),
                    MessageValue::Unsigned(iteration + 200),
                    MessageValue::Unsigned(0),
                    MessageValue::Unsigned(0),
                    MessageValue::Unsigned(0),
                ];
                test_message_with_handler(
                    SENSOR_PROTOCOL_ID,
                    SENSOR_READING_GET,
                    parameters,
                    ReturnStatus::Success,
                    result,
                    &handler,
                );
            }
        }
    }
}
