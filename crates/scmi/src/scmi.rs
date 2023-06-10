// SPDX-FileCopyrightText: Red Hat, Inc.
// SPDX-License-Identifier: Apache-2.0

use std::collections::HashMap;

use itertools::Itertools;
use log::debug;

pub type MessageHeader = u32;
// SCMI specification talks about Le32 parameter and return values.
// VirtIO SCMI specification talks about u8 SCMI values.
// Let's stick with SCMI specification for implementation simplicity.
#[derive(Clone, Debug, PartialEq)]
enum MessageValue {
    Signed(i32),
    Unsigned(u32),
    String(String, usize), // string, expected characters
}
type MessageValues = Vec<MessageValue>;

#[derive(Debug, PartialEq)]
enum MessageType {
    // 4-bit unsigned integer
    Command,     // 0
    Unsupported, // anything else
}
type MessageId = u8;
type ProtocolId = u8;
type NParameters = u8;

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

#[derive(Debug)]
pub struct ScmiResponse {
    header: MessageHeader,
    ret_bytes: Vec<u8>,
}

impl ScmiResponse {
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
        match self.parameters.as_ref().expect("Missing parameters")[parameter] {
            MessageValue::Unsigned(value) => value,
            _ => panic!("Wrong parameter"),
        }
    }
}

const BASE_PROTOCOL_ID: ProtocolId = 0x10;
const BASE_VERSION: MessageId = 0x0;
const BASE_PROTOCOL_ATTRIBUTES: MessageId = 0x1;
const BASE_MESSAGE_ATTRIBUTES: MessageId = 0x2;
const BASE_DISCOVER_VENDOR: MessageId = 0x3;
const BASE_DISCOVER_IMPLEMENTATION_VERSION: MessageId = 0x5;
const BASE_DISCOVER_LIST_PROTOCOLS: MessageId = 0x6;

enum ParameterType {
    _SignedInt32,
    UnsignedInt32,
}
type ParameterSpecification = Vec<ParameterType>;

type HandlerFunction = fn(&ScmiHandler, &ScmiRequest) -> Response;
struct HandlerInfo {
    name: String,
    parameters: ParameterSpecification,
    function: HandlerFunction,
}

// HandlerMap layout is suboptimal but let's prefer simplicity for now.
struct HandlerMap(HashMap<(ProtocolId, MessageId), HandlerInfo>);

impl HandlerMap {
    fn new() -> Self {
        let mut map = Self(HashMap::new());
        map.make_base_handlers();
        map
    }

    fn keys(&self) -> std::collections::hash_map::Keys<(u8, u8), HandlerInfo> {
        self.0.keys()
    }

    fn get(&self, protocol_id: ProtocolId, message_id: MessageId) -> Option<&HandlerInfo> {
        self.0.get(&(protocol_id, message_id))
    }

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
            |_, _| -> Response { Response::from(MessageValue::String("rust-vmm".to_string(), 16)) },
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
}

pub struct ScmiHandler {
    handlers: HandlerMap,
}

impl ScmiHandler {
    pub fn new() -> Self {
        Self {
            handlers: HandlerMap::new(),
        }
    }

    fn request_handler(&self, request: &ScmiRequest) -> Option<&HandlerInfo> {
        self.handlers.get(request.protocol_id, request.message_id)
    }

    pub fn handle(&mut self, request: ScmiRequest) -> ScmiResponse {
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
            MessageValue::String("foo".to_owned(), 16),
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
            MessageValue::String("foo".to_owned(), 16),
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

    fn test_message(
        protocol_id: ProtocolId,
        message_id: MessageId,
        parameters: Vec<MessageValue>,
        result_code: ReturnStatus,
        result_values: Vec<MessageValue>,
    ) {
        let mut handler = ScmiHandler::new();
        let mut request = make_request(protocol_id, message_id);
        let header = request.header;
        if !parameters.is_empty() {
            let parameter_slice = parameters.as_slice();
            store_parameters(&handler, &mut request, parameter_slice);
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
        let result = vec![MessageValue::Unsigned(0)];
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
        let result = vec![MessageValue::String(String::from("rust-vmm"), 16)];
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
        let result = vec![MessageValue::Unsigned(0)];
        test_message(
            BASE_PROTOCOL_ID,
            BASE_DISCOVER_LIST_PROTOCOLS,
            parameters,
            ReturnStatus::Success,
            result,
        );
    }
}
