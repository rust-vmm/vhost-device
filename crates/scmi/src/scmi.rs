// SPDX-FileCopyrightText: Red Hat, Inc.
// SPDX-License-Identifier: Apache-2.0

use log::debug;

pub type MessageHeader = u32;
// SCMI specification talks about Le32 parameter and return values.
// VirtIO SCMI specification talks about u8 SCMI values.
// Let's stick with SCMI specification for implementation simplicity.
#[derive(Clone, Debug, PartialEq)]
#[allow(dead_code)]
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

impl From<&MessageValues> for Response {
    #[allow(dead_code)]
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

pub struct ScmiHandler {}

impl ScmiHandler {
    pub const fn new() -> Self {
        Self {}
    }

    pub fn handle(&mut self, request: ScmiRequest) -> ScmiResponse {
        let response = match request.message_type {
            // TODO: Implement a mechanism to invoke the proper protocol &
            // message handling on command requests.
            MessageType::Command => Response::from(ReturnStatus::NotSupported),
            MessageType::Unsupported => Response::from(ReturnStatus::NotSupported),
        };
        ScmiResponse::from(request.header, response)
    }

    pub fn number_of_parameters(&self, _request: &ScmiRequest) -> Option<NParameters> {
        // TODO: Implement.
        Some(0)
    }

    pub fn store_parameters(&self, _request: &mut ScmiRequest, _buffer: &[u8]) {
        // TODO: Implement (depends on knowledge of the number of parameters).
    }
}

#[allow(dead_code)]
pub struct ScmiRequest {
    header: MessageHeader,     // 32-bit unsigned integer, split below:
    message_id: MessageId,     // bits 7:0
    message_type: MessageType, // bits 9:8
    protocol_id: ProtocolId,   // bits 17:10
    // token: u16,             // bits 27:18
    // bits 31:28 are reserved, must be 0
    _parameters: Option<MessageValues>, // set later based on the number of parameters
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
            _parameters: None,
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
}
