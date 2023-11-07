// SPDX-License-Identifier: Apache-2.0 or BSD-3-Clause

#[derive(Clone, Copy, Eq, PartialEq, Debug)]
pub(crate) enum RxOps {
    /// VSOCK_OP_REQUEST
    Request = 0,
    /// VSOCK_OP_RW
    Rw = 1,
    /// VSOCK_OP_RESPONSE
    Response = 2,
    /// VSOCK_OP_CREDIT_UPDATE
    CreditUpdate = 3,
    /// VSOCK_OP_RST
    Reset = 4,
}

impl RxOps {
    /// Convert enum value into bitmask.
    pub fn bitmask(self) -> u8 {
        1u8 << (self as u8)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rxops() {
        let rx = RxOps::Request;
        // Increase coverage testing Clone and Debug traits
        assert_eq!(rx, rx.clone());
        assert_eq!(format!("{rx:?}"), "Request");
    }

    #[test]
    fn test_bitmask() {
        assert_eq!(1, RxOps::Request.bitmask());
        assert_eq!(2, RxOps::Rw.bitmask());
        assert_eq!(4, RxOps::Response.bitmask());
        assert_eq!(8, RxOps::CreditUpdate.bitmask());
        assert_eq!(16, RxOps::Reset.bitmask());
    }
}
