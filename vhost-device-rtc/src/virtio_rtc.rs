// SPDX-License-Identifier: Apache-2.0 or BSD-3-Clause
// Copyright 2026 Panasonic Automotive Systems Co., Ltd.
// Author: Manos Pitsidianakis <manos.pitsidianakis@linaro.org>

use vm_memory::{ByteValued, Le16, Le64};

// virtqueues

pub const REQUEST_QUEUE_IDX: u16 = 0;
pub const ALARM_QUEUE_IDX: u16 = 1;
pub const NUM_QUEUES: u16 = 2;

pub const VIRTIO_RTC_F_ALARM: u32 = 0;

/// common request header
#[doc(alias = "virtio_rtc_req_head")]
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
#[repr(C)]
pub struct VirtioRtcReqHead {
    pub msg_type: Le16,
    pub reserved: [u8; 6],
}

// SAFETY: This struct is plain-old-data.
unsafe impl ByteValued for VirtioRtcReqHead {}

/// common response header
#[doc(alias = "virtio_rtc_resp_head")]
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
#[repr(C)]
pub struct VirtioRtcRespHead {
    pub status: u8,
    pub reserved: [u8; 7],
}

// SAFETY: This struct is plain-old-data.
unsafe impl ByteValued for VirtioRtcRespHead {}

pub const VIRTIO_RTC_S_OK: u8 = 0;
pub const VIRTIO_RTC_S_EOPNOTSUPP: u8 = 2;
pub const VIRTIO_RTC_S_ENODEV: u8 = 3;
pub const VIRTIO_RTC_S_EINVAL: u8 = 4;
pub const VIRTIO_RTC_S_EIO: u8 = 5;

// Clock types:

pub const VIRTIO_RTC_CLOCK_UTC: u8 = 0;
pub const VIRTIO_RTC_CLOCK_TAI: u8 = 1;
pub const VIRTIO_RTC_CLOCK_MONOTONIC: u8 = 2;
pub const VIRTIO_RTC_CLOCK_UTC_SMEARED: u8 = 3;
pub const VIRTIO_RTC_CLOCK_UTC_MAYBE_SMEARED: u8 = 4;

// Smearing Variants

pub const VIRTIO_RTC_SMEAR_UNSPECIFIED: u8 = 0;
pub const VIRTIO_RTC_SMEAR_NOON_LINEAR: u8 = 1;
pub const VIRTIO_RTC_SMEAR_UTC_SLS: u8 = 2;

// Hardware counters

/// Arm Generic Timer Counter-timer Virtual Count Register (`CNTVCT_EL0`)
pub const VIRTIO_RTC_COUNTER_ARM_VCT: u8 = 0;
/// x86 Time-Stamp Counter
pub const VIRTIO_RTC_COUNTER_X86_TSC: u8 = 1;
/// Invalid
pub const VIRTIO_RTC_COUNTER_INVALID: u8 = 0xFF;

// Control Requests

/// Discovers the number of clocks
pub const VIRTIO_RTC_REQ_CFG: u16 = 0x1000;

#[doc(alias = "virtio_rtc_req_cfg")]
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
#[repr(C)]
pub struct VirtioRtcReqCfg {
    pub head: VirtioRtcReqHead,
}

#[doc(alias = "virtio_rtc_resp_cfg")]
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
#[repr(C)]
pub struct VirtioRtcRespCfg {
    pub head: VirtioRtcRespHead,
    pub num_clocks: Le16,
    pub reserved: [u8; 6],
}

// SAFETY: This struct is plain-old-data.
unsafe impl ByteValued for VirtioRtcRespCfg {}

/// Discovers the capabilities of the clock identified by the `clock_id` field.
pub const VIRTIO_RTC_REQ_CLOCK_CAP: u16 = 0x1001;

#[doc(alias = "virtio_rtc_req_clock_cap")]
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
#[repr(C)]
pub struct VirtioRtcReqClockCap {
    pub head: VirtioRtcReqHead,
    pub clock_id: Le16,
    pub reserved: [u8; 6],
}

// SAFETY: This struct is plain-old-data.
unsafe impl ByteValued for VirtioRtcReqClockCap {}

#[doc(alias = "virtio_rtc_resp_clock_cap")]
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
#[repr(C)]
pub struct VirtioRtcRespClockCap {
    pub head: VirtioRtcRespHead,
    pub r#type: u8,
    pub leap_second_smearing: u8,
    pub flags: u8,
    pub reserved: [u8; 5],
}

/// If `VIRTIO_RTC_F_ALARM` has been negotiated, the `VIRTIO_RTC_FLAG_ALARM_CAP`
/// flag indicates that the clock supports an alarm.
pub const VIRTIO_RTC_FLAG_ALARM_CAP: u8 = 1;

// SAFETY: This struct is plain-old-data.
unsafe impl ByteValued for VirtioRtcRespClockCap {}

/// Discovers whether the device supports cross-timestamping for a particular
/// pair of clock and hardware counter.
pub const VIRTIO_RTC_REQ_CROSS_CAP: u16 = 0x1002;

#[doc(alias = "virtio_rtc_req_cross_cap")]
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
#[repr(C)]
pub struct VirtioRtcReqCrossCap {
    pub head: VirtioRtcReqHead,
    pub clock_id: Le16,
    pub hw_counter: u8,
    pub reserved: [u8; 5],
}

// SAFETY: This struct is plain-old-data.
unsafe impl ByteValued for VirtioRtcReqCrossCap {}

#[doc(alias = "virtio_rtc_resp_cross_cap")]
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
#[repr(C)]
pub struct VirtioRtcRespCrossCap {
    pub head: VirtioRtcRespHead,
    pub flags: u8,
    pub reserved: [u8; 7],
}

// SAFETY: This struct is plain-old-data.
unsafe impl ByteValued for VirtioRtcRespCrossCap {}

/// The clock supports cross-timestamping for the particular clock and hardware
/// counter.
pub const VIRTIO_RTC_FLAG_CROSS_CAP: u8 = 1;

/// Reads the clock identified by the `clock_id` field. The device supports this
/// request for every clock.
pub const VIRTIO_RTC_REQ_READ: u16 = 0x0001;

#[doc(alias = "virtio_rtc_req_read")]
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
#[repr(C)]
pub struct VirtioRtcReqRead {
    pub head: VirtioRtcReqHead,
    pub clock_id: Le16,
    pub reserved: [u8; 6],
}

// SAFETY: This struct is plain-old-data.
unsafe impl ByteValued for VirtioRtcReqRead {}

#[doc(alias = "virtio_rtc_resp_read")]
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
#[repr(C)]
pub struct VirtioRtcRespRead {
    pub head: VirtioRtcRespHead,
    pub clock_reading: Le64,
}

// SAFETY: This struct is plain-old-data.
unsafe impl ByteValued for VirtioRtcRespRead {}

/// Returns a cross-timestamp for the clock identified by the `clock_id` field.
pub const VIRTIO_RTC_REQ_READ_CROSS: u16 = 0x0002;

#[doc(alias = "virtio_rtc_req_read_cross")]
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
#[repr(C)]
pub struct VirtioRtcReqReadCross {
    pub head: VirtioRtcReqHead,
    pub clock_id: Le16,
    pub hw_counter: u8,
    pub reserved: [u8; 5],
}

// SAFETY: This struct is plain-old-data.
unsafe impl ByteValued for VirtioRtcReqReadCross {}

#[doc(alias = "virtio_rtc_resp_read_cross")]
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
#[repr(C)]
pub struct VirtioRtcRespReadCross {
    pub head: VirtioRtcRespHead,
    pub clock_reading: Le64,
    pub counter_cycles: Le64,
}

// SAFETY: This struct is plain-old-data.
unsafe impl ByteValued for VirtioRtcRespReadCross {}

#[doc(alias = "virtio_rtc_notif_head")]
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
#[repr(C)]
/// common notification header
pub struct VirtioRtcNotifHead {
    pub msg_type: Le16,
    pub reserved: [u8; 6],
}

// SAFETY: This struct is plain-old-data.
unsafe impl ByteValued for VirtioRtcNotifHead {}

/// message type
pub const VIRTIO_RTC_NOTIF_ALARM: u16 = 0x2000;

#[doc(alias = "virtio_rtc_notif_alarm")]
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
#[repr(C)]
pub struct VirtioRtcNotifAlarm {
    pub head: VirtioRtcNotifHead,
    pub clock_id: Le16,
    pub reserved: [u8; 6],
}

// SAFETY: This struct is plain-old-data.
unsafe impl ByteValued for VirtioRtcNotifAlarm {}

/// message type
pub const VIRTIO_RTC_REQ_READ_ALARM: u16 = 0x1003;

#[doc(alias = "virtio_rtc_req_read_alarm")]
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
#[repr(C)]
pub struct VirtioRtcReqReadAlarm {
    pub head: VirtioRtcReqHead,
    pub clock_id: Le16,
    pub reserved: [u8; 6],
}

// SAFETY: This struct is plain-old-data.
unsafe impl ByteValued for VirtioRtcReqReadAlarm {}

#[doc(alias = "virtio_rtc_resp_read_alarm")]
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
#[repr(C)]
pub struct VirtioRtcRespReadAlarm {
    pub head: VirtioRtcRespHead,
    pub alarm_time: Le64,
    pub flags: u8,
    pub reserved: [u8; 7],
}

pub const VIRTIO_RTC_FLAG_ALARM_ENABLED: u8 = 1 << 0;

// SAFETY: This struct is plain-old-data.
unsafe impl ByteValued for VirtioRtcRespReadAlarm {}

/// message type
pub const VIRTIO_RTC_REQ_SET_ALARM: u16 = 0x1004;

#[doc(alias = "virtio_rtc_req_set_alarm")]
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
#[repr(C)]
pub struct VirtioRtcReqSetAlarm {
    pub head: VirtioRtcReqHead,
    pub alarm_time: Le64,
    pub clock_id: Le16,
    /* flag: VIRTIO_RTC_FLAG_ALARM_ENABLED */
    pub flags: u8,
    pub reserved: [u8; 5],
}

// SAFETY: This struct is plain-old-data.
unsafe impl ByteValued for VirtioRtcReqSetAlarm {}

#[doc(alias = "virtio_rtc_resp_set_alarm")]
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
#[repr(C)]
pub struct VirtioRtcRespSetAlarm {
    pub head: VirtioRtcRespHead,
    /* no response params */
}

// SAFETY: This struct is plain-old-data.
unsafe impl ByteValued for VirtioRtcRespSetAlarm {}

/// message type
pub const VIRTIO_RTC_REQ_SET_ALARM_ENABLED: u16 = 0x1005;

#[doc(alias = "virtio_rtc_req_set_alarm_enabled")]
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
#[repr(C)]
pub struct VirtioRtcReqSetAlarmEnabled {
    pub head: VirtioRtcReqHead,
    pub clock_id: Le16,
    /* flag: VIRTIO_RTC_FLAG_ALARM_ENABLED */
    pub flags: u8,
    pub reserved: [u8; 5],
}

// SAFETY: This struct is plain-old-data.
unsafe impl ByteValued for VirtioRtcReqSetAlarmEnabled {}

#[doc(alias = "virtio_rtc_resp_set_alarm_enabled")]
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
#[repr(C)]
pub struct VirtioRtcRespSetAlarmEnabled {
    pub head: VirtioRtcRespHead,
    /* no response params */
}

// SAFETY: This struct is plain-old-data.
unsafe impl ByteValued for VirtioRtcRespSetAlarmEnabled {}
