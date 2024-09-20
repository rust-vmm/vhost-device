// Linux SPI bindings
//
// Copyright (c) 2024 Qualcomm Innovation Center, Inc. All rights reserved.
//          Haixu Cui <quic_haixcui@quicinc.com>
//
// SPDX-License-Identifier: Apache-2.0 or BSD-3-Clause

use bitflags::bitflags;
use vmm_sys_util::{ioctl_ioc_nr, ioctl_ior_nr, ioctl_iow_nr};

/// Describes a single SPI transfer
#[derive(Debug)]
#[repr(C)]
pub struct SpiIocTransfer {
    /// Holds pointer to userspace buffer with transmit data, or null
    pub tx_buf: u64,
    /// Holds pointer to userspace buffer for receive data, or null.
    pub rx_buf: u64,
    /// Length of tx and rx buffers, in bytes.
    pub len: u32,
    /// Temporary override of the device's bitrate.
    pub speed_hz: u32,
    /// If nonzero, how long to delay after the last bit transfer
    /// before optionally deselecting the device before the next transfer.
    pub delay_usecs: u16,
    /// Temporary override of the device's wordsize.
    pub bits_per_word: u8,
    /// True to deselect device before starting the next transfer.
    pub cs_change: u8,
    /// Number of bits used for writing.
    pub tx_nbits: u8,
    /// Number of bits used for reading.
    pub rx_nbits: u8,
    /// If nonzero, how long to wait between words within one
    /// transfer. This property needs explicit support in the SPI controller,
    /// otherwise it is silently ignored
    pub word_delay_usecs: u8,
    pub _padding: u8,
}

/// Linux SPI definitions
/// IOCTL commands, refer Linux's Documentation/spi/spidev.rst for further details.
const _IOC_SIZEBITS: u32 = 14;
const _IOC_SIZESHIFT: u32 = 16;
const SPI_IOC_MESSAGE_BASE: u32 = 0x40006b00;

ioctl_ior_nr!(SPI_IOC_RD_BITS_PER_WORD, 107, 3, u8);
ioctl_iow_nr!(SPI_IOC_WR_BITS_PER_WORD, 107, 3, u8);
ioctl_ior_nr!(SPI_IOC_RD_MAX_SPEED_HZ, 107, 4, u32);
ioctl_iow_nr!(SPI_IOC_WR_MAX_SPEED_HZ, 107, 4, u32);
ioctl_ior_nr!(SPI_IOC_RD_MODE32, 107, 5, u32);
ioctl_iow_nr!(SPI_IOC_WR_MODE32, 107, 5, u32);

// Corresponds to the SPI_IOC_MESSAGE macro in Linux
pub fn spi_ioc_message(n: u32) -> u64 {
    let size = if n * 32 < (1 << _IOC_SIZEBITS) {
        n * 32
    } else {
        0
    };
    u64::from(SPI_IOC_MESSAGE_BASE | (size << _IOC_SIZESHIFT))
}

bitflags! {
    pub struct LnxSpiMode: u32 {
        const CPHA = 1 << 0;
        const CPOL = 1 << 1;
        const CS_HIGH = 1 << 2;
        const LSB_FIRST = 1 << 3;
        const LOOP = 1 << 5;
        const TX_DUAL = 1 << 8;
        const TX_QUAD = 1 << 9;
        const TX_OCTAL = 1 << 13;
        const RX_DUAL = 1 << 10;
        const RX_QUAD = 1 << 11;
        const RX_OCTAL = 1 << 14;
    }
}
