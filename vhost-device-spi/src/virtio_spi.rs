// VirtIO SPI definitions
//
// Copyright (c) 2024 Qualcomm Innovation Center, Inc. All rights reserved.
//          Haixu Cui <quic_haixcui@quicinc.com>
//
// SPDX-License-Identifier: Apache-2.0 or BSD-3-Clause

use bitflags::bitflags;
use vmm_sys_util::{ioctl_ioc_nr, ioctl_ior_nr, ioctl_iow_nr};

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
    let mut size: u32 = 0;
    if n * 32 < (1 << _IOC_SIZEBITS) {
        size = n * 32;
    }
    (SPI_IOC_MESSAGE_BASE | (size << _IOC_SIZESHIFT)) as u64
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

    pub struct ConfigNbits: u8 {
        const DUAL = 0x1;
        const QUAD = 0x2;
        const OCTAL = 0x4;
    }

    pub struct ConfigMode: u32 {
        const CPHA_0 = 0x1;
        const CPHA_1 = 0x2;
        const CPOL_0 = 0x4;
        const CPOL_1 = 0x8;
        const CS_HIGH = 0x10;
        const LSB = 0x20;
        const LOOP = 0x40;
    }

    pub struct ReqMode: u32 {
        const CPHA = 1 << 0;
        const CPOL = 1 << 1;
        const CS_HIGH = 1 << 2;
        const LSB_FIRST = 1 << 3;
        const LOOP = 1 << 4;
    }
}
