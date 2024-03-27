// Virtio SPI definitions
//
// Copyright (c) 2024 Qualcomm Innovation Center, Inc. All rights reserved.
//          Haixu Cui <quic_haixcui@quicinc.com>
//
// SPDX-License-Identifier: Apache-2.0 or BSD-3-Clause

use bitflags::bitflags;

bitflags! {
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
