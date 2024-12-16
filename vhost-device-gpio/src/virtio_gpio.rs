// VirtIO GPIO definitions
//
// Copyright 2023 Linaro Ltd. All Rights Reserved.
//          Viresh Kumar <viresh.kumar@linaro.org>
//
// SPDX-License-Identifier: Apache-2.0 or BSD-3-Clause

//! Virtio specification definitions

// Virtio GPIO request types

pub const VIRTIO_GPIO_MSG_GET_LINE_NAMES: u16 = 0x0001;
pub const VIRTIO_GPIO_MSG_GET_DIRECTION: u16 = 0x0002;
pub const VIRTIO_GPIO_MSG_SET_DIRECTION: u16 = 0x0003;
pub const VIRTIO_GPIO_MSG_GET_VALUE: u16 = 0x0004;
pub const VIRTIO_GPIO_MSG_SET_VALUE: u16 = 0x0005;
pub const VIRTIO_GPIO_MSG_IRQ_TYPE: u16 = 0x0006;

// Direction types

pub const VIRTIO_GPIO_DIRECTION_NONE: u8 = 0x00;
pub const VIRTIO_GPIO_DIRECTION_OUT: u8 = 0x01;
pub const VIRTIO_GPIO_DIRECTION_IN: u8 = 0x02;

// Virtio GPIO IRQ types

pub const VIRTIO_GPIO_IRQ_TYPE_NONE: u16 = 0x00;
pub const VIRTIO_GPIO_IRQ_TYPE_EDGE_RISING: u16 = 0x01;
pub const VIRTIO_GPIO_IRQ_TYPE_EDGE_FALLING: u16 = 0x02;
pub const VIRTIO_GPIO_IRQ_TYPE_EDGE_BOTH: u16 =
    VIRTIO_GPIO_IRQ_TYPE_EDGE_RISING | VIRTIO_GPIO_IRQ_TYPE_EDGE_FALLING;
pub const VIRTIO_GPIO_IRQ_TYPE_LEVEL_HIGH: u16 = 0x04;
pub const VIRTIO_GPIO_IRQ_TYPE_LEVEL_LOW: u16 = 0x08;
pub const VIRTIO_GPIO_IRQ_TYPE_ALL: u16 = VIRTIO_GPIO_IRQ_TYPE_EDGE_BOTH
    | VIRTIO_GPIO_IRQ_TYPE_LEVEL_HIGH
    | VIRTIO_GPIO_IRQ_TYPE_LEVEL_LOW;
