// SPDX-FileCopyrightText: Red Hat, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Implementation of SCMI bindings to host devices.
//!
//! The general infrastructure is implemented in [crate::devices::common] module.
//! Access to particular kinds of devices is implemented in the other modules:
//! - [crate::devices::fake] provides a fake sensor.
//! - [crate::devices::iio] implements access to industrial I/O (IIO) devices.

pub mod common;
pub mod fake;
pub mod iio;
