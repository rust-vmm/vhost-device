// VIRTIO CAN Emulation via vhost-user
//
// Copyright 2023 VIRTUAL OPEN SYSTEMS SAS. All Rights Reserved.
//          Timos Ampelikiotis <t.ampelikiotis@virtualopensystems.com>
//
// SPDX-License-Identifier: Apache-2.0 or BSD-3-Clause

#[cfg(target_env = "gnu")]
mod backend;
#[cfg(target_env = "gnu")]
mod can;
#[cfg(target_env = "gnu")]
mod vhu_can;

#[cfg(target_env = "gnu")]
fn main() {
    backend::can_init()
}
