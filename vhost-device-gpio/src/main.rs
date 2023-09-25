// VIRTIO GPIO Emulation via vhost-user
//
// Copyright 2022 Linaro Ltd. All Rights Reserved.
//          Viresh Kumar <viresh.kumar@linaro.org>
//
// SPDX-License-Identifier: Apache-2.0 or BSD-3-Clause

#[cfg(target_env = "gnu")]
mod backend;
#[cfg(target_env = "gnu")]
mod gpio;
#[cfg(target_env = "gnu")]
mod vhu_gpio;

#[cfg(target_env = "gnu")]
fn main() {
    backend::gpio_init()
}

// Rust vmm container (https://github.com/rust-vmm/rust-vmm-container) doesn't
// have tools to do a musl build at the moment, and adding that support is
// tricky as well to the container. Skip musl builds until the time pre-built
// libgpiod library is available for musl.
#[cfg(target_env = "musl")]
fn main() {}
