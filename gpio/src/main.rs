// VIRTIO GPIO Emulation via vhost-user
//
// Copyright 2022 Linaro Ltd. All Rights Reserved.
//          Viresh Kumar <viresh.kumar@linaro.org>
//
// SPDX-License-Identifier: Apache-2.0

mod backend;
mod gpio;
mod vhu_gpio;

fn main() -> backend::Result<()> {
    backend::gpio_init()
}
