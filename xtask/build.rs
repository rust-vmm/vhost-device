// SPDX-License-Identifier: EUPL-1.2 OR GPL-3.0-or-later
// Copyright (c) 2024 Linaro Ltd.

fn main() {
    #[cfg(feature = "vhost-device-sound-pipewire")]
    println!("cargo::rustc-cfg=feature=\"pw-backend\"");
    #[cfg(feature = "vhost-device-sound-alsa")]
    println!("cargo::rustc-cfg=feature=\"alsa-backend\"");
    #[cfg(any(
        feature = "vhost-device-sound-pipewire",
        feature = "vhost-device-sound-alsa"
    ))]
    println!("cargo::rustc-cfg=target_env=\"gnu\"");
}
