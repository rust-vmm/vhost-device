# `xtask` - Run tasks with `cargo`

This binary crate provides support for running useful tasks with `cargo xtask <..>`.

## `mangen`

The `mangen` task which is enabled by the `mangen` cargo feature, builds ROFF manual pages for binary crates in this repository. It uses the [`clap_mangen`](https://crates.io/crates/clap_mangen) crate to generate ROFF from the crate's argument types which implement the `clap::CommandFactory` trait, through the `clap::Parser` derive macro.

Furthmore, if the `README.md` of a crate contains an `Examples` heading, it includes it in the manual page.

```session
$ cargo xtask mangen
    Finished `dev` profile [unoptimized + debuginfo] target(s) in 0.04s
     Running `target/debug/xtask mangen`
Generated the following manual pages:
/path/to/rust-vmm/vhost-device/target/dist/man/vhost-device-sound.1
/path/to/rust-vmm/vhost-device/target/dist/man/vhost-device-scmi.1
```

The following crates have manual pages built by default:

- [`vhost-device-sound`](../vhost-device-sound), enabled by the default feature `vhost-device-sound`.
  - It can further be fine-tuned with the features `vhost-device-sound-pipewire` and `vhost-device-sound-alsa`.
- [`vhost-device-scmi`](../vhost-device-scmi), enabled by the default feature `vhost-device-scmi`.
