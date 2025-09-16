# Changelog
## Unreleased

### Added

- [[#909]](https://github.com/rust-vmm/vhost-device/pull/909)
  `vhost-device-sound` now supports a `--socket-fd` argument.

### Changed

- [[#907]](https://github.com/rust-vmm/vhost-device/pull/907)
  `vhost_device_sound::start_backend_server` now mutably borrows a
  `vhost::vhost_user::Listener`, so the socket isn't removed and
  re-created between each connection, and there's no longer a short
  window of time where there's no socket for clients to connect to.

  As a consequence of this change:

  - `vhost_device_sound::SoundConfig::new` no longer takes a `socket` argument.
  - `vhost_device_sound::SoundConfig::get_socket_path` has been removed.
  - `vhost_device_sound::SoundConfig` no longer implements
    `From<vhost_device_sound::args::SoundArgs>` (since the `socket`
    argument should be handled separately).
  - `vhost_device_sound::start_backend_server` now additionally takes
    a `listener` argument.

### Fixed

### Deprecated

## v0.3.0

### Added

- [[#876]](https://github.com/rust-vmm/vhost-device/pull/876) Add GStreamer audio backend support
- [[#806]](https://github.com/rust-vmm/vhost-device/pull/806) Add controls field in VirtioSoundConfig
- [[#746]](https://github.com/rust-vmm/vhost-device/pull/746) Add new sampling rates 12000Hz and 24000Hz

### Changed

- [[#852]](https://github.com/rust-vmm/vhost-device/pull/852) Changed to 2021 Rust edition
- [[#792]](https://github.com/rust-vmm/vhost-device/pull/792) sound: move CLI arg types to lib submodule
- [[#823]](https://github.com/rust-vmm/vhost-device/pull/823) sound: Use PathBuf for socket paths instead of Strings
- [[#789]](https://github.com/rust-vmm/vhost-device/pull/789) sound/pipewire: add truncated exp backoff to tests and fork them
- [[#788]](https://github.com/rust-vmm/vhost-device/pull/788) sound: Put AlsaTestHarness static in a LazyLock
- [[#580]](https://github.com/rust-vmm/vhost-device/pull/580) sound: use descriptor_utils.rs to manipulate requests


### Fixed
- [[#808]](https://github.com/rust-vmm/vhost-device/pull/808) pipewire: Fix rand module imports
- [[#884]](https://github.com/rust-vmm/vhost-device/pull/884) vhost-device-sound/pipewire: fix wrong format

### Limitations

- GStreamer backend: 20-bit PCM formats (VIRTIO_SND_PCM_FMT_S20/U20) are not directly supported by GStreamer and are automatically converted to 24/32-bit formats

### Deprecated

## v0.2.0

### Added
- [[#616]](https://github.com/rust-vmm/vhost-device/pull/616) pipewire: specify audio
  channel position

### Changed
- [[#617]](https://github.com/rust-vmm/vhost-device/pull/617) Update pipewire
  dependencies to version 0.8 after the release of pipewire v0.8

### Fixed
- [[#599]](https://github.com/rust-vmm/vhost-device/pull/599) Fix symbolic links to license files
- [[#638]](https://github.com/rust-vmm/vhost-device/pull/638) Remove duplicate increment in pipewire
- [[#644]](https://github.com/rust-vmm/vhost-device/pull/644) Destroy pipewire streams not destroyed in pipewire

## v0.1.0

First release with null, pipewire and alsa host audio backends.
