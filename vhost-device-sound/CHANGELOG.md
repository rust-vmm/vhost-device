# Changelog
## Unreleased

### Added

- [[#806]](https://github.com/rust-vmm/vhost-device/pull/806) Add controls field in VirtioSoundConfig
- [[#746]](https://github.com/rust-vmm/vhost-device/pull/746) Add new sampling rates 12000Hz and 24000Hz

### Changed

### Fixed

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
