# Changelog
## Unreleased

### Added

- [#936](https://github.com/rust-vmm/vhost-device/pull/936) vsock: Enable live migrations (snapshot-restore)

### Changed

### Fixed

- [#936](https://github.com/rust-vmm/vhost-device/pull/936) vsock: Access virtqueues only if they are ready

### Deprecated

## v0.3.0

### Added
- [#698](https://github.com/rust-vmm/vhost-device/pull/698) vsock: add mdoc page
- [#706](https://github.com/rust-vmm/vhost-device/pull/706) Support proxying using vsock
- [#755](https://github.com/rust-vmm/vhost-device/pull/755) Advertise `VhostUserProtocolFeatures::MQ` protocol feature
- [#790](https://github.com/rust-vmm/vhost-device/pull/790) vsock/tests: clarify the vsock_loopback requirement

### Changed
- [#819](https://github.com/rust-vmm/vhost-device/pull/819) vsock: Use PathBuf for socket paths instead of Strings

### Fixed
- [#800](https://github.com/rust-vmm/vhost-device/pull/800) Disable EPOLLOUT if triggered while txbuf is empty
- [#838](https://github.com/rust-vmm/vhost-device/pull/838) Fix handling of data in the tx queue

## v0.2.0

### Added
- [[#406]](https://github.com/rust-vmm/vhost-device/pull/406) Add VM groups in sibling communication
- [[#526]](https://github.com/rust-vmm/vhost-device/pull/526) increase test coverage

### Changed
- [[#434]](https://github.com/rust-vmm/vhost-device/pull/434) Don't allow duplicate CIDs
- [[#450]](https://github.com/rust-vmm/vhost-device/pull/450) refactor VhostUserVsockThread worker
- [[#451]](https://github.com/rust-vmm/vhost-device/pull/451) remove unused feature to reduce deps
- [[#587]](https://github.com/rust-vmm/vhost-device/pull/587) update serde_yaml dependency
- [[#672]](https://github.com/rust-vmm/vhost-device/pull/672) simplify the examples using memfd
- [[#679]](https://github.com/rust-vmm/vhost-device/pull/679) increase max queue size to 1024

### Fixed
- [[#409]](https://github.com/rust-vmm/vhost-device/pull/409) Increase NUM_QUEUES to 3
- [[#410]](https://github.com/rust-vmm/vhost-device/pull/410) always epoll_register with cloned stream fd
- [[#499]](https://github.com/rust-vmm/vhost-device/pull/499) avoid circular references
- [[#506]](https://github.com/rust-vmm/vhost-device/pull/506) try epoll_modify before epoll_register in recv_pkt
- [[#531]](https://github.com/rust-vmm/vhost-device/pull/531) fix intermittent failures
- [[#641]](https://github.com/rust-vmm/vhost-device/pull/641) Use a patched version for the config dependency
- [[#663]](https://github.com/rust-vmm/vhost-device/pull/663) check if we get '\n' early while reading from socket
- [[#691]](https://github.com/rust-vmm/vhost-device/pull/691) Replace the config Crate with figment

## v0.1.0

First release

