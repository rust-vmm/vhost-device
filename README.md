# vhost-device

## Design

This repository hosts various 'vhost-user' device backends in their own crates.
See their individual README.md files for specific information about those
crates.

Here is the list of device backends that we support:

- [I2C](https://github.com/rust-vmm/vhost-device/blob/main/i2c/README.md)
- [VSOCK](vsock/README.md)

## Separation of Concerns

The binaries built by this repository can be run with any VMM which
can act as a vhost-user master. Typically they have been tested with
[QEMU](https://www.qemu.org) although the rust-vmm project does
provide a [vhost-user
master](https://github.com/rust-vmm/vhost/tree/main/src/vhost_user)
crate for rust based VMMs.

While it's possible to implement all parts of the backend inside the
vhost-device workspace consideration should be given to separating the
VirtQueue handling and response logic to a crate in [vm-virtio
devices](https://github.com/rust-vmm/vm-virtio/tree/main/crates/devices).
This way a monolithic rust-vmm VMM implementation can reuse the core
logic to service the virtio requests directly in the application.

