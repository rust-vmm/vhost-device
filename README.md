# vhost-device

## Design

This repository hosts various 'vhost-user' device backends in their own crates.
See their individual README.md files for specific information about those
crates.

Here is the list of device backends that we support:

- [GPIO](https://github.com/rust-vmm/vhost-device/blob/main/vhost-device-gpio/README.md)
- [I2C](https://github.com/rust-vmm/vhost-device/blob/main/vhost-device-i2c/README.md)
- [RNG](https://github.com/rust-vmm/vhost-device/blob/main/vhost-device-rng/README.md)
- [SCMI](https://github.com/rust-vmm/vhost-device/blob/main/vhost-device-scmi/README.md)
- [SCSI](https://github.com/rust-vmm/vhost-device/blob/main/vhost-device-scsi/README.md)
- [VSOCK](https://github.com/rust-vmm/vhost-device/blob/main/vhost-device-vsock/README.md)

For `vhost-user` device backends that have no final specification merged into
the [VIRTIO specification](https://github.com/oasis-tcs/virtio-spec), or have partial functionality, we have a [staging
workspace](./staging/).
More information may be found in its [README file](./staging/README.md).

Here is the list of device backends in **staging**:

- Currently none.

<!--
Template:

- [`_DEVICE_NAME_`](https://github.com/rust-vmm/vhost-device/blob/main/staging/vhost-device-_DEVICE_NAME_/README.md)

-->

## Testing and Code Coverage

Like the wider rust-vmm project we expect new features to come with
comprehensive code coverage. However as a multi-binary repository
there are cases where avoiding a drop in coverage can be hard and an
exception to the approach is allowable. These are:

* adding a new binary target (aim at least 60% overall coverage)
* expanding the main function (a small drop is acceptable)

However any new feature added to an existing binary should not cause a
drop in coverage. The general aim should be to always improve
coverage.

## Separation of Concerns

The binaries built by this repository can be run with any VMM which
can act as a vhost-user frontend. Typically they have been tested with
[QEMU](https://www.qemu.org) although the rust-vmm project does
provide a [vhost-user
frontend](https://github.com/rust-vmm/vhost/tree/main/src/vhost_user)
crate for rust based VMMs.

While it's possible to implement all parts of the backend inside the
vhost-device workspace consideration should be given to separating the
VirtQueue handling and response logic to a crate in [vm-virtio
devices](https://github.com/rust-vmm/vm-virtio/tree/main/crates/devices).
This way a monolithic rust-vmm VMM implementation can reuse the core
logic to service the virtio requests directly in the application.

## Build dependency

The GPIO crate needs a local installation of libgpiod library to be available.
If your distro ships libgpiod >= v2.0, then you should be fine.

Otherwise, you will need to build libgpiod yourself:

    git clone --depth 1 --branch v2.0.x https://git.kernel.org/pub/scm/libs/libgpiod/libgpiod.git/
    cd libgpiod
    ./autogen.sh --prefix="$PWD/install/"
    make install

In order to inform tools about the build location, you can now set:

    export PKG_CONFIG_PATH="<PATH-TO-LIBGPIOD>/install/lib/pkgconfig/"

To prevent setting this in every terminal session, you can also configure
cargo to
[set it automatically](https://doc.rust-lang.org/cargo/reference/config.html#env).

## Xen support

Supporting Xen requires special handling while mapping the guest memory. The
`vm-memory` crate implements xen memory mapping support via a separate feature
`xen`, and this crate uses the same feature name to enable Xen support.

It was decided by the `rust-vmm` maintainers to keep the interface simple and
build the crate for either standard Unix memory mapping or Xen, and not both.
