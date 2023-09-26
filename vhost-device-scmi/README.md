# vhost-device-scmi

This program is a vhost-user backend for a VirtIO SCMI device.
It provides SCMI access to various entities on the host; not
necessarily only those providing an SCMI interface themselves.

It is tested with QEMU's `-device vhost-user-scmi-pci` but should work
with any virtual machine monitor (VMM) that supports vhost-user. See
the Examples section below.

## Synopsis

**vhost-device-scmi** [*OPTIONS*]

## Options

.. program:: vhost-device-scmi

.. option:: -h, --help

  Print help.

.. option:: -s, --socket-path=PATH

  Location of the vhost-user Unix domain sockets.

.. option:: -d, --device=SPEC

  SCMI device specification in the format `ID,PROPERTY=VALUE,...`.  
  For example: `-d iio,path=/sys/bus/iio/devices/iio:device0,channel=in_accel`.  
  Can be used multiple times for multiple exposed devices.
  If no device is specified then no device will be provided to the
  guest OS but VirtIO SCMI will be still available there.
  Use `--help-devices` to list help on all the available devices.

You can set `RUST_LOG` environment variable to `debug` to get maximum
messages on the standard error output.

## Examples

The daemon should be started first:

::

  host# vhost-device-scmi --socket-path=scmi.sock --device fake,name=foo

The QEMU invocation needs to create a chardev socket the device can
use to communicate as well as share the guests memory over a memfd:

::

  host# qemu-system \
      -chardev socket,path=scmi.sock,id=scmi \
      -device vhost-user-scmi-pci,chardev=vscmi,id=scmi \
      -machine YOUR-MACHINE-OPTIONS,memory-backend=mem \
      -m 4096 \
      -object memory-backend-file,id=mem,size=4G,mem-path=/dev/shm,share=on \
      ...

## Supported SCMI protocols

The currently supported SCMI protocols are:

- base
- sensor management

Basically only the mandatory and necessary parts of the protocols are
implemented.

See source code (`vhost-device-scmi` crate) documentation for details and how to
add more protocols, host device bindings or other functionality.

## Testing

SCMI is supported only on Arm in Linux.  This restriction doesn't
apply to the host, which can be any architecture as long as the guest
is Arm.

The easiest way to test it on the guest side is using the Linux SCMI
Industrial I/O driver there.  If an 3-axes accelerometer or gyroscope
VirtIO SCMI device is present and the guest kernel is compiled with
`CONFIG_IIO_SCMI` enabled then the device should be available in
`/sys/bus/iio/devices/`.  The vhost-device-scmi fake device is
suitable for this.

Of course, other means of accessing SCMI devices can be used too.  The
following Linux kernel command line can be useful to obtain SCMI trace
information, in addition to SCMI related messages in dmesg:
`trace_event=scmi:* ftrace=function ftrace_filter=scmi*`.

### Kernel support for testing

`kernel` subdirectory contains
[instructions](kernel/iio-dummy/README.md) how to create emulated
industrial I/O devices for testing.

## License

This project is licensed under either of

- [Apache License](http://www.apache.org/licenses/LICENSE-2.0), Version 2.0
- [BSD-3-Clause License](https://opensource.org/licenses/BSD-3-Clause)

unless specified in particular files otherwise.
