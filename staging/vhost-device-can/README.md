# vhost-device-can - CAN emulation backend daemon

## Description
This program is a vhost-user backend that emulates a VirtIO CAN device.
The device's binary takes three (3) parameters:  a socket, a 'can-out' and a
'can-in' device name. The socket is commonly used across all vhost-devices to
communicate with the vhost-user frontend device.

The 'can-out' represents
the actual CAN/FD device appears in the host system which vhost-device-can will
forward the messages from the frontend side. Finally, the 'can-in' is again a
CAN/FD device connected on the host systems and vhost-device-can reads CAN/FD
frames and sends them to the frontend. The 'can-in' and 'can-out' can be find
by "ip link show" command. Also, the vhost-device-can may have the same CAN/FD
device name for both 'can-in' and 'can-out', if the user desires to setup a
loopback configuration.


This program is tested with Virtio-loopback's `-device vhost-user-can`.
Examples section below.

## Synopsis

**vhost-device-can** [*OPTIONS*]

## Options

.. program:: vhost-device-can

.. option:: -h, --help

  Print help.

.. option:: -s, --socket-path=PATH

.. option:: -i, --can-int='CAN/FD interface name'

  The name of the input CAN interface to retrieve CAN frames by

.. option:: -o, --can-out='CAN/FD interface name'

  The name of the output CAN interface to send the CAN frames

## Examples

The daemon should be started first:

::

  host# vhost-device-can --socket-path=can.sock --can-in="can0" --can-out="can1"

The virtio-loopback invocation needs to insert the [virtio-loopback-transport](https://git.virtualopensystems.com/virtio-loopback/loopback_driver/-/tree/epsilon-release) driver
and then start the [virtio-loopback-adapter](https://git.virtualopensystems.com/virtio-loopback/adapter_app/-/tree/epsilon-release) which is the intermediate between
vhost-device and virtio-loopback-transport driver.

For more information please check the virtio-loopback [guide](https://git.virtualopensystems.com/virtio-loopback/docs/-/tree/epsilon-release) and the [design document](https://git.virtualopensystems.com/virtio-loopback/docs/-/blob/epsilon-release/design_docs/EG-VIRT_VOSYS_virtio_loopback_design_v1.4_2023_04_03.pdf).

::

  host# sudo insmod loopback_driver.ko
  host# sudo ./adapter -s /path/to/can.sock0 -d vhucan

## License

This project is licensed under either of

- [Apache License](http://www.apache.org/licenses/LICENSE-2.0), Version 2.0
- [BSD-3-Clause License](https://opensource.org/licenses/BSD-3-Clause)
