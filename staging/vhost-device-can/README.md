# vhost-device-can - CAN emulation backend daemon

## Description
This program is a vhost-user backend that emulates a VirtIO CAN device.
The device's binary takes two (2) parameters:  a socket, a 'can-devices' list.
The socket is commonly used across all vhost-devices to communicate with
the vhost-user frontend device. The 'can-devices' represents a list of
CAN/FD devices appears in the host system. This list includes *can_input* and
*can_output* devices which vhost-device-can will forward messages to and from
the frontend side.

This program is tested with QEMU's `vhost-user-device-pci` device.
Examples' section below.

## Synopsis
```
**vhost-device-can** [*OPTIONS*]
````

## Options

.. program:: vhost-device-can

.. option:: -h, --help

  Print help.

.. option:: -s, --socket-path=PATH

  Location of vhost-user Unix domain sockets, this path will be suffixed with
  0,1,2..socket_count-1.

.. option:: -c, --socket-count=INT

  Number of guests (sockets) to attach to, default set to 1.

.. option:: -d, --can-devices='CAN/FD interfaces'

  CAN/FD device list at the host OS in the format:
      <can-in_X_0>:<can_out_Y_0> [<can_in_X_1>:<can_out_Y_1>] ... [<can_in_X_N-1>:<can_out_Y_N-1>]

  Note 1: Where N (the number of tuples) is equal with the number provided via *socket_count* parameter.

      Example: --can-devices "vcan0:vcan1 vcan2:vcan3"

  Note 2: In most cases, the user needs to send and receive messages to/from the same interface
          so the arguments will be `--can-devices "can0:can0"`. But there are cases, where there
          might be the need to have 2 CAN/FD available channels (connected in the same CAN bus)
          and use can0 as receiver and can1 as sender (--can-devices "can0:can1"). To cover
          scenarios like this, the `--can-device` argument consists of couple structures of CAN/FD
          devices as shown above.

## Limitations
This device is still work-in-progress (WIP) and is based on virtio-can
Linux driver and QEMU's device presented in the following RFC:
- https://lwn.net/Articles/934187/ 

Currently version of the device has been tested only with *vcan* device.

## Features
Vhost-device-can can be used with multiple QEMU's VMs with both *Classic CAN*
and *CANFD* devices.

## Examples

### Dependencies
For testing the device the required dependencies are:
- Linux:
    - Integrate *virtio-can* driver implemented by OpenSynergy:
        - https://lwn.net/Articles/934187/
    - Set `CONFIG_VIRTIO_CAN=y`
- QEMU
    - Integrate *virtio-can* device implemented by OpenSynergy:
        - https://lwn.net/Articles/934187/
    - Clone vhost-user-can QEMU device (optional):
        - A new vhost-user-can device has been implemented in the following repo:
            - https://github.com/virtualopensystems/qemu/tree/vhu-can-rfc

### Test the device

The daemon should be started first:
```shell
host# vhost-device-can --socket-path=can.sock --can-devices="can0:can1"
```

The QEMU invocation needs to create a chardev socket the device can
use to communicate as well as share the guests memory over a memfd.

There are two option for running QEMU with vhost-device-can:
1) Using `vhost-user-device-pci`:
```text
host# qemu-system                                                                    \
    -m 4096                                                                          \
    -numa node,memdev=mem                                                            \
    -object memory-backend-memfd,id=mem,size=4G,share=on                             \
    -chardev socket,id=can0,path=/tmp/can.sock                                       \
    -device vhost-user-device-pci,chardev=can0,virtio-id=36,num_vqs=3,config_size=16 \
    ...
```
2) Using `vhost-user-can-pci`:
```text
host# qemu-system                                         \
    -m 4096                                               \
    -numa node,memdev=mem                                 \
    -object memory-backend-memfd,id=mem,size=4G,share=on  \
    -chardev socket,path=/tmp/can.sock,id=can0            \
    -device vhost-user-can-pci,chardev=can0,id=can        \
    ...
```

> Note: For testing this scenario the reader needs to clone the QEMU version
>       from the following repo which implements `vhost-user-can` device:
> - https://github.com/virtualopensystems/qemu/tree/vhu-can-rfc

### Multi-Guest case

Run vhost-device-can as:
```text
./vhost-device-can --socket-path /tmp/can.sock  --socket-count 2 --can-devices "vcan0:vcan0 vcan1:vcan2"
```
This command will start the device and create two new sockets: */tmp/can.sock0* and */tmp/can.sock1*.

From the other side we run two QEMU instances (VMs) with vhost-user-can:
```text
host# qemu-system                                         \
    -m 4096                                               \
    -numa node,memdev=mem                                 \
    -object memory-backend-memfd,id=mem,size=4G,share=on  \
    -chardev socket,path=<SOCKET_PATH>,id=can0            \
    -device vhost-user-can-pci,chardev=can0,id=can        \
    ...
```
In the first instance of QEMU *SOCKET_PATH* would be: */tmp/can.sock0*,
and will use *can0* (host interface) as sender and receiver. The second
QEMU VM would have: *SOCKET_PATH* = */tmp/can.sock1*, and will use *can1*
as receiver and *can2* as sender.

## License

This project is licensed under either of

- [Apache License](http://www.apache.org/licenses/LICENSE-2.0), Version 2.0
- [BSD-3-Clause License](https://opensource.org/licenses/BSD-3-Clause)
