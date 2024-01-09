# vhost-device-console - Console emulation backend daemon

## Description

This program is a vhost-user backend that emulates a VirtIO Console device.
The device's binary takes as parameter a socket, a socket number which is the
number of connections, commonly used across all vhost-devices to communicate
with the vhost-user frontend devices, and the backend type "nested" or
"network".

By using the "nested" backend, vhost-device-console, as soon as, the guest
is booted, will print the login prompt into the same terminal and gives
the ability to insert characters or certain keys as in a regular
terminal.

By using "network" backend, vhost-device-console, as soon as the guests
is booted, creates a local server in the given localhost port, and gives
the chance to connect on them and interact with the guests.

This program is tested with QEMU's `vhost-user-device-pci` device.
Examples' section below.

This program is a vhost-user backend that emulates a VirtIO Console device.

## Synopsis
```text
vhost-device-console --socket-path=<SOCKET_PATH>
```

## Options

.. program:: vhost-device-console

.. option:: -h, --help

  Print help.

.. option:: -s, --socket-path=PATH

  Location of vhost-user Unix domain sockets, this path will be suffixed with
  0,1,2..socket_count-1.

.. option:: -p, --tcp-port=PORT_NUMBER

 The localhost's port to be used for each guest, this part will be increased with
 0,1,2..socket_count-1.

-- option:: -b, --backend=network|nested

  The backend type vhost-device-console will use.
  Note: The nested backend can be used only when socket_count equals 1.

## Limitations

This device is still work-in-progress (WIP). The current version has been tested
with VIRTIO_CONSOLE_F_MULTIPORT, but only for one console.

## Features

The current device gives access to multiple QEMU guest by providing a login prompt
either by connecting to a localhost server port (network backend) or by creating an
nested command prompt in the current terminal (nested backend). This prompt appears
as soon as the guest is fully booted and gives the ability to user run command as a
in regular terminal.

## Examples

### Dependencies
For testing the device the required dependencies are:
- Linux:
    - Set `CONFIG_VIRTIO_CONSOLE=y`
- QEMU (optional):
    - A new vhost-user-console device has been implemented in the following repo:
      - https://github.com/virtualopensystems/qemu/tree/vhu-console-rfc


### Test the device

The daemon should be started first:
```shell
host# vhost-device-console --socket-path=console.sock --socket-count=1 \
                           --tcp-port=12345 --backend=network
```
>Note: In case the backend is "nested" there is no need to provide
       "--socket-count" and "--tcp-port" parameters.

The QEMU invocation needs to create a chardev socket the device can
use to communicate as well as share the guests memory over a memfd.

There are two option for running QEMU with vhost-device-console:

1) Using `vhost-user-console-pci`:
```text
host# qemu-system                                          \
    -m 4096                                                \
    -numa node,memdev=mem                                  \
    -object memory-backend-memfd,id=mem,size=4G,share=on   \
    -chardev socket,path=/tmp/console.sock,id=con          \
    -device vhost-user-console-pci,chardev=con0,id=console \
    ...
```

> Note: For testing this scenario the reader needs to clone the QEMU version from the following repo
>       which implements `vhost-user-console` device.
> - https://github.com/virtualopensystems/qemu/tree/vhu-console-rfc

2) Using `vhost-user-device-pci`:
```text
host# qemu-system                                                                   \
    -m 4096                                                                         \
    -numa node,memdev=mem                                                           \
    -object memory-backend-memfd,id=mem,size=4G,share=on                            \
    -chardev socket,id=con0,path=/tmp/console.sock                                  \
    -device vhost-user-device-pci,chardev=con0,virtio-id=3,num_vqs=4,config_size=12 \
    ...
```

Eventually, the user can connect to the console by running:
```test
host# nc 127.0.0.1 12345
```

>Note: In case the backend is "nested" a nested terminal will be shown into
       vhost-device-console terminal space.

## License

This project is licensed under either of

- [Apache License](http://www.apache.org/licenses/LICENSE-2.0), Version 2.0
- [BSD-3-Clause License](https://opensource.org/licenses/BSD-3-Clause)
