# vhost-device-console - Console emulation backend daemon

## Description

This program is a vhost-user backend that emulates a VirtIO Console device.
The device's binary takes as parameters a socket path, a socket number which
is the number of connections, commonly used across all vhost-devices to
communicate with the vhost-user frontend devices, and the backend type
"nested" or "network" or "uds".

The "nested" backend allows input/output to the guest console through the
current terminal.

The "network" backend creates a local TCP port (specified on vhost-device-console
arguments) and allows input/output to the guest console via that socket.

The "uds" backend creates a unix domain socket (specified on vhost-device-console
arguments) and allows input/output to the guest console via that socket.

This program is tested with QEMU's `vhost-user-device-pci` device.
Examples' section below.

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
 This option is only valid when backend type is "network".

-- option:: -b, --backend=nested|network|uds

  The backend type vhost-device-console to be used. The current implementation
  supports 3 types of backends: "nested", "network", "uds".
  Note: The nested backend is selected by default and can be used only when
        socket_count equals 1.

.. option:: --uds-path=uds-file-path

  The unix domain socket to be used for each guest, this path will be suffixed with
  0,1,2..socket_count-1. e.g.: `--uds-path=/tmp/vm.sock --socket-count=2`
  leads to two connectable vhost-user sockets:
  /tmp/vm.sock0, /tmp/vm.sock1
  This option is only valid when backend type is "uds".

.. option:: -q, --max-queue-size=SIZE

  The maximum size of virtqueues. It is optional, and the default value is
  128. The size must be greater than 0 and a power of 2.

## Limitations

This device is still work-in-progress (WIP). The current version has been tested
with VIRTIO_CONSOLE_F_MULTIPORT, but only for one console (`max_nr_ports = 1`).
Also it does not yet support the VIRTIO_CONSOLE_F_EMERG_WRITE and
VIRTIO_CONSOLE_F_SIZE features.

## Features

The current device gives access to multiple QEMU guest by providing a login prompt
either by connecting to a localhost server port (network backend) or a unix socket
file (uds backend) or by creating an nested command prompt in the current terminal
(nested backend). This prompt appears as soon as the guest is fully booted and
gives the ability to user run command as a in regular terminal.

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
host# vhost-device-console --socket-path=/tmp/console.sock --socket-count=1 \
                           --tcp-port=12345 --backend=network # for network backend
```
or
```shell
host# vhost-device-console --socket-path=/tmp/console.sock --socket-count=1 \
                           --uds-path=/tmp/vm.sock --backend=uds # for uds backend
```
>Note: In case the backend is "nested" there is no need to provide
       "--socket-count", "--tcp-port" and "--uds-path" parameters.

The QEMU invocation needs to create a chardev socket the device can
use to communicate as well as share the guests memory over a memfd.

There are two option for running QEMU with vhost-device-console:

1) Using `vhost-user-console-pci`:
```text
host# qemu-system                                               \
    <normal QEMU options>                                       \
    -machine <machine options>,memory-backend=mem0              \
    -object memory-backend-memfd,id=mem0,size=<Guest RAM size>  \ # size == -m size
    -chardev socket,path=/tmp/console.sock0,id=con0             \
    -device vhost-user-console-pci,chardev=con0,id=console      \
    ...
```

> Note: For testing this scenario the reader needs to clone the QEMU version from the following repo
>       which implements `vhost-user-console` device.
> - https://github.com/virtualopensystems/qemu/tree/vhu-console-rfc

2) Using `vhost-user-device-pci`:
```text
host# qemu-system                                                                   \
    <normal QEMU options>                                                           \
    -machine <machine options>,memory-backend=mem0                                  \
    -object memory-backend-memfd,id=mem0,size=<Guest RAM size>                      \ # size == -m size
    -chardev socket,id=con0,path=/tmp/console.sock0                                 \
    -device vhost-user-device-pci,chardev=con0,virtio-id=3,num_vqs=4,config_size=12 \
    ...
```

#### Test the device with UML
Start the daemon as above section, then run the following cmdline for
Kernel Mode Linux [`virtio console`](https://github.com/torvalds/linux/blob/848e076317446f9c663771ddec142d7c2eb4cb43/include/uapi/linux/virtio_ids.h#L34):
```text
host# linux root=/dev/ubda1 rw ubd0=$YOUR-PATH/kata-ubuntu-latest.image   \
    <normal UML options>                                             \
    virtio_uml.device=/tmp/console.sock0:3 console=tty0 console=hvc0 \
    init=/bin/systemd                                                \
    systemd.unit=kata-containers.target agent.debug_console
```
Test with [kata-ubuntu-latest.image](https://github.com/kata-containers/kata-containers/releases/),
you can also use systemd to setup pty manually without kata-agent help.

Eventually, the user can connect to the console by running:
```test
host# stty -icanon -echo && nc localhost 12345 && stty echo # for network backend
```
or
```test
host# stty -icanon -echo && nc -U /tmp/vm.sock0 && stty echo # for uds backend
```

>Note: `stty -icanon -echo` is used to force the tty layer to disable buffering and send / receive each character individually. After closing the connection please run `stty echo` so character are printed back on the local terminal console.

>Note: In case the backend is "nested" a nested terminal will be shown into
       vhost-device-console terminal space.

## License

This project is licensed under either of

- [Apache License](http://www.apache.org/licenses/LICENSE-2.0), Version 2.0
- [BSD-3-Clause License](https://opensource.org/licenses/BSD-3-Clause)
