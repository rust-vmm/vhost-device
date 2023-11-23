# vhost-device-input

## Synopsis
vhost-device-input --socket-path <SOCKET_PATH> --event-list <EVENT_LIST>

## Description

This program is a vhost-user backend that emulates a VirtIO input event.
It polls on a host's input event device (/dev/input/eventX) and passes the
input event data to guests.

This program is tested with QEMU's `vhost-user-input-pci`.  The
implemenation is based on the vhost-user protocol and as such should be
interoperable with other virtual machine managers.  Please see below for
working examples.

## Options

```text
    -h, --help
        Print help.

    -s, --socket-path <SOCKET_PATH>
        Location of vhost-user Unix domain sockets, this path will be suffixed with
        0,1,2..event_count-1.

    -e, --event-list <EVENT_LIST>
        Input event device list in the format: event_device1,event_device2,...
        Example: --event-list /dev/input/event14,/dev/input/event15
```

## Examples

The daemon should be started first:

```shell
host# vhost-device-input --socket-path /some/path/input.sock    \
      --event-list /dev/input/event14,/dev/input/event15
```

Note that from the above command the socket path "/some/path/input.sock0" and
"/some/path/input.sock1" will be created for input events "event14" and
"event15" respectively.  This in turn needs to be communicated as chardev
sockets to QEMU in order for the backend daemon and access the Virtio queues
with the guest over the shared memory.

```shell
host# qemu-system -M virt                                                   \
      -object memory-backend-file,id=mem,size=4G,mem-path=/dev/shm,share=on \
      -chardev socket,path=/some/path/input.sock0,id=kbd0                   \
      -device vhost-user-input-pci,chardev=kdb0                             \
      -chardev socket,path=/some/path/input.sock1,id=mouse0                 \
      -device vhost-user-input-pci,chardev=mouse0                           \
      -numa node,memdev=mem                                                 \
      ...
```

## License

This project is licensed under either of

- [Apache License](http://www.apache.org/licenses/LICENSE-2.0), Version 2.0
- [BSD-3-Clause License](https://opensource.org/licenses/BSD-3-Clause)
