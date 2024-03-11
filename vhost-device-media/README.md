# vhost-device-media

A virtio-media device using the vhost-user protocol.

This crate provides a vhost-user backend for virtio-media devices. It is an implementation of the VIRTIO Media Device specification, which can be found on [virtio-spec v1.4](https://docs.oasis-open.org/virtio/virtio/v1.4/virtio-v1.4.html). The purpose of this device is to provide a standardized way for virtual machines to access media devices on the host.

The low-level implementation of the virtio-media protocol is provided by the device crate from the [virtio-media](https://github.com/chromeos/virtio-media) repository.

## Synopsis

```console
vhost-device-media --socket-path <SOCKET> --v4l2-device <V4L2_DEVICE> --backend <BACKEND>
```

## Description


## Options

```text
     --socket-path <SOCKET>
            vhost-user Unix domain socket path

     --v4l2-device <V4L2_DEVICE>
            Path to the V4L2 media device file. Defaults to /dev/video0.

     --backend <BACKEND>
            Media backend to be used. [possible values: simple-capture, v4l2-proxy]

     -h, --help
            Print help

     -V, --version
            Print version
```

## Examples

Launch the backend on the host machine:

```shell
host# vhost-device-media --socket-path /tmp/media.sock --v4l2-device /dev/video0 --backend v4l2-proxy
```

With QEMU, you can add a `virtio` device that uses the backend's socket with the following flags:

```text
-chardev socket,id=vmedia,path=/tmp/media.sock \
-device vhost-user-media-pci,chardev=vmedia,id=media
```

## Features

The following backends are available:

- **simple-capture**: A simple video capture device generating a pattern, purely software-based and thus not requiring any kind of hardware. Can be used for testing purposes.
- **v4l2-proxy**: A proxy device for host V4L2 devices, i.e. a device allowing to expose a host V4L2 device to the guest almost as-is.

## Limitations

This crate is currently under active development.

- **dmabuf memory sharing**: DMA buffer (dmabuf) support for zero-copy memory sharing between guest and host and through multiple virtio devices using VirtIO shared objects is not yet implemented. Currently, all memory operations use regular memory mappings.
- **Kernel driver availability**: The virtio-media kernel driver is still being upstreamed to the Linux kernel and may not be available in all kernel versions. Check [virtio-media](https://github.com/chromeos/virtio-media) for instructions on how to build the OOT module.

## License

This project is licensed under either of

- [Apache License](http://www.apache.org/licenses/LICENSE-2.0), Version 2.0
- [BSD-3-Clause License](https://opensource.org/licenses/BSD-3-Clause)
