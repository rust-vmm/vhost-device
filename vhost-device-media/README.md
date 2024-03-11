# vhost-device-media

A virtio-media device using the vhost-user protocol.

This crate provides a vhost-user backend for virtio-media devices. It is an implementation of the VIRTIO Media Device specification, which can be found on [virtio-spec v1.4](https://docs.oasis-open.org/virtio/virtio/v1.4/virtio-v1.4.html). The purpose of this device is to provide a standardized way for virtual machines to access media devices on the host.

The low-level implementation of the virtio-media protocol is provided by the device crate from the [virtio-media](https://github.com/chromeos/virtio-media) repository.

## Synopsis

```console
vhost-device-media --socket-path <SOCKET> --v4l2-device <V4L2_DEVICE> --backend <BACKEND>
```

## Description

`vhost-device-media` implements a vhost-user backend for virtio-media, exposing
one or more V4L2-compatible media devices to a virtual machine guest. The host
side of the device is handled by this daemon, which translates virtio-media
protocol requests into operations on the chosen backend (e.g. a host V4L2
device, an FFmpeg-based decoder, or a software capture generator). The guest
side requires a virtio-media-capable kernel driver; see the
[virtio-media](https://github.com/chromeos/virtio-media) repository for the
out-of-tree module.

## Options

```text
     --socket-path <SOCKET>
            vhost-user Unix domain socket path

     --v4l2-device <V4L2_DEVICE>
            Path to the V4L2 media device file (used by v4l2-proxy). Defaults to /dev/video0.

     --backend <BACKEND>
            Media backend to use.
            [possible values: null, simple-capture, v4l2-proxy, ffmpeg-decoder]
            Not all values are available in every build; see the Cargo features below.
            Defaults to simple-capture when that feature is enabled, null otherwise.

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

> Note: The `vhost-user-media-pci` QEMU device is not yet upstream. A patch
> series adding support is currently under review on the
> [QEMU mailing list](https://lore.kernel.org/all/20260630112310.552606-1-aesteve@redhat.com/).
> Search for "vhost-user-media" on [lore.kernel.org](https://lore.kernel.org/qemu-devel/)
> for the latest revision.

## Features

The crate exposes the following Cargo feature flags. Build with
`--features <name>` (or multiple comma-separated names) to enable them.

| Feature | Backend value | Description |
|---------|---------------|-------------|
| `simple-capture` | `simple-capture` | A purely software capture device that generates a test pattern. No hardware required. |
| `v4l2-proxy` | `v4l2-proxy` | Proxy a host V4L2 device (`/dev/videoN`) into the guest as-is. |
| `ffmpeg` | `ffmpeg-decoder` | Software video decoder powered by FFmpeg. |
| *(none)* | `null` | A no-op backend that presents itself as a V4L2 device. |

**System dependencies** for the `v4l2-proxy` backend: a V4L2-capable host
kernel and access to `/dev/videoN`.

## Limitations

This crate is currently under active development.

- **dmabuf memory sharing**: DMA buffer (dmabuf) support for zero-copy memory sharing between guest and host and through multiple virtio devices using VirtIO shared objects is not yet implemented. Currently, all memory operations use regular memory mappings.
- **Kernel driver availability**: The virtio-media kernel driver is still being upstreamed to the Linux kernel and may not be available in all kernel versions. Check [virtio-media](https://github.com/chromeos/virtio-media) for instructions on how to build the OOT module.

## License

This project is licensed under either of

- [Apache License](http://www.apache.org/licenses/LICENSE-2.0), Version 2.0
- [BSD-3-Clause License](https://opensource.org/licenses/BSD-3-Clause)
