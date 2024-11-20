# vhost-device-gpu - GPU emulation backend daemon

## Synopsis
```shell
vhost-device-gpu --socket-path <SOCKET>
```

## Description
A virtio-gpu device using the vhost-user protocol.

## Options

```text
       -s, --socket-path <SOCKET>
              vhost-user Unix domain socket path

       -h, --help
              Print help

       -V, --version
              Print version
```

## Limitations

We are currently only supporting sharing the display output to QEMU through a
socket using the transfer_read operation triggered by
VIRTIO_GPU_CMD_TRANSFER_FROM_HOST_3D to transfer data from and to virtio-gpu 3d
resources. It'll be nice to have support for directly sharing display output
resource using dmabuf.

This device does not yet support the VIRTIO_GPU_CMD_RESOURCE_CREATE_BLOB,
VIRTIO_GPU_CMD_SET_SCANOUT_BLOB and VIRTIO_GPU_CMD_RESOURCE_ASSIGN_UUID features.

Currently this crate requires some necessary bits in order to move the crate out of staging:

- Addition of CLI arguments to specify the exact number of capsets and use
  a default capset configuration when no capset is specified rather than using
  hard-coded capset value.

## Features

The device leverages the [rutabaga_gfx](https://crates.io/crates/rutabaga_gfx) crate
to provide virglrenderer and gfxstream rendering. With Virglrenderer, Rutabaga
translates OpenGL API and Vulkan calls to an intermediate representation and allows
for OpenGL acceleration on the host. With the gfxstream rendering mode, GLES and
Vulkan calls are forwarded to the host with minimal modification.

## Examples

First start the daemon on the host machine using either of the 2 gpu modes:

1) virgl-renderer
2) gfxstream

```shell
host# vhost-device-gpu --socket-path /tmp/gpu.socket --gpu-mode virgl-renderer
```

With QEMU, there are two device front-ends you can use with this device.
You can either use `vhost-user-gpu-pci` or `vhost-user-vga`, which also
implements VGA, that allows you to see boot messages before the guest
initializes the GPU. You can also use different display outputs (for example
`gtk` or `dbus`).
By default, QEMU also adds another VGA output, use `-vga none` to make 
sure it is disabled.

1) Using `vhost-user-gpu-pci`

Start QEMU with the following flags:

```text
-chardev socket,id=vgpu,path=/tmp/gpu.socket \
-device vhost-user-gpu-pci,chardev=vgpu,id=vgpu \
-object memory-backend-memfd,share=on,id=mem0,size=4G, \
-machine q35,memory-backend=mem0,accel=kvm \
-display gtk,gl=on,show-cursor=on \
-vga none
```

2) Using `vhost-user-vga`

Start QEMU with the following flags:

```text
-chardev socket,id=vgpu,path=/tmp/gpu.socket \
-device vhost-user-vga,chardev=vgpu,id=vgpu \
-object memory-backend-memfd,share=on,id=mem0,size=4G, \
-machine q35,memory-backend=mem0,accel=kvm \
-display gtk,gl=on,show-cursor=on \
-vga none
```

## License

This project is licensed under either of

- [Apache License](http://www.apache.org/licenses/LICENSE-2.0), Version 2.0
- [BSD-3-Clause License](https://opensource.org/licenses/BSD-3-Clause)
