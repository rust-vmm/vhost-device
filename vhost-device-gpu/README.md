# vhost-device-gpu - GPU emulation backend daemon

## Synopsis

```shell
vhost-device-gpu --socket-path <SOCKET> --gpu-mode <GPU_MODE>
```

## Description

A virtio-gpu device using the vhost-user protocol.

## Options

```text
  -s, --socket-path <SOCKET>
          vhost-user Unix domain socket

  -g, --gpu-mode <GPU_MODE>
          The mode specifies which backend implementation to use
          
          [possible values: virglrenderer, gfxstream]

  -c, --capset <CAPSET>
          Comma separated list of enabled capsets

          Possible values:
          - virgl:            [virglrenderer] OpenGL implementation, superseded by Virgl2
          - virgl2:           [virglrenderer] OpenGL implementation
          - gfxstream-vulkan: [gfxstream] Vulkan implementation (partial support only)
             NOTE: Can only be used for 2D display output for now, there is no hardware acceleration yet
          - gfxstream-gles:   [gfxstream] OpenGL ES implementation (partial support only)
             NOTE: Can only be used for 2D display output for now, there is no hardware acceleration yet

      --use-egl <USE_EGL>
          Enable backend to use EGL
          
          [default: true]
          [possible values: true, false]

      --use-glx <USE_GLX>
          Enable backend to use GLX
          
          [default: false]
          [possible values: true, false]

      --use-gles <USE_GLES>
          Enable backend to use GLES
          
          [default: true]
          [possible values: true, false]

      --use-surfaceless <USE_SURFACELESS>
          Enable surfaceless backend option
          
          [default: true]
          [possible values: true, false]

  -h, --help
          Print help (see a summary with '-h')

  -V, --version
          Print version
```

_NOTE_: Option `-g, --gpu-mode` can only accept the `gfxstream` value if the
crate has been built with the `gfxstream` feature, which is the default.

## Limitations

This device links native libraries (because of the usage of Rutabaga) compiled
with GNU libc, so the CI is setup to not build this device for musl targets. 
It might be possible to build those libraries using musl and then build the gpu
device, but this is not tested.

We are currently only supporting sharing the display output to QEMU through a
socket using the transfer_read operation triggered by
`VIRTIO_GPU_CMD_TRANSFER_FROM_HOST_3D` to transfer data from and to virtio-gpu 3D
resources. It'll be nice to have support for directly sharing display output
resource using dmabuf.

This device does not yet support the `VIRTIO_GPU_CMD_RESOURCE_CREATE_BLOB`,
`VIRTIO_GPU_CMD_SET_SCANOUT_BLOB` and `VIRTIO_GPU_CMD_RESOURCE_ASSIGN_UUID` features. 
This requires https://github.com/rust-vmm/vhost/pull/251, which in turn requires QEMU API stabilization.
Because blob resources are not yet supported, some capsets are limited:
- Venus (Vulkan implementation in virglrenderer project) support is not available at all.
- gfxstream-vulkan and gfxstream-gles support are exposed, but can practically only be used for display output, there is no hardware acceleration yet.
## Features

The device leverages the [rutabaga_gfx](https://crates.io/crates/rutabaga_gfx)
crate to provide rendering with virglrenderer and gfxstream.

gfxstream support is compiled by default, it can be disabled by not building with the `gfxstream` feature flag, for example:

```session
$ cargo build --no-default-features
```

With Virglrenderer, Rutabaga translates OpenGL API and Vulkan calls to an
intermediate representation and allows for OpenGL acceleration on the host.

With the gfxstream rendering mode, GLES and Vulkan calls are forwarded to the
host with minimal modification.

## Examples

First start the daemon on the host machine using either of the 2 gpu modes:

1) `virglrenderer`
2) `gfxstream` (if the crate has been compiled with the feature `gfxstream`)

```shell
host# vhost-device-gpu --socket-path /tmp/gpu.socket --gpu-mode virglrenderer
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
