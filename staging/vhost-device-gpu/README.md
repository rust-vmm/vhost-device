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

## Examples

First start the daemon on the host machine:

```shell
host# vhost-device-gpu --socket-path /tmp/gpu.socket
```

With QEMU, there are two device frontends you can use with this device.
You can either use `vhost-user-gpu-pci` or `vhost-user-vga`, which also
implements VGA, that allows you to see boot messages before the guest
initializes the GPU. You can also use different display outputs (for example
`gtk` or `dbus`).
By default, QEMU also adds another VGA output, use `-vga none` to make 
sure it is disabled.

1) Using `vhost-user-gpu-pci` Start QEMU with the following flags:

```text
-chardev socket,id=vgpu,path=/tmp/gpu.socket \
-device vhost-user-gpu-pci,chardev=vgpu,id=vgpu \
-object memory-backend-memfd,share=on,id=mem0,size=4G, \
-machine q35,memory-backend=mem0,accel=kvm \
-display gtk,gl=on,show-cursor=on \
-vga none
```

2) Using `vhost-user-vga` Start QEMU with the following flags:

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
