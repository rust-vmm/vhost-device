# vhost-device-spi - SPI emulation backend daemon

## Description
This program is a vhost-user backend that emulates a VirtIO SPI bus.
This program takes the layout of the spi bus and its devices on the host
OS and then talks to them via the `/dev/spidevX.Y` interface when a request
comes from the guest OS for a SPI device.

## Synopsis

```shell
vhost-device-spi [OPTIONS]
```

## Options
```text
 -h, --help

  Print help.

 -s, --socket-path=PATH

  Location of vhost-user Unix domain sockets, this path will be suffixed with
  0,1,2..socket_count-1.

 -c, --socket-count=INT

  Number of guests (sockets) to attach to, default set to 1.

 -l, --device=SPI-DEVICES

  Spi device full path at the host OS in the format:
      /dev/spidevX.Y

  Here,
      X: is spi controller's bus number.
      Y: is chip select index.
```

## Examples

### Dependencies
For testing the device the required dependencies are:
- Linux:
    - Integrate *virtio-spi* driver:
        - https://lwn.net/Articles/966715/
    - Set `CONFIG_SPI_VIRTIO=y`
- QEMU:
    - Integrate vhost-user-spi QEMU device:
        - https://lore.kernel.org/all/20240712034246.2553812-1-quic_haixcui@quicinc.com/

### Test the device
First start the daemon on the host machine::

````suggestion
```console
vhost-device-spi --socket-path=vspi.sock --socket-count=1 --device "/dev/spidev0.0"
```
````

The QEMU invocation needs to create a chardev socket the device spi
use to communicate as well as share the guests memory over a memfd.

````suggestion
```console
qemu-system-aarch64 -m 1G \
    -chardev socket,path=/home/root/vspi.sock0,id=vspi \
    -device vhost-user-spi-pci,chardev=vspi,id=spi \
    -object memory-backend-file,id=mem,size=1G,mem-path=/dev/shm,share=on \
    -numa node,memdev=mem \
    ...
```
````

## License

This project is licensed under either of

- [Apache License](http://www.apache.org/licenses/LICENSE-2.0), Version 2.0
- [BSD-3-Clause License](https://opensource.org/licenses/BSD-3-Clause)
