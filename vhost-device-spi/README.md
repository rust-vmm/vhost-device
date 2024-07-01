# vhost-device-spi - SPI emulation backend daemon

## Description
This program is a vhost-user backend that emulates a VirtIO SPI bus.
This program takes the layout of the spi bus and its devices on the host
OS and then talks to them via the /dev/spidevX.Y interface when a request
comes from the guest OS for a SPI device.

## Synopsis

**vhost-device-spi** [*OPTIONS*]

## Options

.. program:: vhost-device-spi

.. option:: -h, --help

  Print help.

.. option:: -s, --socket-path=PATH

  Location of vhost-user Unix domain sockets, this path will be suffixed with
  0,1,2..socket_count-1.

.. option:: -c, --socket-count=INT

  Number of guests (sockets) to attach to, default set to 1.

.. option:: -l, --device=SPI-DEVICES

  Spi device full path at the host OS in the format:
      /dev/spidevX.Y

  Here,
      X: is spi controller's bus number.
      Y: is chip select index.

## Examples

The daemon should be started first:

::

  host# vhost-device-spi --socket-path=vspi.sock --socket-count=1 --device "/dev/spidev0.0"

## License

This project is licensed under either of

- [Apache License](http://www.apache.org/licenses/LICENSE-2.0), Version 2.0
- [BSD-3-Clause License](https://opensource.org/licenses/BSD-3-Clause)
