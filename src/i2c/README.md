# vhost-device-i2c - I2C emulation backend daemon

## Description
This program is a vhost-user backend that emulates a VirtIO I2C bus.
This program takes the layout of the i2c bus and its devices on the host
OS and then talks to them via the /dev/i2c-X interface when a request
comes from the guest OS for an I2C or SMBUS device.

This program is tested with QEMU's `-device vhost-user-i2c-pci` but should
work with any virtual machine monitor (VMM) that supports vhost-user. See the
Examples section below.

## Synopsis

**vhost-device-i2c** [*OPTIONS*]

## Options

.. program:: vhost-device-i2c

.. option:: -h, --help

  Print help.

.. option:: -s, --socket-path=PATH

  Location of vhost-user Unix domain sockets, this path will be suffixed with
  0,1,2..socket_count-1.

.. option:: -c, --socket-count=INT

  Number of guests (sockets) to attach to, default set to 1.

.. option:: -l, --device-list=I2C-DEVICES

  I2c device list at the host OS in the format:
      <bus>:<client_addr>[:<client_addr>],[<bus>:<client_addr>[:<client_addr>]]

      Example: --device-list "2:32:21,3:10:23"

  Here,
      bus (decimal): adatper bus number. e.g. 2 for /dev/i2c-2, 3 for /dev/i2c-3.
      client_addr (decimal): address for client device, 32 == 0x20.

## Examples

The daemon should be started first:

::

  host# vhost-device-i2c --socket-path=vi2c.sock --socket-count=1 --device-list 0:32

The QEMU invocation needs to create a chardev socket the device can
use to communicate as well as share the guests memory over a memfd.

::

  host# qemu-system \
      -chardev socket,path=vi2c.sock,id=vi2c \
      -device vhost-user-i2c-pci,chardev=vi2c,id=i2c \
      -m 4096 \
      -object memory-backend-file,id=mem,size=4G,mem-path=/dev/shm,share=on \
      -numa node,memdev=mem \
      ...
