# vhost-device-gpio - GPIO emulation backend daemon

## Description
This program is a vhost-user backend that emulates a VirtIO GPIO device. This
program takes a list of gpio devices on the host OS and then talks to them via
the /dev/gpiochip{X} interface when a request comes from the guest OS for an
GPIO device.

This program is tested with QEMU's `-device vhost-user-gpio-pci` but should
work with any virtual machine monitor (VMM) that supports vhost-user. See the
Examples section below.

## Synopsis

**vhost-device-gpio** [*OPTIONS*]

## Options

.. program:: vhost-device-gpio

.. option:: -h, --help

  Print help.

.. option:: -s, --socket-path=PATH

  Location of vhost-user Unix domain sockets, this path will be suffixed with
  0,1,2..socket_count-1.

.. option:: -c, --socket-count=INT

  Number of guests (sockets) to attach to, default set to 1.

.. option:: -l, --device-list=GPIO-DEVICES

  GPIO device list at the host OS in the format:
      <device1>[:<device2>]

      Example: --device-list "2:4:7"

  Here, each GPIO devices correspond to a separate guest instance, i.e. the
  number of devices in the device-list must match the number of sockets in the
  --socket-count. For example, the GPIO device 0 will be allocated to the guest
  with "<socket-path>0" path.

## MockGpioDevice support

As connecting VM guests to random GPIO pins on your host is generally
asking for trouble you can enable the "mock_gpio" feature in your build:

    cargo build --features "mock_gpio"

You can then enable simulated GPIOs using the 's' prefix:

    --device-list s4:s8

Which will create two gpio devices, the first with 4 pins and the
second with 8. By default updates are display via env logger:

    vhost-device-gpio -s /tmp/vus.sock -c 1 -l s4
    [2023-09-14T14:15:14Z INFO  vhost_device_gpio::mock_gpio] gpio dummy0 set value to 1
    [2023-09-14T14:15:14Z INFO  vhost_device_gpio::mock_gpio] gpio dummy0 set direction to 1
    [2023-09-14T14:15:14Z INFO  vhost_device_gpio::mock_gpio] gpio dummy0 set direction to 0
    [2023-09-14T14:15:19Z INFO  vhost_device_gpio::mock_gpio] gpio dummy1 set value to 1
    [2023-09-14T14:15:19Z INFO  vhost_device_gpio::mock_gpio] gpio dummy1 set direction to 1
    [2023-09-14T14:15:19Z INFO  vhost_device_gpio::mock_gpio] gpio dummy1 set direction to 0

## Examples

The daemon should be started first:

::

  host# vhost-device-gpio --socket-path=gpio.sock --socket-count=2 --device-list 0:3

The QEMU invocation needs to create a chardev socket the device can
use to communicate as well as share the guests memory over a memfd.

::

  host# qemu-system \
      -chardev socket,path=vgpio.sock,id=vgpio \
      -device vhost-user-gpio-pci,chardev=vgpio,id=gpio \
      -m 4096 \
      -object memory-backend-file,id=mem,size=4G,mem-path=/dev/shm,share=on \
      -numa node,memdev=mem \
      ...

## License

This project is licensed under either of

- [Apache License](http://www.apache.org/licenses/LICENSE-2.0), Version 2.0
- [BSD-3-Clause License](https://opensource.org/licenses/BSD-3-Clause)
