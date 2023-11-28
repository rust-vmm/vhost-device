# vhost-device-template - Template for a vhost-device backend implementation

## Description
This program is a template for developers who intend to write a new vhost-device
backend.

## Synopsis

**vhost-device-template** [*OPTIONS*]

## Options

.. program:: vhost-device-template

.. option:: -h, --help

  Print help.

.. option:: -s, --socket-path=PATH

  Location of vhost-user Unix domain socket. This supports a single socket /
  guest.

## Examples

The daemon should be started first:

::

  host# vhost-device-template --socket-path=vfoo.sock

## License

This project is licensed under either of

- [Apache License](http://www.apache.org/licenses/LICENSE-2.0), Version 2.0
- [BSD-3-Clause License](https://opensource.org/licenses/BSD-3-Clause)
