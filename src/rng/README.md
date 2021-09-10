# vhost-device-rng - RNG emulation backend daemon

## Description
This program is a vhost-user backend that emulates a VirtIO random number
generator (RNG).  It uses the host's random number generator pool,
/dev/urandom by default but configurable at will, to satisfy requests from
guests.

The daemon is designed to respect limitation on possible random generator
hardware using the --max-bytes and --period options.  As such 5 kilobyte per
second would translate to "--max-bytes 5000 --period 1000".  If an application
requests more bytes than the allowed limit the thread will block until the
start of a new period.  The daemon will automatically split the available
bandwidth equally between the guest when several threads are requested.

Thought developed and tested with QEMU, the implemenation is based on the
vhost-user protocol and as such should be interoperable with other virtual
machine managers.  Please see below for working examples.

## Synopsis

**vhost-device-rng** [*OPTIONS*]

## Options

.. program:: vhost-device-rng

.. option:: -h, --help

  Print help.

.. option:: -s, --socket-path=PATH

  Location of vhost-user Unix domain sockets, this path will be suffixed with
  0,1,2..socket_count-1.

.. option:: -f, --filename
  Random number generator source file, defaults to /dev/urandom.

.. option:: -c, --socket-count=INT

  Number of guests (sockets) to attach to, default set to 1.

.. option:: -p, --period

  Rate, in milliseconds, at which the RNG hardware can generate random data.
  Used in conjunction with the --max-bytes option.

.. option:: -m, --max-bytes

  In conjuction with the --period parameter, provides the maximum number of byte
  per milliseconds a RNG device can generate.

## Examples

The daemon should be started first:

::

  host# vhost-device-rng --socket-path=rng.sock -c 1 -m 512 -p 1000

The QEMU invocation needs to create a chardev socket the device can
use to communicate as well as share the guests memory over a memfd.

::

  host# qemu-system -M virt						    	\
      -object memory-backend-file,id=mem,size=4G,mem-path=/dev/shm,share=on 	\
      -chardev socket,path=rng.sock,id=rng0					\
      -device vhost-user-rng-pci,chardev=rng0                         		\
      -numa node,memdev=mem							\
      ...
