# Using emulated industrial I/O devices

This is a modified version of the Linux [industrial I/O dummy
driver](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/drivers/iio/dummy).
Both the original driver and this modification can provide emulated
industrial I/O devices for testing vhost-device-scmi.

## Modifications in this module

If the stock industrial I/O dummy driver is enough for you, use it
(but you may still want to read the instructions below).

Otherwise, this alternative is provided with the following changes:

- Simplified Makefile for out of tree compilation.
- The accelerometer has three axes instead of just one.
- The Y axis of the accelerometer has offset and scale.

Of course, you can modified it further for your liking if needed.

## How to create emulated industrial I/O devices

Make sure your kernel supports software industrial I/O devices and
industrial I/O with configfs.  You can check this by running `modprobe
industrialio_sw_device && modprobe industrialio_configfs`.  If any of
the modules is not present, follow the [instructions for recompiling
kernel](#recompiling-kernel-with-industrial-io) below.

Make sure you have the right kernel version.  Since Linux 5.19, the
dummy industrial I/O driver is broken.  This will be probably fixed in
Linux 6.6.

If you have a broken kernel version, apply the
[fix](./iio-dummy-fix.patch) and compile and install the modified
kernel.

If you want to use the modified module from here, compile it.  In
order to do this, you must have kernel development environment
installed, for example:

- Fedora or derivatives: `dnf install kernel-devel kernel-modules make`
- Debian or derivatives: `apt install linux-headers-$(uname -r) make`
- NixOS: `nix-shell '<nixpkgs>' -A linux.dev`

Then you can compile the module, simply running `make` should work on
most distributions.

Insert a dummy industrial I/O kernel module.  Either the stock one:

```
# modprobe iio-dummy
```

or the modified one from here:

```
# modprobe industrialio
# modprobe industrialio_configfs
# modprobe industrialio_sw_device
# insmod ./iio-dummy-modified.ko
```

Find out where configfs is mounted: `mount | grep configfs`.  It's
typically `/sys/kernel/config`.  If configfs is not mounted, mount it
somewhere: `mount -t configfs none MOUNTPOINT`.

Now you can create emulated industrial I/O devices with the stock driver:

```
# mkdir /sys/kernel/config/iio/devices/dummy/my-device
```

And/or with the modified driver from here:

```
# mkdir /sys/kernel/config/iio/devices/dummy-modified/my-device
```

If everything is OK then you can find the device in
`/sys/bus/iio/devices/`.

## Recompiling kernel with industrial I/O

Making a custom kernel is different on each GNU/Linux distribution.
The corresponding documentation can be found for example here:

- Fedora: [https://fedoraproject.org/wiki/Building_a_custom_kernel](https://fedoraproject.org/wiki/Building_a_custom_kernel)
- CentOS Stream: [https://wiki.centos.org/HowTos/BuildingKernelModules](https://wiki.centos.org/HowTos/BuildingKernelModules)
  (looks more useful for Fedora builds than CentOS)
- Debian: [https://kernel-team.pages.debian.net/kernel-handbook/ch-common-tasks.html#s-common-official](https://kernel-team.pages.debian.net/kernel-handbook/ch-common-tasks.html#s-common-official)
- NixOS: [https://nixos.wiki/wiki/Linux_kernel](https://nixos.wiki/wiki/Linux_kernel)

Here are instructions for Fedora, similar steps can be used for other
distributions, with distribution specifics as described in the links
above.  This is not necessarily the most official or the best way to
do it but it's a way that *actually works* for me.

Note on CentOS Stream 9: The kernel there doesn't contain the needed
modules.  Recompiling the kernel on CentOS Stream may be challenging
due to missing build dependencies.  If it doesn't work for you, you
can try to use Fedora kernel and modules on CentOS Stream, including
the dummy module compiled on Fedora.

### Install kernel sources

```
# dnf install 'dnf-command(download)'
$ dnf download --source kernel
$ rpm -i kernel-*.src.rpm
# dnf builddep ~/rpmbuild/SPECS/kernel.spec
```

### Change kernel configuration

Not needed for current Fedora but may be needed for e.g. CentOS Stream.

```
# dnf install kernel-devel kernel-modules make rpm-build python3-devel ncurses-devel
$ rpmbuild -bp ~/rpmbuild/SPECS/kernel.spec
$ cd ~/rpmbuild/BUILD/kernel-*/linux-*/
$ cp configs/kernel-VERSION-YOURARCH.config .config
$ make nconfig
```

Configuration options that must be enabled:

- Device Drivers -> Industrial I/O Support -> Enable IIO configuration via configfs
- Device Drivers -> Industrial I/O Support -> Enable software IIO device support

Optionally (you can use the alternative driver from here instead):

- Device Drivers -> Industrial I/O Support -> IIO dummy drive -> An example driver with no hardware requirements

Then copy `.config` back to its original file and don't forget to add
the original architecture specification line there.

### Apply the kernel fix

If the kernel fix from here is needed, copy it to the sources:

```
cp .../iio-dummy-fix.patch ~/rpmbuild/SOURCES/
```

Edit `~/rpmbuild/SPECS/kernel.spec`:

- Uncomment: `%define buildid .local`.

- Add the patch file before: `Patch999999: linux-kernel-test.patch`.

- Add the patch file before: `ApplyOptionalPatch linux-kernel-test.patch`.

### Build the kernel

You can use different options, if you don't need anything extra then
the following builds the most important rpm's:

```
$ rpmbuild -bb --with baseonly --without debug --without debuginfo ~/rpmbuild/SPECS/kernel.spec
```

## Adding industrial I/O dummy module to your kernel

If all you need is to add a missing stock I/O dummy module, you can
try to compile just the module.  Switch to kernel sources and run:

```
$ make oldconfig
$ make prepare
$ make modules_prepare
$ make M=drivers/iio/dummy
```

And insert the module:

```
# modprobe industrialio
# modprobe industrialio_configfs
# modprobe industrialio_sw_device
# insmod ./drivers/iio/dummy/iio-dummy.ko
```

If this fails, inspect `dmesg` output and try to figure out what's
wrong.  If this fails too, rebuild the whole kernel with the given
module enabled.
