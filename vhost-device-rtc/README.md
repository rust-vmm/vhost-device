# vhost-device-rtc - Real time clock/timer device

This crate provides both a library and a binary for implementing a VIRTIO RTC through `vhost-user` protocol.
The RTC (Real Time Clock) device provides information about current time.

## Description

## Synopsis

```console
vhost-device-rtc [OPTIONS] <--socket-path <SOCKET>|--socket-fd <FD>>
```

## Options

```text
 vhost-device-rtc

  -s, --socket-path <SOCKET>

  Location of vhost-user Unix domain socket

  --socket-fd <FD>

  vhost-user Unix domain socket FD

  --no-offer-alarm

  Don't offer alarm functionality for smeared UTC clocks. Turns `VIRTIO_RTC_F_ALARM` feature off

  --no-utc

  Don't offer UTC clock

  --no-tai

  Don't offer TAI clock

  --no-monotonic

  Don't offer monotonic clock

  -h, --help

  Print help

  -V, --version

  Print version
```

## Examples

The daemon should be started first:

```console
vhost-device-rtc --socket-path /path/to/rtc.sock
```

With QEMU command-line options:

```text
-chardev socket,path=/path/to/rtc.sock,id=rtc \
-device vhost-user-rtc-pci,chardev=rtc,id=rtc \
```

Or similar.

For usage with QEMU, a `memfd` memory backend is required, e.g.:

```text
  -m 8192 \
  -object memory-backend-memfd,id=mem,size=8G,share=on \
  -numa node,memdev=mem \
```

## Usage in a Linux guest

The following configuration must be enabled to build the driver:

```text
CONFIG_VIRTIO_RTC=y
CONFIG_VIRTIO_RTC_PTP=y
CONFIG_VIRTIO_RTC_CLASS=y
```

If the `virtio_rtc` driver is in your kernel (versions 6.17 and up), these or similar lines should appear on your kernel log:

```text
[    0.353545] virtio_rtc virtio2: registered as rtc0
[    0.354654] virtio_rtc virtio2: setting system clock to 2025-11-19T10:44:38 UTC (1763549078)
```

The clocks will be visible as `/dev/ptp*` devices.

```console
$ cat /sys/class/ptp/ptp0/clock_name
Virtio PTP type 0/variant 0
$ $ phc_ctl /dev/ptp0 get
phc_ctl[449.603]: clock time is ....
```

Smeared UTC clocks will also be visible as `/dev/rtc*` devices which allow for alarm functionality.

```console
# ls -halt /sys/class/rtc/
total 0
drwxr-xr-x  2 root root 0 Nov 19 10:45 .
lrwxrwxrwx  1 root root 0 Nov 19 10:44 rtc0 -> ../../devices/platform/4010000000.pcie/pci0000:00/0000:00:03.0/virtio2/rtc/rtc0
# cat /sys/class/rtc/rtc0/name
virtio_rtc virtio2
```

Set the alarm to wake up the guest:

```console
# date +%s -d'+10 seconds' > /sys/class/rtc/rtc0/wakealarm
```

### How the RTC device wakes up the guest VM

The VIRTIO specification states[^1]:

[^1]: Section "5.23.6.6 Alarm Operation", in "[VIRTIO-v1.4] Virtual I/O Device (VIRTIO) Version 1.4"

> Through the optional alarm feature, the driver can set an alarm time.
> On alarm expiration, the device notifies the driver.
> On alarm expiration, the device may also wake up the driver, while the driver is in a sleep state, or while the driver is powered off.
> How this is done is beyond the scope of the specification

Since the specification states "*How this is done is beyond the scope of the specification*" the user needs to find their own way to wake the guest from suspending to RAM or other sleep state.

#### Virtio-pci wake up

*Note: A vhost-user device can be used with the virtio-pci transport by using its vhost-user-pci device wrapper in QEMU, e.g. `-device vhost-user-rtc-pci,chardev=rtc,id=rtc -chardev socket,path=/path/to/rtc.sock,id=rtc`.*

While the PCI standard allows for wakeup from suspend/sleep, the way the Linux virtio-pci driver and QEMU interact does not allow it.

Before entering sleep, the Linux kernel "freezes" each device.
The virtio-pci Linux driver, disables the PCI device in its freezing handler:

```c
static int virtio_pci_freeze(struct device *dev)
{
	struct pci_dev *pci_dev = to_pci_dev(dev);
	struct virtio_pci_device *vp_dev = pci_get_drvdata(pci_dev);
	int ret;

	ret = virtio_device_freeze(&vp_dev->vdev);

	if (!ret)
		pci_disable_device(pci_dev);
	return ret;
}
```

In QEMU, this is received as a PCI disable command, which disables listening to input from vhost-user backends.
Thus, the alarm notification will never be read from QEMU and passed to the guest.

#### Virtio-mmio wake up (with Device Tree modification)

*Note: A vhost-user device can be used with the virtio-mmio transport by using the device directly in QEMU, e.g. `-device vhost-user-rtc,chardev=rtc,id=rtc -chardev socket,path=/path/to/rtc.sock,id=rtc`.*

According to Linux kernel documentation[^3], through the Device Tree specification (which virtio-mmio can be discovered from when the Linux guest boots) a device can be declared as capable of waking up the guest with the "`wakeup-source;`" node property.

[^3]:  `https://www.kernel.org/doc/Documentation/devicetree/bindings/power/wakeup-source.txt`

Indeed, in the linux kernel, when the transport sets up the virtqueues, it performs the check:

```c
if (of_property_read_bool(vm_dev->pdev->dev.of_node, "wakeup-source"))
        enable_irq_wake(irq);
```

This means that if we set up the device tree property, we can wake up the guest by simply setting the alarm notification, as is already required by the VIRTIO specification.

First, we must extract the device tree blob that QEMU passes to the guest by passing the `dumpdtb=./qemu.dtb` option to the `-machine` CLI flag[^5].
This will save the blob to the `qemu.dtb` file.

[^5]:  Run the same QEMU command that you use to run the guest, only modify `-machine` e.g. `qemu-system-aarch64 -machine type=virt,virtualization=off,acpi=off,dumpdtb=qemu.dtb ...`

Then, we convert the blob to plain-text:

```console
$ dtc -I dtb qemu.dtb > qemu.dts
```

We locate the corresponding `virtio-mmio@`[^6] node and append the property `wakeup-source;`, like in this example:

[^6]: The virtio-mmio address can be discovered from inside the guest VM in its sysfs, e.g.: `$ ls -halt /sys/class/rtc/`


```
        virtio_mmio@a003e00 {
                dma-coherent;
                interrupts = <0x00 0x2f 0x01>;
                reg = <0x00 0xa003e00 0x00 0x200>;
                compatible = "virtio,mmio";
                wakeup-source;
        };
```

Then we convert the plain-text back to a devicetree blob:

```console
$ dtc - -o rtc.dtb < qemu.dts
````

You can now load the modified dtb file with the `-dtb` CLI option in QEMU:

```text
-dtb rtc.dtb
```

Example session: Set the alarm to wake up the guest:

`$ date +%s -d'+10 seconds' > /sys/class/rtc/rtc0/wakealarm`

Suspending the guest to RAM with e.g. with the `systemctl suspend` command, **before the alarm fires**, will result in the guest waking up when it does.

```console
root@localhost:~# date +%s -d'+15 seconds'  > /sys/class/rtc/rtc0/wakealarm
root@localhost:~# systemctl suspend
root@localhost:~# [   17.483157] PM: suspend entry (s2idle)
[   17.505929] Filesystems sync: 0.022 seconds
[   17.510944] Freezing user space processes
[   17.515137] Freezing user space processes completed (elapsed 0.004 seconds)
[   17.516712] OOM killer disabled.
[   17.516729] Freezing remaining freezable tasks
[   17.519581] Freezing remaining freezable tasks completed (elapsed 0.002 seconds)
[   17.519607] printk: Suspending console(s) (use no_console_suspend to debug)
[   29.974776] virtio_blk virtio3: 1/0/0 default/read/poll queues
[   29.981198] virtio_scsi virtio2: 1/0/0 default/read/poll queues
[   29.986429] OOM killer enabled.
[   29.986445] Restarting tasks: Starting
[   29.992477] Restarting tasks: Done
[   29.993779] random: crng reseeded on system resumption
[   29.995620] PM: suspend exit

root@localhost:~#
```
## License

This project is licensed under either of

- [Apache License](http://www.apache.org/licenses/LICENSE-2.0), Version 2.0
- [BSD-3-Clause License](https://opensource.org/licenses/BSD-3-Clause)
