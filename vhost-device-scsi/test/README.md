# Testing tools

This folder contains some tooling for tests

## Prerequisites

For running these tests, you need a KVM enabled x86_64 machine and `podman`.

vhost-device-scsi must have been built already.

## Performed tests

Right now, the test harness will only run
[blktests](https://github.com/osandov/blktests) against the target device
(these tests are probably testing the guest kernel more than the actual
device).

## Test execution

Triggering the build of the necessary container images and invoking the tests
is done by calling `./invoke-test.sh`.

That will build the `Containerfile`, launch a container and invoke
`./start-test.sh` inside of the container. That will download a Fedora cloud
image, launch the daemon, launch QEMU, waits until it is up and triggers the
test execution.

Results will be downloaded into a timestamped folder under `results/`.

# Other test tools

Some quick and dirty fuzzing code is available at
https://github.com/Ablu/vhost-device/tree/scsi-fuzzing.
