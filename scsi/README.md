# vhost-user-scsi

This is a Rust implementation of a vhost-user-scsi daemon.

## Usage

Run the vhost-user-scsi daemon:

```
vhost-user-scsi -r /tmp/vhost-user-scsi.sock /path/to/image.raw /path/to/second-image.raw ...
```

Run QEMU:

```
qemu-system-x86_64 ... \
  -device vhost-user-scsi-pci,chardev=vus \
  -chardev socket,id=vus,path=/tmp/vhost-user-scsi.sock \
  # must match total guest meory
  -object memory-backend-memfd,id=mem,size=384M,share=on \
  -numa node,memdev=mem
```

## Features

This crate is a work-in-progress. Currently, it's possible to mount and read
up to 256 read-only raw disk images. Some features we might like to add
at some point, roughly ordered from sooner to later:

- Write support. This should just be a matter of implementing the WRITE
  command, but there's a bit of complexity around writeback caching we
  need to make sure we get right.
- Support more LUNs. virtio-scsi supports up to 16384 LUNs per target.
  After 256, the LUN encoding format is different; it's nothing too
  complicated, but I haven't gotten around to implementing it.
- Concurrency. Currently, we process SCSI commands one at a time. Eventually,
  it'd be a good idea to use threads or some fancy async/io_uring stuff to
  concurrently handle multiple commands. virtio-scsi also allows for multiple
  request queues, allowing the guest to sumbit requests from multiple cores
  in parallel; we should support that.
- iSCSI passthrough. This shouldn't be too bad, but it might be a good idea
  decide on a concurrency model (threads or async) before we spend too much
  time here.
