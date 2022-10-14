# vhost-user-vsock

## Design

The crate introduces a vhost-user-vsock device that enables communication between an
application running in the guest i.e inside a VM and an application running on the
host i.e outside the VM. The application running in the guest communicates over VM
sockets i.e over AF_VSOCK sockets. The application running on the host connects to a
unix socket on the host i.e communicates over AF_UNIX sockets. The main components of
the crate are split into various files as described below:

- [packet.rs](src/packet.rs)
  - Introduces the **VsockPacket** structure that represents a single vsock packet
  processing methods.
- [rxops.rs](src/rxops.rs)
  - Introduces various vsock operations that are enqueued into the rxqueue to be sent to the
  guest. Exposes a **RxOps** structure.
- [rxqueue.rs](src/rxqueue.rs)
  - rxqueue contains the pending rx operations corresponding to that connection. The queue is
  represented as a bitmap as we handle connection-oriented connections. The module contains
  various queue manipulation methods. Exposes a **RxQueue** structure.
- [thread_backend.rs](src/thread_backend.rs)
  - Multiplexes connections between host and guest and calls into per connection methods that
  are responsible for processing data and packets corresponding to the connection. Exposes a
  **VsockThreadBackend** structure.
- [txbuf.rs](src/txbuf.rs)
  - Module to buffer data that is sent from the guest to the host. The module exposes a **LocalTxBuf**
  structure.
- [vhost_user_vsock_thread.rs](src/vhost_user_vsock_thread.rs)
  - Module exposes a **VhostUserVsockThread** structure. It also handles new host initiated
  connections and provides interfaces for registering host connections with the epoll fd. Also
  provides interfaces for iterating through the rx and tx queues.
- [vsock_conn.rs](src/vsock_conn.rs)
  - Module introduces a **VsockConnection** structure that represents a single vsock connection
  between the guest and the host. It also processes packets according to their type.
- [vhu_vsock.rs](src/lib.rs)
  - exposes the main vhost user vsock backend interface.

## Usage

Run the vhost-user-vsock device:
```
vhost-user-vsock --guest-cid=4 --uds-path=/tmp/vm4.vsock --socket=/tmp/vhost4.socket
```

Run qemu:

```
qemu-system-x86_64 -drive file=/path/to/disk.qcow2 -enable-kvm -m 512M \
  -smp 2 -vga virtio -chardev socket,id=char0,reconnect=0,path=/tmp/vhost4.socket \
  -device vhost-user-vsock-pci,chardev=char0 \
  -object memory-backend-file,share=on,id=mem,size="512M",mem-path="/dev/hugepages" \
  -numa node,memdev=mem -mem-prealloc
```

### Guest listening

#### iperf

```sh
# https://github.com/stefano-garzarella/iperf-vsock
guest$ iperf3 --vsock -s
host$  iperf3 --vsock -c /tmp/vm4.vsock
```

#### netcat

```sh
guest$ nc --vsock -l 1234

host$  nc -U /tmp/vm4.vsock
CONNECT 1234
```

### Host listening

#### iperf

```sh
# https://github.com/stefano-garzarella/iperf-vsock
host$  iperf3 --vsock -s -B /tmp/vm4.vsock
guest$ iperf3 --vsock -c 2
```

#### netcat

```sh
host$ nc -l -U /tmp/vm4.vsock_1234

guest$ nc --vsock 2 1234
```

```rust
use my_crate;

...
```

## License

**!!!NOTICE**: The BSD-3-Clause license is not included in this template.
The license needs to be manually added because the text of the license file
also includes the copyright. The copyright can be different for different
crates. If the crate contains code from CrosVM, the crate must add the
CrosVM copyright which can be found
[here](https://chromium.googlesource.com/chromiumos/platform/crosvm/+/master/LICENSE).
For crates developed from scratch, the copyright is different and depends on
the contributors.
