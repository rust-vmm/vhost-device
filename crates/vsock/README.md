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
vhost-user-vsock --guest-cid=<CID assigned to the guest> \
  --socket=<path to the Unix socket to be created to communicate with the VMM via the vhost-user protocol>
  --uds-path=<path to the Unix socket to communicate with the guest via the virtio-vsock device>
```

Run VMM (e.g. QEMU):

```
qemu-system-x86_64 \
  <normal QEMU options> \
  -object memory-backend-file,share=on,id=mem0,size=<Guest RAM size>,mem-path=<Guest RAM file path> \ # size == -m size
  -machine <machine options>,memory-backend=mem0 \
  -chardev socket,id=char0,reconnect=0,path=<vhost-user socket path> \
  -device vhost-user-vsock-pci,chardev=char0
```

## Working example

```sh
shell1$ vhost-user-vsock --guest-cid=4 --uds-path=/tmp/vm4.vsock --socket=/tmp/vhost4.socket
```

```sh
shell2$ qemu-system-x86_64 \
          -drive file=vm.qcow2,format=qcow2,if=virtio -smp 2 -m 512M -mem-prealloc \
          -object memory-backend-file,share=on,id=mem0,size=512M,mem-path="/dev/hugepages" \
          -machine q35,accel=kvm,memory-backend=mem0 \
          -chardev socket,id=char0,reconnect=0,path=/tmp/vhost4.socket \
          -device vhost-user-vsock-pci,chardev=char0
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

## License

This project is licensed under either of

- [Apache License](http://www.apache.org/licenses/LICENSE-2.0), Version 2.0
- [BSD-3-Clause License](https://opensource.org/licenses/BSD-3-Clause)
