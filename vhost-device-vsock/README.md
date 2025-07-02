# vhost-device-vsock

## Design

The crate introduces a vhost-device-vsock device that enables communication between an
application running in the guest i.e inside a VM and an application running on the
host i.e outside the VM. The application running in the guest communicates over VM
sockets i.e over AF_VSOCK sockets. The application running on the host connects to a
unix socket on the host i.e communicates over AF_UNIX sockets when using the unix domain
socket backend through the uds-path option or the application in the host listens or
connects to vsock on the host i.e communicates over AF_VSOCK sockets when using the
vsock backend through the forward-cid, forward-listen options. The main components of
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
- [vhu_vsock.rs](src/vhu_vsock.rs)
  - exposes the main vhost user vsock backend interface.

## Usage

Run the vhost-device-vsock device with unix domain socket backend:
```
vhost-device-vsock --guest-cid=<CID assigned to the guest> \
  --socket=<path to the Unix socket to be created to communicate with the VMM via the vhost-user protocol> \
  --uds-path=<path to the Unix socket to communicate with the guest via the virtio-vsock device> \
  [--tx-buffer-size=<size of the buffer used for the TX virtqueue (guest->host packets)>] \
  [--queue-size=<size of the vring queue>] \
  [--groups=<list of group names to which the device belongs concatenated with '+' delimiter>]
```
or
```
vhost-device-vsock --vm guest_cid=<CID assigned to the guest>,socket=<path to the Unix socket to be created to communicate with the VMM via the vhost-user protocol>,uds-path=<path to the Unix socket to communicate with the guest via the virtio-vsock device>[,tx-buffer-size=<size of the buffer used for the TX virtqueue (guest->host packets)>][,queue-size=<size of the vring queue>][,groups=<list of group names to which the device belongs concatenated with '+' delimiter>]
```

Run the vhost-device-vsock device with vsock backend:
```
vhost-device-vsock --guest-cid=<CID assigned to the guest> \
  --socket=<path to the Unix socket to be created to communicate with the VMM via the vhost-user protocol> \
  --forward-cid=<the vsock CID to which the connections from guest should be forwarded> \
  [--forward-listen=<port numbers separated by '+' for forwarding connections from host to guest> \
  [--tx-buffer-size=<size of the buffer used for the TX virtqueue (guest->host packets)>] \
  [--queue-size=<size of the vring queue>] \
```
or
```
vhost-device-vsock --vm guest_cid=<CID assigned to the guest>,socket=<path to the Unix socket to be created to communicate with the VMM via the vhost-user protocol>,forward-cid=<the vsock CID to which the connections from guest should be forwarded>[,forward-listen=<port numbers separated by '+' for forwarding connections from host to guest>][,tx-buffer-size=<size of the buffer used for the TX virtqueue (guest->host packets)>][,queue-size=<size of the vring queue>][,groups=<list of group names to which the device belongs concatenated with '+' delimiter>]
```

Specify the `--vm` argument multiple times to specify multiple devices like this:
```
vhost-device-vsock \
--vm guest-cid=3,socket=/tmp/vhost3.socket,uds-path=/tmp/vm3.vsock,groups=group1+groupA \
--vm guest-cid=4,socket=/tmp/vhost4.socket,uds-path=/tmp/vm4.vsock,tx-buffer-size=32768,queue-size=256 \
--vm guest-cid=5,socket=/tmp/vhost5.socket,forward-cid=1,forward-listen=9001+9002,tx-buffer-size=32768,queue-size=1024
```

Or use a configuration file:
```
vhost-device-vsock --config=<path to the local yaml configuration file>
```

Configuration file example:
```yaml
vms:
    - guest_cid: 3
      socket: /tmp/vhost3.socket
      uds_path: /tmp/vm3.sock
      tx_buffer_size: 65536
      queue_size: 1024
      groups: group1+groupA
    - guest_cid: 4
      socket: /tmp/vhost4.socket
      uds_path: /tmp/vm4.sock
      tx_buffer_size: 32768
      queue_size: 256
      groups: group2+groupB
    - guest_cid: 5
      socket: /tmp/vhost5.socket
      forward-cid: 1
      forward-listen: 9001+9002
      tx_buffer_size: 32768
      queue_size: 1024
```

Run VMM (e.g. QEMU):

```
qemu-system-x86_64 \
  <normal QEMU options> \
  -object memory-backend-memfd,id=mem0,size=<Guest RAM size> \ # size == -m size
  -machine <machine options>,memory-backend=mem0 \
  -chardev socket,id=char0,reconnect=0,path=<vhost-user socket path> \
  -device vhost-user-vsock-pci,chardev=char0
```

## Working example

```sh
shell1$ vhost-device-vsock --vm guest-cid=4,uds-path=/tmp/vm4.vsock,socket=/tmp/vhost4.socket
```
or if you want to configure the TX buffer size and vring queue size
```sh
shell1$ vhost-device-vsock --vm guest-cid=4,uds-path=/tmp/vm4.vsock,socket=/tmp/vhost4.socket,tx-buffer-size=65536,queue-size=1024
```

```sh
shell2$ qemu-system-x86_64 \
          -drive file=vm.qcow2,format=qcow2,if=virtio -smp 2 \
          -object memory-backend-memfd,id=mem0,size=512M \
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

### Sibling VM communication

If you add multiple VMs with their devices configured with at least one common group name, they can communicate with
each other. If you don't explicitly specify a group name, a default group will be assigned to the device with name
`default`, and all such devices will be able to communicate with each other. Or you can choose a different list of
group names for each device, and only devices with the at least one group in common will be able to communicate with
each other.

For example, if you have two VMs with CID 3 and 4, you can run the following commands to make them communicate:

```sh
shell1$ vhost-device-vsock --vm guest-cid=3,uds-path=/tmp/vm3.vsock,socket=/tmp/vhost3.socket,groups=group1+group2 \
          --vm guest-cid=4,uds-path=/tmp/vm4.vsock,socket=/tmp/vhost4.socket,groups=group1
shell2$ qemu-system-x86_64 \
          -drive file=vm1.qcow2,format=qcow2,if=virtio -smp 2 \
          -object memory-backend-memfd,id=mem0,size=512M \
          -machine q35,accel=kvm,memory-backend=mem0 \
          -chardev socket,id=char0,reconnect=0,path=/tmp/vhost3.socket \
          -device vhost-user-vsock-pci,chardev=char0
shell3$ qemu-system-x86_64 \
          -drive file=vm2.qcow2,format=qcow2,if=virtio -smp 2 \
          -object memory-backend-memfd,id=mem0,size=512M \
          -machine q35,accel=kvm,memory-backend=mem0 \
          -chardev socket,id=char0,reconnect=0,path=/tmp/vhost4.socket \
          -device vhost-user-vsock-pci,chardev=char0
```

Please note that here the `groups` parameter is specified just for clarity, but it is not necessary to specify it if you want
to use the default group and make all the devices communicate with one another. It is useful to specify a list of groups
when you want fine-grained control over which devices can communicate with each other.

```sh
# nc-vsock patched to set `.svm_flags = VMADDR_FLAG_TO_HOST`
guest_cid3$ nc-vsock -l 1234
guest_cid4$ nc-vsock 3 1234
```

### Using the vsock backend

The vsock backend is available under the `backend_vsock` feature (enabled by default). If you want to test a guest VM that
has built-in applications which communicate with another VM over AF_VSOCK, you can forward the connections from the guest
to the host machine instead of running a separate VM for easier testing using the forward-cid option. In such a case, you
would run the corresponding applications that listen for or connect with applications in the guest VM using AF_VSOCK in the
host instead of running the separate VM. For forwarding AF_VSOCK connections from the host, you can use the forward-listen
option.

For example, if the guest VM that you want to test has an application that connects to (CID 3, port 9000) upon boot and applications
that listen on port 9001 and 9002 for connections, first run vhost-device-vsock:

```sh
shell1$ vhost-device-vsock --vm guest-cid=4,forward-cid=1,forward-listen=9001+9002,socket=/tmp/vhost4.socket
```

Now run the application listening for connections to port 9000 on the host machine and then run the guest VM:

```sh
shell2$ qemu-system-x86_64 \
          -drive file=vm1.qcow2,format=qcow2,if=virtio -smp 2 \
          -object memory-backend-memfd,id=mem0,size=512M \
          -machine q35,accel=kvm,memory-backend=mem0 \
          -chardev socket,id=char0,reconnect=0,path=/tmp/vhost4.socket \
          -device vhost-user-vsock-pci,chardev=char0
```

After the guest VM boots, the application inside the guest connecting to (CID 3, port 9000) should successfully connect to the
application running on the host. Assuming the applications listening on port 9001 and 9002 are running in the guest VM, you can
now run the applications that connect to port 9001 and 9002 (you need to modify the CID they connect to be the host CID i.e. 1)
on the host machine.

## Testing

This crate contains several tests that can be run with `cargo test`.

If `backend_vsock` feature is enabled (true by default), some of the tests use
the AF_VSOCK loopback address [CID = 1] to run the tests, so you must have
loaded the kernel module that handles it (`modprobe vsock_loopback`).

Otherwise you may experience the following failures:
```
...
test thread_backend::tests::test_vsock_thread_backend_vsock ... FAILED
...
test vhu_vsock_thread::tests::test_vsock_thread_vsock_backend ... FAILED

failures:


---- thread_backend::tests::test_vsock_thread_backend_vsock stdout ----
thread 'thread_backend::tests::test_vsock_thread_backend_vsock' panicked at vhost-device-vsock/src/thread_backend.rs:607:84:
This test uses VMADDR_CID_LOCAL, so the vsock_loopback kernel module must be loaded: Os { code: 99, kind: AddrNotAvailable, message: "Cannot assign requested address" }

---- vhu_vsock_thread::tests::test_vsock_thread_vsock_backend stdout ----
thread 'vhu_vsock_thread::tests::test_vsock_thread_vsock_backend' panicked at vhost-device-vsock/src/vhu_vsock_thread.rs:1044:84:
This test uses VMADDR_CID_LOCAL, so the vsock_loopback kernel module must be loaded: Os { code: 99, kind: AddrNotAvailable, message: "Cannot assign requested address" }

failures:
    thread_backend::tests::test_vsock_thread_backend_vsock
    vhu_vsock_thread::tests::test_vsock_thread_vsock_backend
```

With the `vsock_loopback` kernel module loaded in your system, all the tests
should pass.

## License

This project is licensed under either of

- [Apache License](http://www.apache.org/licenses/LICENSE-2.0), Version 2.0
- [BSD-3-Clause License](https://opensource.org/licenses/BSD-3-Clause)
