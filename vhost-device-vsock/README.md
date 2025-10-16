# vhost-device-vsock

vhost-device-vsock is a vhost-user device implementation that emulates a virtio-vsock device, allowing guest applications to use AF_VSOCK sockets to communicate with host services or daemons. It enables bidirectional communication between applications running inside a virtual machine (guest) and applications running on the host or other VMs.

The device acts as a bridge between the guest's vsock interface and the host, supporting multiple backend configurations to accommodate different use cases and host environments.

## Backends

vhost-device-vsock supports two different backends for host-side communication, allowing flexible integration depending on your use case. The backend is selected by the command-line options you provide:

- **Unix Domain Socket backend**: enabled by using the `--uds-path` option
- **VSOCK backend**: enabled by using the `--forward-cid` option

### Unix Domain Socket Backend

The Unix domain socket (UDS) backend is enabled by specifying the `--uds-path` option. It enables communication between the guest and host applications using AF_UNIX sockets on the host side. This backend implements a protocol based on [Firecracker's hybrid-vsock design](https://github.com/firecracker-microvm/firecracker/blob/main/docs/vsock.md#firecracker-virtio-vsock-design), providing a bridge between AF_VSOCK (guest) and AF_UNIX (host) socket domains.

**How it works:**
- Guest applications use AF_VSOCK sockets to communicate
- vhost-device-vsock translates these connections to AF_UNIX sockets on the host
- The main Unix socket is specified by `--uds-path` (e.g., `/tmp/vm4.vsock`)

**Protocol for host applications:**

1. **Host connecting to guest** (guest is listening):
   - Connect to the main Unix socket specified by `--uds-path`
   - Send a text command: `CONNECT <port>\n` where `<port>` is the guest port number
   - If the guest is listening on that port, the connection is established
   - The socket is then used for bidirectional data transfer

   Example with netcat:
   ```sh
   # Guest is listening on port 1234:
   guest$ nc --vsock -l 1234

   # Host connects:
   host$ nc -U /tmp/vm4.vsock
   CONNECT 1234
   # Now data can be sent/received
   ```

2. **Host listening for guest connections** (guest is connecting):
   - Create a Unix socket at `<uds-path>_<port>` where `<port>` is the port number the guest will connect to
   - When the guest connects to host CID (typically 2) on that port, vhost-device-vsock routes the connection to the corresponding Unix socket

   Example with netcat:
   ```sh
   # Host listens on port 1234:
   host$ nc -l -U /tmp/vm4.vsock_1234

   # Guest connects to host CID 2, port 1234:
   guest$ nc --vsock 2 1234
   ```

**When to use:**
- When host applications are designed to work with Unix sockets
- For simple guest-to-host communication scenarios
- When you want to test vsock applications without requiring vsock support on the host (no need to load the vhost-vsock kernel module, which is required when using standard vsock in QEMU)
- When you need a protocol compatible with Firecracker's vsock implementation

**Example:**
```sh
vhost-device-vsock --vm guest-cid=4,uds-path=/tmp/vm4.vsock,socket=/tmp/vhost4.socket
```

In this configuration, guest applications using AF_VSOCK will have their connections forwarded to `/tmp/vm4.vsock` on the host, and host applications can use the protocol described above to communicate with the guest.

### VSOCK Backend

The vsock backend is enabled by specifying the `--forward-cid` option (available under the `backend_vsock` feature, enabled by default). It allows direct AF_VSOCK to AF_VSOCK communication. This backend is useful when you want to forward connections from the guest to another vsock-capable entity on the host, such as the host itself or another VM.

**How it works:**
- Guest applications use AF_VSOCK sockets to communicate
- vhost-device-vsock forwards these connections to another AF_VSOCK address on the host
- The target is specified using `--forward-cid` (typically CID 1 for the host)
- Optionally, `--forward-listen` enables host-to-guest connections on specified ports

**Protocol for host applications:**

1. **Host listening for guest connections** (guest is connecting):
   - The guest always connects to CID 2 (the host from guest's perspective)
   - vhost-device-vsock forwards the connection to `--forward-cid` on the host (e.g., CID 1 for host loopback)
   - Host application listens on the forward-cid using AF_VSOCK sockets
   - The connection is established directly without any protocol commands

   Example with netcat:
   ```sh
   # Host listens on CID 1 (loopback), port 9000:
   host$ nc --vsock -l 1 9000

   # Guest connects to CID 2 (host), port 9000:
   guest$ nc --vsock 2 9000
   # Now data can be sent/received
   ```

2. **Host connecting to guest** (guest is listening):
   - Host application connects to `--forward-cid` on the specified port
   - Ports must be listed in `--forward-listen` option
   - vhost-device-vsock listens on these ports on the forward-cid and forwards connections to the guest via virtio-vsock
   - This creates two separate vsock connections: host ↔ vhost-device-vsock (on forward-cid), and vhost-device-vsock ↔ guest (via virtio-vsock)

   Example with netcat:
   ```sh
   # Guest is listening on port 9001:
   guest$ nc --vsock -l 9001

   # Host connects to CID 1 (forward-cid), port 9001:
   host$ nc --vsock 1 9001
   # vhost-device-vsock forwards this to guest CID 4, port 9001
   # Now data can be sent/received
   ```

**When to use:**
- When testing guest applications that need to communicate with vsock-enabled host services
- When you want to forward guest connections to the host's vsock loopback (CID 1)
- For bidirectional vsock communication between host and guest
- When the host has native vsock support and you want end-to-end vsock connectivity

**Example:**
```sh
vhost-device-vsock --vm guest-cid=4,forward-cid=1,forward-listen=9001+9002,socket=/tmp/vhost4.socket
```

In this configuration:
- Guest-initiated connections are forwarded to the host (CID 1)
- Host applications can connect to ports 9001 and 9002 on the guest

**Requirements:**
- The host must have vsock support (e.g., `vsock_loopback` kernel module loaded)
- For testing, you can load the module with: `modprobe vsock_loopback`

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
      uds_path: /tmp/vm3.vsock
      tx_buffer_size: 65536
      queue_size: 1024
      groups: group1+groupA
    - guest_cid: 4
      socket: /tmp/vhost4.socket
      uds_path: /tmp/vm4.vsock
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

For example, if the guest VM that you want to test has an application that connects to the host on port 9000 upon boot and applications
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

After the guest VM boots, you can test the bidirectional communication:

#### Guest connecting to host

```sh
# Host listens on CID 1 (loopback), port 9000:
host$ nc --vsock -l 1 9000

# Guest connects to CID 2 (host), port 9000:
# vhost-device-vsock forwards to forward-cid (1) on the host
guest$ nc --vsock 2 9000
# Now data can be sent/received
```

#### Host connecting to guest

```sh
# Guest is listening on port 9001:
guest$ nc --vsock -l 9001

# Host connects to CID 1 (forward-cid), port 9001:
# vhost-device-vsock forwards this to the guest
host$ nc --vsock 1 9001
# Now data can be sent/received
```

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
