# vhost-user-sound

<!--
generated with help2man target/debug/vhost-user-sound |mandoc
-->
## Synopsis
       vhost-user-sound --socket <SOCKET> --backend <BACKEND>

## Description
       A virtio-sound device using the vhost-user protocol.

## Options

```text
     --socket <SOCKET>
            vhost-user Unix domain socket path

     --backend <BACKEND>
            audio backend to be used (supported: null)

     -h, --help
            Print help

     -V, --version
            Print version
```

## Examples

Launch the backend on the host machine:

```shell
host# vhost-user-sound --socket /tmp/snd.sock --backend null
```

With QEMU, you can add a `virtio` device that uses the backend's socket with the following flags:

```text
-chardev socket,id=vsnd,path=/tmp/snd.sock \
-device vhost-user-snd-pci,chardev=vsnd,id=snd
```

## License

This project is licensed under either of

- [Apache License](http://www.apache.org/licenses/LICENSE-2.0), Version 2.0
- [BSD-3-Clause License](https://opensource.org/licenses/BSD-3-Clause)
