# vhost-user-video

## Synopsis
    vhost-user-video --socket-path <SOCKET_PATH> --backend <BACKEND>

## Description
    A virtio-video device using the vhost-user protocol.

## Arguments

```text
    <BACKEND>
        Video backend to be used [possible values: null, v4l2-decoder]
```

## Options

```text
    -s, --socket-path <SOCKET_PATH>
        Unix socket to which a hypervisor connects to and sets up the control path with the device

    -d, --v4l2-device <V4L2_DEVICE>
        Path to the video device file [default: /dev/video0]

    -b, --backend <BACKEND>
        Video backend to be used [possible values: null, v4l2-decoder]

    -h, --help
        Print help

    -V, --version
        Print version
```

## Limitations

Currently this crate only supports v4l2 stateful decoder devices, and
the intention is it will be used with Arm SoCs that implement stateful
decode/encode devices such as Qcom Venus, RPi, MediaTek etc.

Support for VAAPI or decoding via libavcodec or similar
libraries is not implemented, but this could be added in the future
through different video backends.

## Features

This crate is a work-in-progress. Also, the specification for this device is
still a work-in-progress, so it requires and out-of-tree kernel on the
guest. Currently, the vmm translates from virtio-video
[v3](http://archive.lwn.net:8080/linux-media/6557912.4vTCxPXJkl@os-lin-dmo/T/)
protocol and writes to a 
[v4l2 mem2mem stateful decoder device](https://www.kernel.org/doc/html/latest/userspace-api/media/v4l/dev-decoder.html).
The v3 of the specification was chosen as there is a
virtio-video Linux frontend driver implementation available for testing.

The primary goal so far is to enable development of virtio-video
frontend driver using purely open source software. Using
[vicodec](https://lwn.net/Articles/760650/)
v4l2 stateful decoder on the host for testing allows a pure
virtual environment for development and testing.

## Working example

In this section we provide with some example commands to run the daemon
and decode a video using vicodec.

Guest Linux kernel modules:

```text
CONFIG_MEDIA_SUPPORT=y
CONFIG_MEDIA_TEST_SUPPORT=y
CONFIG_V4L_TEST_DRIVERS=y
CONFIG_VIRTIO_VIDEO=y
CONFIG_GDB_SCRIPTS=y
CONFIG_DRM_VIRTIO_GPU=y
```


Host kernel modules:

```text
CONFIG_MEDIA_SUPPORT=y
CONFIG_MEDIA_TEST_SUPPORT=y
CONFIG_V4L_TEST_DRIVERS=y
CONFIG_VIDEO_VICODEC=y
```

The daemon should be started first (video3 typically is the stateful video):

```text
host# vhost-user-video --socket-path=/tmp/video.sock --v4l2-device=/dev/video3 --backend=v4l2-decoder
```

The QEMU invocation needs to create a chardev socket the device can
use to communicate as well as share the guests memory over a memfd.

```text
host# qemu-system								                            \
    -device vhost-user-video-pci,chardev=video,id=video                     \
    -chardev socket,path=/tmp/video.sock,id=video                           \
    -m 4096 		        					                            \
    -object memory-backend-file,id=mem,size=4G,mem-path=/dev/shm,share=on	\
    -numa node,memdev=mem							                        \
    ...
```

After booting, the device should be available at /dev/video0:

```text
guest# v4l2-ctl -d/dev/video0 --info
Driver Info:
        Driver name      : virtio-video
        Card type        : 
        Bus info         : virtio:stateful-decoder
        Driver version   : 6.1.0
        Capabilities     : 0x84204000
                Video Memory-to-Memory Multiplanar
                Streaming
                Extended Pix Format
                Device Capabilities
        Device Caps      : 0x04204000
                Video Memory-to-Memory Multiplanar
                Streaming
                Extended Pix Format
```

Example v4l2-ctl decode command:

```text
guest# v4l2-ctl -d0 -x width=640,height=480 -v width=640,height=480,pixelformat=YU12 \
    --stream-mmap --stream-out-mmap --stream-from test_640_480-420P.fwht            \
    --stream-to out-test-640-480.YU12
```

Play the raw decoded video with ffplay or mplayer:

```text
guest# ffplay -loglevel warning -v info -f rawvideo -pixel_format yuv420p \
    -video_size "640x480" ./out-test-640-480.YU12
guest# mplayer -demuxer rawvideo -rawvideo \
    format=i420:w=640:h=480:fps=25 out-test-640-480.YU12
```

Enable v4l2 debug in virtio-video driver:

```text
# echo 0x1f > /sys/class/video4linux/videoX/dev_debug
```

## License

This project is licensed under either of

- [Apache License](http://www.apache.org/licenses/LICENSE-2.0), Version 2.0
- [BSD-3-Clause License](https://opensource.org/licenses/BSD-3-Clause)