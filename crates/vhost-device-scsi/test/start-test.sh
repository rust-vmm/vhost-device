#!/bin/bash -xe

cd $(dirname "$0")

libvirtd --daemon
virtlogd --daemon
export LIBGUESTFS_BACKEND=direct

mkdir -p test-data/
pushd test-data
  IMAGE=Fedora-Cloud-Base-38-1.6.x86_64.qcow2
  test -e "$IMAGE" || wget --quiet "https://download.fedoraproject.org/pub/fedora/linux/releases/38/Cloud/x86_64/images/$IMAGE" -O "$IMAGE"
  qemu-img create -f qcow2 -F qcow2 -b "$PWD/$IMAGE" fedora-overlay.qcow2

  test -e test-key-id_rsa || ssh-keygen -N "" -f test-key-id_rsa

  virt-sysprep -a fedora-overlay.qcow2 \
    --ssh-inject root:file:test-key-id_rsa.pub

  fallocate -l 5GiB big-image.img
popd

SSH_OPTS="-i test-data/test-key-id_rsa -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o User=root -o Port=2222"

vhost-device-scsi --socket-path /tmp/vhost-user-scsi.sock test-data/big-image.img &

sleep 1

qemu-system-x86_64 \
  -enable-kvm -cpu host \
  -device virtio-net-pci,netdev=net0,mac=52:54:00:12:35:02\
  -netdev user,id=net0,hostfwd=tcp::2222-:22,hostfwd=tcp::2323-:23 \
  -object rng-random,filename=/dev/urandom,id=rng0 -device virtio-rng-pci,rng=rng0 \
  -hda test-data/fedora-overlay.qcow2 \
  -object memory-backend-memfd,id=mem,size=8192M,share=on \
  -numa node,memdev=mem \
  -device vhost-user-scsi-pci,num_queues=1,param_change=off,chardev=vus \
  -chardev socket,id=vus,path=/tmp/vhost-user-scsi.sock \
  -smp 4 -m 8192 \
  -serial mon:stdio \
  -display none &


while ! ssh $SSH_OPTS localhost echo waiting for guest to come online
do
  sleep 1
done


scp $SSH_OPTS test-script.sh localhost:~/
ssh $SSH_OPTS localhost /root/test-script.sh || echo "tests failed"

export RESULT_DIR="$PWD/results/$(date --rfc-3339=s)"
mkdir -p "$RESULT_DIR"

scp $SSH_OPTS -r localhost:/root/blktests/results/ "$RESULT_DIR/"
ssh $SSH_OPTS localhost poweroff

wait # wait for qemu to terminate

