#!/bin/bash -xe

cd $(dirname "$0")

DAEMON_BINARY="$PWD/../../../target/debug/vhost-device-scsi"

if [[ ! -e "$DAEMON_BINARY" ]]
then
  echo "Unable to find \"$DAEMON_BINARY\". Did you run cargo build?"
  exit 1
fi

TAG_NAME=vhost-device-scsi-test-env
podman build -t "$TAG_NAME" .
podman run \
  -v /dev/kvm:/dev/kvm \
  --security-opt label=disable  \
  -v "$DAEMON_BINARY":/usr/local/bin/vhost-device-scsi:ro \
  -v $PWD:/test "$TAG_NAME" \
  /test/start-test.sh
