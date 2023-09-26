#!/bin/bash -xe

dnf install -y git make g++ fio liburing-devel blktrace

git clone https://github.com/osandov/blktests.git
pushd blktests
  echo "TEST_DEVS=(/dev/sdb)" > config
	make -j $(nproc)
	./check scsi block
popd