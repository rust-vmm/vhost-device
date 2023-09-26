# SPDX-License-Identifier: GPL-2.0
#
# Makefile for the IIO Dummy Driver
#
# Modified by Milan Zamazal <mzamazal@redhat.com> in 2023 for out of
# tree compilation.
#

obj-m += iio_modified_dummy.o

on_nixos = $(wildcard /etc/NIXOS)
ifeq ($(on_nixos), /etc/NIXOS)
nix_prefix = $(shell nix-build -E '(import <nixpkgs> {}).linux.dev' --no-out-link)
endif

all:
	make -C $(nix_prefix)/lib/modules/$(shell uname -r)/build M=$(PWD) modules
clean:
	make -C $(nix_prefix)/lib/modules/$(shell uname -r)/build M=$(PWD) clean
