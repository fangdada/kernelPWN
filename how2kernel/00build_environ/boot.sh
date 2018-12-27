#!/bin/sh

KERNELDIR=/home/fanda/Desktop/file/linux-2.6.32.1/arch/x86/boot/bzImage
BUSYDIR=/home/fanda/Desktop/file/busybox-1.29.3/rootfs.img

qemu-system-i386 -m 128M -kernel $KERNELDIR -initrd $BUSYDIR -append "console=ttyS0 root=/dev/ram rdinit=/sbin/init" --nographic -s

