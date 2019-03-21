#!/bin/sh

insmod *.ko
mknod /dev/bof c 248 0
#mknod /dev/vuln c 248 0
#mknod /dev/arw c 248 0

#sysctl -w vm.mmap_min_addr="0"

mkdir -p /home/fanda
touch /etc/group
touch /etc/passwd
adduser fanda

#chmod 777 /dev/vuln
chmod 777 /dev/bof
#chmod 777 /dev/ptmx
#chmod 777 /dev/arw

su fanda

