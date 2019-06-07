KERNEL64DIR="/home/fanda/Desktop/file/kernel/linux-4.4.72/arch/x86_64/boot/bzImage"
BUSYDIR="/home/fanda/Desktop/file/kernel/busybox-1.29.3/rootfs.img"

qemu-system-x86_64 -kernel $KERNEL64DIR -initrd $BUSYDIR -append "console=ttyS0 root=/dev/ram rdinit=/sbin/init oops=panic panic=1" -m 64M -cpu kvm64,+smep --nographic -gdb tcp::1234

