obj-m := kmod.o
KERNELDIR := /home/fanda/Desktop/file/kernel/linux-4.4.72
BUSYDIR  := /home/fanda/Desktop/file/kernel/busybox-1.29.3/_install/mytest
CONFIG_MODULE_SIG=n

PWD := $(shell pwd)
modules:
	$(MAKE) -C $(KERNELDIR) M=$(PWD) modules
	gcc -o poc poc.c -static
	rm $(BUSYDIR)/*.ko
	rm $(BUSYDIR)/poc
	cp *.ko $(BUSYDIR)
	cp poc $(BUSYDIR)
	cd $(BUSYDIR)/../ && find . | cpio -o --format=newc > ../rootfs.img
clean:
	rm -rf *.o *~ core .depend .*.cmd *.ko *.mod.c .tmp_versions

