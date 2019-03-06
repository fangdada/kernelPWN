obj-m := csaw.o  

KERNELDR := /home/fanda/Desktop/file/linux-2.6.32.1
BUSYDIR  := /home/fanda/Desktop/file/busybox-1.29.3/_install/mytest
PWD := $(shell pwd)  

modules:  
	$(MAKE) -C $(KERNELDR) M=$(PWD) modules  
	gcc -o poc poc.c -static
	rm $(BUSYDIR)/*.ko
	rm $(BUSYDIR)/poc
	cp *.ko $(BUSYDIR)
	cp poc $(BUSYDIR)
	cd $(BUSYDIR)/../ && find . | cpio -o --format=newc > ../rootfs.img
clean:  
	rm -rf *.o *~ core .depend .*.cmd *.ko *.mod.c .tmp_versions

