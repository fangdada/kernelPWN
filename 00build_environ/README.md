# how2kernel

## Author: Wenhuo

&nbsp;&nbsp;&nbsp;&nbsp;<font size=2>最近一边继续学习基础的堆利用技巧，一边入门Linux kernel，第一篇文章我们还是同样讲讲怎么搭建环境吧，现在32位较为早起的Linux kernel的漏洞利用资料比较多，非常适合入门，因此我用了Ubuntu14 32位desktop+Linux kernel2.6.32.1版本的内核用来入门学习，用busybox构建一个简单的文件系统，用qemu模拟运行内核。</font></br>

**编译内核**

&nbsp;&nbsp;&nbsp;&nbsp;<font size=2>首先我们先构建内核，从Linux官方的[镜像网站](https://mirrors.edge.kernel.org/pub/linux/kernel/)上下载2.6.32.1版本的内核代码。解压后到文件里make menuconfig设置好配置文件，一般来讲**确保下列选项是勾选**的：</font></br>

KernelHacking-->

- Compile the kernel with debug info
- Compile the kernel with frame poiners

&nbsp;&nbsp;&nbsp;&nbsp;<font size=2>然后**去掉**：</font></br>

Processor type and features-->

- Paravirtualized guest support

&nbsp;&nbsp;&nbsp;&nbsp;<font size=2>然后直接make，make all，make modules就行了。但是生活怎么会对我们这么好呢？马上make就报错了（因为目前版本的gcc版本过高，kernel版本过低，有些语法已经不能使用），所以make之前我们要先做一些改动：</font></br>

- 修改linux-2.6.32.1/arch/x86/vdso/Makefile中（大约28行）的**-m elf_x86_64为-m64**，修改（大约72行）**-m elf_i386为-m32**。
- 修改linux-2.6.32.1/drivers/net/igbvf/igbvf.h中（123行）的**struct结构内部的“struct page *page;”为“struct page *_page;”**。

&nbsp;&nbsp;&nbsp;&nbsp;<font size=2>然后make就可以开始编译了，过程比较长。</font></br>

**编译busybox**

&nbsp;&nbsp;&nbsp;&nbsp;<font size=2>然后我们开始用busybox搭建一个简单的文件系统，在busybox的镜像网站上下载（选最新版本就行）压缩包，然后解压同样进入文件目录用make menuconfig设置配置文件，**关闭以下选项**：</font></br>

Linux System Utilities-->

- Support mounting NFS file system

Networking Utilities-->

- inetd

&nbsp;&nbsp;&nbsp;&nbsp;<font size=2>**打开选项**：</font></br>

Settings --> Build Options ->

- Build Busybox as a static binary

&nbsp;&nbsp;&nbsp;&nbsp;<font size=2>然后make，make结束之后sudo make install。结束了之后cd _install进入安装完了的目录，进行如下配置：</font></br>

```shell
$ mkdir proc sys dev etc etc/init.d
$ vim etc/init.d/rcS
#!/bin/sh
mount -t proc none /proc
mount -t sysfs none /sys
/sbin/mdev -s
$ chmod +x etc/init.d/rcS
$ find . | cpio -o --format=newc > ../rootfs.img
```

&nbsp;&nbsp;&nbsp;&nbsp;<font size=2>注意每次在busybox的文件系统里有什么操作改动的话一定要在_install目录下重新用cpio建立文件镜像，然后我们就可以用qemu创建虚拟机了，在这里用qemu-system-i386的“-kernel”选项指定引导扇区（boot sector），也就是make内核时生成的bzImage；用“-initrd”选项指定文件映像，也就是用cpio生成的rootfs.img；用“-append "console=ttyS0 root=/dev/ram rdinit=/sbin/init"  --nographic -s”指定虚拟机开启的模式，console=ttyS0意为用当前终端作为虚拟机的终端，剩下的两个意思不太懂，猜测是指定初始化路径和内存路径吧，然后--nographic就是字面意思，-s就是-gdb tcp::1234的缩写，开启一个可供远程调试的端口。我们可以写一个boot.sh脚本这样每次就不用敲这么长的命令了：</font></br>

```shell
#!/bin/sh

KERNELDIR=/home/fanda/Desktop/file/linux-2.6.32.1/arch/x86/boot/bzImage
BUSYDIR=/home/fanda/Desktop/file/busybox-1.29.3/rootfs.img

qemu-system-i386 -m 128M -kernel $KERNELDIR -initrd $BUSYDIR -append "console=ttyS0 root=/dev/ram rdinit=/sbin/init" --nographic -s

```

&nbsp;&nbsp;&nbsp;&nbsp;<font size=2>内核环境搭建完了，现在我们可以很简单的启动内核测试环境了，下一节就开始第一个漏洞的demo测试了，而且不但驱动文件的生成，还可以把文件系统的镜像生成也放入Makefile，这样就更简单了。</font></br>