#include <tee_api.h>
#include <utee_api.h>

int main(int argc, char **argv)
{
	int pid = 0;
	void *ptr = 0;

	/* test getpid() */
	TEE_Printf("=======================\n");
	pid = getpid();
	TEE_Printf("pid = %d\n",pid);

	/* test brk() */
	TEE_Printf("=======================\n");

	ptr = sbrk(0x0);
	TEE_Printf("sbrk(0x0) cur_ptr=0x%08x\n",(unsigned int)ptr);
	ptr = sbrk(0x1000);
	TEE_Printf("sbrk(0x1000) old_ptr=0x%08x\n",(unsigned int )ptr);
	ptr = sbrk(0x0);
	TEE_Printf("sbrk(0x1000) cur_ptr=0x%08x\n",(unsigned int )ptr);

	/* test malloc() */
	TEE_Printf("=======================\n");
	ptr = 0;
	ptr = malloc(0x100);
	TEE_Printf("malloc(0x100) cur_ptr=0x%08x\n",(unsigned int )ptr);
	if(ptr != 0){
		free(ptr);
		TEE_Printf("free!\n");
	}

	exit(0);

    return 0;
}

