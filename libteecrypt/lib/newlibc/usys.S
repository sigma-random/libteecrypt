#include "syscall.h"


/*

#define SYSCALL(name) \
.globl name; \
name: \
	PUSH {r4};\
	MOV r4, r3;\
	MOV r3, r2;\
	MOV r2, r1;\
	MOV r1, r0;\
	MOV r0, #SYS_ ## name;\
	swi 0x00;\
	POP {r4};\
	bx lr;


SYSCALL(fork)
SYSCALL(exit)
SYSCALL(wait)
SYSCALL(pipe)
SYSCALL(read)
SYSCALL(write)
SYSCALL(close)
SYSCALL(kill)
SYSCALL(exec)
SYSCALL(open)
SYSCALL(mknod)
SYSCALL(unlink)
SYSCALL(fstat)
SYSCALL(link)
SYSCALL(mkdir)
SYSCALL(chdir)
SYSCALL(dup)
SYSCALL(getpid)
SYSCALL(sbrk)
SYSCALL(sleep)
SYSCALL(uptime)
SYSCALL(invoke_nsworld)
SYSCALL(yield)
SYSCALL(mshare)
SYSCALL(mmap_ns)
SYSCALL(munmap_ns)
SYSCALL(tzact)
SYSCALL(tzact_ret)
SYSCALL(createsockfd)
SYSCALL(getsockfd)
SYSCALL(flush_cache)
SYSCALL(lseek)
SYSCALL(setsecuremem)
SYSCALL(configperipheral)
SYSCALL(execm)
SYSCALL(secfb_enable)
SYSCALL(secfb_disable)

*/



/***************** used *****************/

#define NEW_SYSCALL(name) \
.globl name; \
name: \
	STMFD SP! , {R7,LR};\
	MOV R7, #NEW_SYS_ ## name;\
	SWI 0x00;\
	LDMFD SP! , {R7,LR};\
	BX LR;

NEW_SYSCALL(exit)
NEW_SYSCALL(read)
NEW_SYSCALL(write)
NEW_SYSCALL(open)
NEW_SYSCALL(close)
NEW_SYSCALL(lseek)
NEW_SYSCALL(getpid)
NEW_SYSCALL(brk)
NEW_SYSCALL(gettimeofday)
NEW_SYSCALL(mmap)
NEW_SYSCALL(munmap)
NEW_SYSCALL(fstat)

