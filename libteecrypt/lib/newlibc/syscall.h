/* 
 * Copyright (C) 2013 - 2014 TrustKernel Team - All Rights Reserved
 *
 * This file is part of T6.
 * Unauthorized copying of this file, via any medium is strictly prohibited
 * Proprietary and confidential
 *
 * A full copy of license could be obtained from 
 *
 * 		http://www.trustkernel.org/license/license.txt
 *
 * Written by Wenhao Li <liwenhaosuper@gmail.com>
 *
 */


/*

// System call numbers

#define SYS_fork    1
#define SYS_exit    2
#define SYS_wait    3
#define SYS_pipe    4
#define SYS_read    5
#define SYS_kill    6
#define SYS_exec    7
#define SYS_fstat   8
#define SYS_chdir   9
#define SYS_dup    10
#define SYS_getpid 11
#define SYS_sbrk   12
#define SYS_sleep  13
#define SYS_uptime 14
#define SYS_open   15
#define SYS_write  16
#define SYS_mknod  17
#define SYS_unlink 18
#define SYS_link   19
#define SYS_mkdir  20
#define SYS_close  21
#define SYS_invoke_nsworld 22
#define SYS_yield  23
#define SYS_mshare  24
#define SYS_mmap_ns	25
#define SYS_munmap_ns 26
#define SYS_tzact 27
#define SYS_tzact_ret 28
#define SYS_tzact_close 29
#define SYS_createsockfd 30
#define SYS_getsockfd 31
#define SYS_flush_cache 32
#define SYS_lseek 33
#define SYS_setsecuremem 34
#define SYS_configperipheral 35
#define SYS_execm 36
#define SYS_secfb_enable 37
#define SYS_secfb_disable 38

*/

/***************** used /*****************/
#define NEW_SYS_exit			1
#define NEW_SYS_read    		3
#define NEW_SYS_write			4
#define NEW_SYS_open    		5
#define NEW_SYS_close  			6
#define NEW_SYS_lseek			19
#define NEW_SYS_getpid			20
#define NEW_SYS_brk				45
#define NEW_SYS_gettimeofday	78
#define NEW_SYS_mmap 			90
#define NEW_SYS_munmap			91
#define NEW_SYS_fstat			108
