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
#ifndef PARAM_INCLUDE
#define PARAM_INCLUDE


#define NPROC        64  // maximum number of processes
#define KSTACKSIZE 4096  // size of per-process kernel stack
#define NCPU          8  // maximum number of CPUs
#define NOFILE       16  // open files per process
#define NFILE       100  // open files per system
#define NBUF         10  // size of disk block cache
#define NINODE       50  // maximum number of active i-nodes
#define NDEV         10  // maximum major device number
#define ROOTDEV       1  // device number of file system root disk
#define MAXARG       32  // max exec arguments
#define LOGSIZE      10  // max data sectors in on-disk log
#define NSTASK		 10  // maximum number of smc sessions/tasks
#define NSSERVICE	 50  // maximum number of secure service 
#define NSESSION	 10 // maximum number of sessions in a service
#define NTZACT		 8	 // maximum of trustzone callback handler
#define REQBUFSIZE	 4096	// size of request buffer, used to store normal world request 
#define RSPBUFSIZE	 4096	// siz eof response buffer, used to store normal world response
#define HZ           10
#define NSTACK		 2	//number of pages for user stack
#define N_CALLSTK    15
#endif