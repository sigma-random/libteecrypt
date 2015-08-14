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
#ifndef _USER_H_
#define _USER_H_
struct stat;

typedef void (*tzact_t)(int,void*,void*);

// system calls
int fork(void);
void exit(int) __attribute__((noreturn));
int wait(void);
int pipe(int*);
int write(int, void*, int);
int read(int, void*, int);
int close(int);
int kill(int);
int exec(char*, char**);
int open(char*, int);
int mknod(char*, short, short);
int unlink(char*);
int fstat(int fd, struct stat*);
int link(char*, char*);
int mkdir(char*);
int chdir(char*);
int dup(int);
int getpid(void);
char* sbrk(int);
int sleep(int);
int uptime(void);
int invoke_nsworld(int);
int yield(void);
int mshare(int);
int mmap_ns(int,int);
int munmap_ns(int,int);
int tzact(int,tzact_t);
int tzact_ret(void);
//int tzact_close(void);
int createsockfd(int);
int getsockfd(int);
void flush_cache();
int lseek(int, int, int);
int setsecuremem(int, int, int);
int configperipheral(int);
int	execm(char*, int, char**);
int secfb_enable(int win_id, unsigned int start, unsigned int size, int mode);
int secfb_disable(void);

// ulib.c
int stat(char*, struct stat*);
char* strcpy(char*, char*);
void *memmove(void*, const void*, int);
char* strchr(const char*, int c);
int strcmp(const char*, const char*);
void uprintf(int, char*, ...);
void uvsprintf(char *buf, const char *fmt, char* args);
char* gets(char*, int max);
//unsigned int strlen(char*);
unsigned int strlen(const char*);
void* memset(void*, int, unsigned int);
void* memcpy(void *dst, const void *src, unsigned int n);
void* malloc(unsigned int);
void* realloc(void* ptr, unsigned int size);
void free(void*);
int atoi(const char*);
long int labs(long int);
int strncmp(const char *p, const char *q, unsigned int n);
char* strncpy(char *s, const char *t, int n);
int memcmp(const void *v1, const void *v2, unsigned int n);
char *strstr(const char *haystack, const char *needle);



/********************** append ***************************/

#include "mytypes.h"
int raise(int sig);
int rand(void);
void srand(unsigned int seed);
void printf(char *fmt, ...);
FILE *fopen(const char *path, const char *mode);
int fclose(FILE *fp);
size_t fread(void *ptr, size_t size, size_t nmemb, FILE *stream);
size_t fwrite(const void *ptr, size_t size, size_t nmemb,
                     FILE *stream);
void qsort(void *base, size_t nmemb, size_t size,
                  int (*compar)(const void *, const void *));


int brk(void *addr);

int gettimeofday(struct timeval *tv, struct timezone *tz);

/*********************************************************/




#endif
