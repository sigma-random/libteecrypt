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
#include "types.h"
#include "stat.h"
#include "fcntl.h"
#include "user.h"

char*
strcpy(char *s, char *t)
{
    char *os;
    
    os = s;
    while((*s++ = *t++) != 0)
        ;
    return os;
}
int strncmp(const char *p, const char *q, uint n)
{
    while(n > 0 && *p && *p == *q) {
        n--, p++, q++;
    }

    if(n == 0) {
        return 0;
    }

    return (uchar)*p - (uchar)*q;
}

char* strncpy(char *s, const char *t, int n)
{
    char *os;

    os = s;

    while(n-- > 0 && (*s++ = *t++) != 0)
        ;

    while(n-- > 0) {
        *s++ = 0;
    }

    return os;
}
int
strcmp(const char *p, const char *q)
{
    while(*p && *p == *q)
        p++, q++;
    return (uchar)*p - (uchar)*q;
}

uint
//strlen(char *s)
strlen(const char *s)
{
    int n;
    
    for(n = 0; s[n]; n++)
        ;
    return n;
}

int memcmp(const void *v1, const void *v2, unsigned int n)
{
    const unsigned char *s1, *s2;

    s1 = v1;
    s2 = v2;

    while(n-- > 0){
        if(*s1 != *s2) {
            return *s1 - *s2;
        }

        s1++, s2++;
    }

    return 0;
}
void*
memset(void *dst, int v, uint n)
{
	uint8	*p;
	uint8	c;
	uint32	val;
	uint32	*p4;

	p   = dst;
	c   = v & 0xff;
	val = (c << 24) | (c << 16) | (c << 8) | c;

	// set bytes before whole uint32
	for (; (n > 0) && ((uint)p % 4); n--, p++){
		*p = c;
	}

	// set memory 4 bytes a time
	p4 = (uint*)p;

	for (; n >= 4; n -= 4, p4++) {
		*p4 = val;
	}

	// set leftover one byte a time
	p = (uint8*)p4;

	for (; n > 0; n--, p++) {
		*p = c;
	}
// LL : strange here. Why does it need a return here. Should it be "void"?
	return dst;
}

char *strchr(const char *s, int c){
	char *ptr = (char*)s;
	while (*ptr != (char)c) {
		if(*ptr == '\0')
			return NULL;
		ptr++;
	}
	return ptr;   
}


char*
gets(char *buf, int max)
{
    int i, cc;
    char c;
    
    for(i=0; i+1 < max; ){
        cc = read(0, &c, 1);
        if(cc < 1)
            break;
        buf[i++] = c;
        if(c == '\n' || c == '\r')
            break;
    }
    buf[i] = '\0';
    return buf;
}

int
stat(char *n, struct stat *st)
{
    int fd;
    int r;
    
    fd = open(n, O_RDONLY);
    if(fd < 0)
        return -1;
    r = fstat(fd, st);
    close(fd);
    return r;
}

int
atoi(const char *s)
{
    int n;
    
    n = 0;
    while('0' <= *s && *s <= '9')
        n = n*10 + *s++ - '0';
    return n;
}

void*
memmove(void *vdst, const void *vsrc, int n)
{
    char *dst;
	const char *src;
    
	dst = vdst;
	src = vsrc;
	if(dst == src)
		return vdst;
	if(src + n <= dst || dst + n <= src)
		return memcpy(dst, src, n);
	//could overlap
	if(src < dst){
		src +=n;
		dst +=n;
		while(n-- > 0)
			*--dst = *--src;
	}else{
		while(n-- > 0)
			*dst++ = *src++;
	}
    return vdst;
}
void* memcpy(void *dst, const void *src, uint n)
{
	const char *s;
	char *d;
	s = src;
	d = dst;
	while(n>0){
		n--;
		*d = *s;
		d++;
		s++;
	}
    return dst;
}
char *strstr(const char *searchee, const char *lookfor){
	if (*searchee == 0){
		if (*lookfor)
			return (char *) NULL;
		return (char *) searchee;
	}
	while (*searchee){
		unsigned int i;
		i = 0;
		while (1){
			if (lookfor[i] == 0){
				return (char *) searchee;
			}
			if (lookfor[i] != searchee[i])
			{
				break;
			}
			i++;
		}
		searchee++;
	}
	return (char*) NULL;
}


/********************** append ***************************/


static unsigned long prng_next = 1;  

int rand(void) {  
    prng_next = prng_next * 1103515245 + 12345;  
    return((unsigned)(prng_next/65536) % RAND_MAX);  
}  

void srand(unsigned int seed) {  
    prng_next = seed;  
}  



FILE *fopen(const char *path, const char *mode) {

	return NULL;
}
int fclose(FILE *fp) {

	return 0;
}

size_t fread(void *ptr, size_t size, size_t nmemb, FILE *stream) {

	return 0;
}

size_t fwrite(const void *ptr, size_t size, size_t nmemb,
                     FILE *stream) {

	return 0;
}

void qsort(void *base, size_t nmemb, size_t size,
           int (*compar)(const void *, const void *)){


}


int raise(int sig) {

	return 0;
}
