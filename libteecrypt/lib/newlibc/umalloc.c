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
#include "user.h"
#include "param.h"

// Memory allocator by Kernighan and Ritchie,
// The C programming Language, 2nd ed.  Section 8.7.

typedef long Align;

union header {
    struct {
        union header *ptr;
        uint size;
    } s;
    Align x;
};

typedef union header Header;

static Header base;
static Header *freep;

void
free(void *ap)
{

    Header *bp, *p;
    
    bp = (Header*)ap - 1;
    for(p = freep; !(bp > p && bp < p->s.ptr); p = p->s.ptr)
        if(p >= p->s.ptr && (bp > p || bp < p->s.ptr))
            break;
    if(bp + bp->s.size == p->s.ptr){
        bp->s.size += p->s.ptr->s.size;
        bp->s.ptr = p->s.ptr->s.ptr;
    } else
        bp->s.ptr = p->s.ptr;
    if(p + p->s.size == bp){
        p->s.size += bp->s.size;
        p->s.ptr = bp->s.ptr;
    } else
        p->s.ptr = bp;
    freep = p;
}

static unsigned int get_ptr_size(void *ap){
    Header *bp, *p;
    
    bp = (Header*)ap - 1;
    for(p = freep; !(bp > p && bp < p->s.ptr); p = p->s.ptr)
        if(p >= p->s.ptr && (bp > p || bp < p->s.ptr))
            break;
    return p->s.size;
}

static Header*
morecore(uint nu)
{
    char *p;
    Header *hp;
    
    if(nu < 4096)
        nu = 4096;
    p = sbrk(nu * sizeof(Header));
    if(p == (char*)-1)
        return 0;
    hp = (Header*)p;
    hp->s.size = nu;
    free((void*)(hp + 1));
    return freep;
}

void*
malloc(uint nbytes)
{
    Header *p, *prevp;
    uint nunits;
    
    nunits = (nbytes + sizeof(Header) - 1)/sizeof(Header) + 1;
    if((prevp = freep) == 0){
        base.s.ptr = freep = prevp = &base;
        base.s.size = 0;
    }
    for(p = prevp->s.ptr; ; prevp = p, p = p->s.ptr){
        if(p->s.size >= nunits){
            if(p->s.size == nunits)
                prevp->s.ptr = p->s.ptr;
            else {
                p->s.size -= nunits;
                p += p->s.size;
                p->s.size = nunits;
            }
            freep = prevp;
            return (void*)(p + 1);
        }
        if(p == freep)
            if((p = morecore(nunits)) == 0)
                return 0;
    }
}
void* realloc(void* ptr, unsigned int size){
	void* local_ptr = NULL;
	unsigned int old_size = 0;

	if(ptr == NULL) {
		return malloc(size);
	}
	if((size == 0) && (ptr != NULL)) {
		free(ptr);
		return NULL;
	}
	local_ptr = malloc(size);
	old_size = get_ptr_size(ptr);
	memcpy(local_ptr,ptr,old_size>size?size:old_size);
	free(ptr);
	return local_ptr;
}

/*void *
calloc(uint nbytes) {
	void *s = malloc(nbytes);
	if (s == NULL)
		return NULL;
	memset(s, 0, nbytes);
	return s;
}*/


/*********************************************************/

/* defined in sysdeps\unix\sysv\linux\arm\Brk.c */
static void *__curbrk = 0;

int __brk (void *addr) {
    void *newbrk;

    __curbrk = newbrk = (void*)brk(addr);
    if (newbrk < addr) {
        return -1;
    }

    return 0;
}

char* sbrk (intptr_t increment){
    void *oldbrk;

    if (__curbrk == NULL )
        if (__brk (0) < 0)      /* Initialize the break.  */
            return (void *) -1;

    if (increment == 0)
        return __curbrk;

    oldbrk = __curbrk;
    if ((increment > 0
        ? ((uintptr_t) oldbrk + (uintptr_t) increment < (uintptr_t) oldbrk)
        : ((uintptr_t) oldbrk < (uintptr_t) -increment))
        || __brk (oldbrk + increment) < 0)
        return (void *) -1;

    return oldbrk;
}
