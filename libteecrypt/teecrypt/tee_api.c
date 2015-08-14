/*
 * Copyright (c) 2014, STMicroelectronics International N.V.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */ 

#include <tee_api.h>
#include <utee_api.h>
#include <utee_mem.h>


/* System API - Misc */

void TEE_Panic(TEE_Result panicCode)
{
    utee_printf("exception is generated with code 0x%x\n", (TEE_Result )panicCode);
    /* raise segment fault */ 
    //int *p = 0;
    //*p = 1;
    exit(panicCode);
}


/* System API - Memory Management */

TEE_Result TEE_CheckMemoryAccessRights(uint32_t accessFlags, void *buffer,
				       size_t size)
{
	TEE_Result res;

	return TEE_SUCCESS;
}

void *TEE_MemMove(void *dest, const void *src, uint32_t size)
{
	return utee_mem_move(dest, src, size);
}

int32_t TEE_MemCompare(const void *buffer1, const void *buffer2, uint32_t size)
{
	return utee_mem_cmp(buffer1, buffer2, size);
}

void *TEE_MemFill(void *buff, uint32_t x, uint32_t size)
{
	return utee_mem_fill(buff, x, size);
}


TEE_Result TEE_Wait(uint32_t timeout)
{
	TEE_Result res;

	return TEE_SUCCESS;
}

void *TEE_Malloc(size_t len, uint32_t hint)
{
	return utee_mem_alloc(len);
}

void *TEE_Realloc(void *buffer, uint32_t newSize)
{
	/*
	 * GP TEE Internal API specifies newSize as 'uint32_t'.
	 * use unsigned 'size_t' type. it is at least 32bit!
	 */
	return utee_mem_realloc(buffer, (size_t) newSize);
}

void TEE_Free(void *buffer)
{
	utee_mem_free(buffer);
}
