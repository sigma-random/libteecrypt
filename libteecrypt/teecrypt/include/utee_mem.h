#ifndef UTEE_MEM_H_
#define UTEE_MEM_H_


#include "tee_config.h"
#include "tee_api_types.h"


/* Tee Memory Functions */

void *utee_mem_alloc(size_t len);

void *utee_mem_realloc(void *buffer, size_t len);

void utee_mem_free(void *buffer);

void *utee_mem_move(void *dest, const void *src, uint32_t size);

void *utee_mem_copy(void *dest, const void *src, uint32_t size);

int32_t utee_mem_cmp(const void *buffer1, const void *buffer2, uint32_t size);

void *utee_mem_fill(void *buff, uint32_t x, uint32_t size);

void *utee_mem_calloc(size_t nmemb, size_t size);

TEE_Result utee_copy_to_user(void *sess, void *uaddr, const void *kaddr, size_t len);

TEE_Result utee_copy_from_user(void *sess, void *kaddr, const void *uaddr, size_t len);

TEE_Result utee_mem_hexdump(char *title, unsigned char *data, uint32_t size, uint32_t linenum, bool isUp);

/******************************************************************************
 * By default, the hint of a buffer is 0, means the buffer is fill with 0
 * after its allocation
 */
static const uint32_t DEFAULT_TEE_MALLOC_HINT = 0x0;

/* Hint implementation defines */
#define TEE_TA_MEM_HINT_NO_FILL_ZERO       0x80000000

#endif
