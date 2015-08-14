#ifndef CRYPT_HASH_H
#define CRYPT_HASH_H

#include <tee_api_types.h>
#include <utee_mem.h>
#include <utee_defines.h>

#include "crypt_state.h"
#include "crypt_ctx.h"
#include "crypt_obj.h"
#include "crypt_engine.h"

/* iv and iv_len are ignored for some algorithms */
TEE_Result 
utee_hash_init(uint32_t state, const void *iv, size_t iv_len);

TEE_Result 
utee_hash_update(uint32_t state, const void *chunk,size_t chunk_size);

TEE_Result 
utee_hash_final(uint32_t state, const void *chunk,
			   size_t chunk_size, void *hash, size_t *hash_len);

#endif