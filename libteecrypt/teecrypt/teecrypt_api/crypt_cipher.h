#ifndef CRYPT_CIPHER_H
#define CRYPT_CIPHER_H

#include <tee_api_types.h>
#include <utee_mem.h>
#include <utee_defines.h>
#include "crypt_ctx.h"
#include "crypt_state.h"
#include "crypt_obj.h"

#include "crypt_engine.h"



TEE_Result utee_cipher_init(uint32_t state, const void *iv, size_t iv_len);

TEE_Result utee_cipher_update(uint32_t state, const void *src, size_t src_len,
			      void *dest, size_t *dest_len);

TEE_Result utee_cipher_final(uint32_t state, const void *src, size_t src_len,
			     void *dest, size_t *dest_len);

#endif