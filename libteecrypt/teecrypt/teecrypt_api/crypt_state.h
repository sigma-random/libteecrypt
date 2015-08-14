#ifndef CRYPT_STATE_H
#define CRYPT_STATE_H

#include <tee_api_types.h>
#include <tee_queue.h>
#include <utee_mem.h>

#include "crypt_ctx.h"
#include "crypt_engine.h"


typedef void (*tee_crypt_ctx_finalize_func_t) (void *ctx, uint32_t algo);


struct tee_crypt_state {
	TAILQ_ENTRY(tee_crypt_state) link;
	uint32_t algo;
	uint32_t mode;
	uint32_t key1;
	uint32_t key2;
	size_t ctx_size;
	void *ctx;
	tee_crypt_ctx_finalize_func_t ctx_finalize;
};


/* */
TEE_Result utee_crypt_state_alloc(uint32_t algo, uint32_t op_mode,
				 uint32_t key1, uint32_t key2,
				 uint32_t *state);

TEE_Result utee_crypt_state_copy(uint32_t dst, uint32_t src);

TEE_Result utee_crypt_state_free(uint32_t state);

TEE_Result utee_crypt_get_state(void *crypt_ctx,
					 uint32_t state_id,
					 struct tee_crypt_state **state);

#endif