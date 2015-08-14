#include "crypt_ctx.h"


//static struct tee_crypt_ctx_head ta_crypt_ctxes = TAILQ_HEAD_INITIALIZER(ta_crypt_ctxes);

//global crypto context
static struct tee_crypt_ctx  *ta_crypt_ctx = NULL;


TEE_Result tee_init_crypt_ctx( )
{
	//TEE_STDOUT("tee_init_crypt_ctx\n");
	struct tee_crypt_ctx *crypt_ctx = NULL;
	crypt_ctx = utee_mem_alloc(sizeof(*crypt_ctx));
	if(NULL == crypt_ctx) {
		return TEE_ERROR_OUT_OF_MEMORY;
	}
	TAILQ_INIT(&crypt_ctx->cryp_states);
	TAILQ_INIT(&crypt_ctx->objects);
	crypt_ctx->ref_count = 1;
	//TAILQ_INSERT_TAIL(&ta_crypt_ctxes, crypt_ctx, link);
	ta_crypt_ctx = crypt_ctx;
	//TEE_STDOUT("ta_crypt_ctx : 0x%08x\n",ta_crypt_ctx);


	/* Libtomcrypt initialization */
	tee_ltc_init();

	return TEE_SUCCESS;
}

TEE_Result tee_fini_crypt_ctx( )
{
	//TEE_STDOUT("tee_fini_crypt_ctx\n");

	if (ta_crypt_ctx == NULL) {
		return TEE_ERROR_BAD_STATE;
	}
	utee_mem_free((void*)ta_crypt_ctx);
	ta_crypt_ctx = NULL;

	return TEE_SUCCESS;
}


TEE_Result tee_get_crypt_ctx(struct tee_crypt_ctx **crypt_ctx)
{
	//TEE_STDOUT("tee_get_crypt_ctx\n");

	if(crypt_ctx == NULL) {
		return TEE_ERROR_BAD_PARAMETERS;
	}
		
	if (ta_crypt_ctx == NULL) {
		return TEE_ERROR_BAD_STATE;
	}
	*crypt_ctx = ta_crypt_ctx;
	
	return TEE_SUCCESS;
}

TEE_Result tee_set_crypt_ctx(struct tee_crypt_ctx *crypt_ctx)
{
	if(crypt_ctx == NULL) {
		return TEE_ERROR_BAD_PARAMETERS;
	}
		
	if (ta_crypt_ctx == NULL) {
		return TEE_ERROR_BAD_STATE;
	}

	ta_crypt_ctx = crypt_ctx;

	return TEE_SUCCESS;
}

