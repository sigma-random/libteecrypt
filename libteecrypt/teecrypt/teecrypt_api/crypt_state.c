#include "crypt_state.h"
#include "crypt_obj.h"


static void tee_crypt_state_free(struct tee_crypt_ctx *crypt_ctx, struct tee_crypt_state *cs)
{
	struct tee_obj *o;

	if (tee_crypt_obj_get(crypt_ctx, cs->key1, &o) == TEE_SUCCESS) {
		tee_crypt_obj_close(crypt_ctx, o);		
	}
	if (tee_crypt_obj_get(crypt_ctx, cs->key2, &o) == TEE_SUCCESS) {
		tee_crypt_obj_close(crypt_ctx, o);		
	}
	TAILQ_REMOVE(&crypt_ctx->cryp_states, cs, link);
	if (cs->ctx_finalize != NULL) {
		cs->ctx_finalize(cs->ctx, cs->algo);
	}
	utee_mem_free(cs->ctx);
	utee_mem_free(cs);
}


TEE_Result tee_crypt_get_state(struct tee_crypt_ctx *crypt_ctx,
					 uint32_t state_id,
					 struct tee_crypt_state **state)
{
	struct tee_crypt_state *s;

	TAILQ_FOREACH(s, &crypt_ctx->cryp_states, link) {
		if (state_id == (uint32_t) s) {
			*state = s;
			return TEE_SUCCESS;
		}
	}

	return TEE_ERROR_BAD_PARAMETERS;
}

TEE_Result utee_crypt_get_state(void *crypt_ctx,
					 uint32_t state_id,
					 struct tee_crypt_state **state)
{
	return tee_crypt_get_state((struct tee_crypt_ctx *)crypt_ctx,
					 state_id, state);
}


TEE_Result utee_crypt_state_alloc(uint32_t algo, uint32_t mode,
				    uint32_t key1, uint32_t key2,
				    uint32_t *state)
{
	TEE_Result res;
	struct tee_crypt_state *cs;
	struct tee_crypt_ctx *crypt_ctx;
	struct tee_obj *o1 = NULL;
	struct tee_obj *o2 = NULL;

	res = tee_get_crypt_ctx(&crypt_ctx);
	if (res != TEE_SUCCESS)
		return res;
	if (key1 != 0) {
		res = tee_crypt_obj_get(crypt_ctx, key1, &o1);
		if (res != TEE_SUCCESS)
			return res;
		if (o1->busy)
			return TEE_ERROR_BAD_PARAMETERS;
		res = tee_crypt_check_key_type(o1, algo, mode);
		if (res != TEE_SUCCESS)
			return res;
	}
	if (key2 != 0) {
		res = tee_crypt_obj_get(crypt_ctx, key2, &o2);
		if (res != TEE_SUCCESS)
			return res;
		if (o2->busy)
			return TEE_ERROR_BAD_PARAMETERS;
		res = tee_crypt_check_key_type(o2, algo, mode);
		if (res != TEE_SUCCESS)
			return res;
	}
	cs = utee_mem_calloc(1, sizeof(struct tee_crypt_state));
	if (cs == NULL)
		return TEE_ERROR_OUT_OF_MEMORY;
	TAILQ_INSERT_TAIL(&crypt_ctx->cryp_states, cs, link);
	cs->algo = algo;
	cs->mode = mode;
	switch (TEE_ALG_GET_CLASS(algo)) {	
		case TEE_OPERATION_CIPHER:
			if ((algo == TEE_ALG_AES_XTS && (key1 == 0 || key2 == 0)) ||
			    (algo != TEE_ALG_AES_XTS && (key1 == 0 || key2 != 0))) {
				res = TEE_ERROR_BAD_PARAMETERS;
			} else {
				res = tee_cipher_get_ctx_size(algo, &cs->ctx_size);
				if (res != TEE_SUCCESS)
					break;
				cs->ctx = utee_mem_calloc(1, cs->ctx_size);
				if (cs->ctx == NULL)
					res = TEE_ERROR_OUT_OF_MEMORY;
			}
			break;
		case TEE_OPERATION_AE:
			if (key1 == 0 || key2 != 0) {
				res = TEE_ERROR_BAD_PARAMETERS;
			} else {
				res = tee_authenc_get_ctx_size(algo, &cs->ctx_size);
				if (res != TEE_SUCCESS)
					break;
				cs->ctx = utee_mem_calloc(1, cs->ctx_size);
				if (cs->ctx == NULL)
					res = TEE_ERROR_OUT_OF_MEMORY;
			}
			break;
		case TEE_OPERATION_MAC:
			if (key1 == 0 || key2 != 0) {
				res = TEE_ERROR_BAD_PARAMETERS;
			} else {
				res = tee_mac_get_ctx_size(algo, &cs->ctx_size);
				if (res != TEE_SUCCESS)
					break;
				cs->ctx = utee_mem_calloc(1, cs->ctx_size);
				if (cs->ctx == NULL)
					res = TEE_ERROR_OUT_OF_MEMORY;
			}
			break;
		case TEE_OPERATION_DIGEST:
			if (key1 != 0 || key2 != 0) {
				res = TEE_ERROR_BAD_PARAMETERS;
			} else {
				res = tee_hash_get_ctx_size(algo, &cs->ctx_size);
				if (res != TEE_SUCCESS)
					break;
				cs->ctx = utee_mem_calloc(1, cs->ctx_size);
				if (cs->ctx == NULL)
					res = TEE_ERROR_OUT_OF_MEMORY;
			}
			break;
		case TEE_OPERATION_ASYMMETRIC_CIPHER:
		case TEE_OPERATION_ASYMMETRIC_SIGNATURE:
			if (key1 == 0 || key2 != 0)
				res = TEE_ERROR_BAD_PARAMETERS;
			break;
		case TEE_OPERATION_KEY_DERIVATION:
			if (key1 == 0 || key2 != 0)
				res = TEE_ERROR_BAD_PARAMETERS;
			break;
		default:
			res = TEE_ERROR_NOT_SUPPORTED;
			break;
	}
	if (res != TEE_SUCCESS)
		goto _ret_;
	res = utee_copy_to_user(NULL, state, &cs, sizeof(uint32_t));
	if (res != TEE_SUCCESS)
		goto _ret_;
	/* Register keys */
	if (o1 != NULL) {
		o1->busy = true;
		cs->key1 = key1;
	}
	if (o2 != NULL) {
		o2->busy = true;
		cs->key2 = key2;
	}

_ret_:
	if (res != TEE_SUCCESS)
		tee_crypt_state_free(crypt_ctx, cs);

	return res;
}



TEE_Result utee_crypt_state_free(uint32_t state)
{
	TEE_Result res;
	struct tee_crypt_state *cs;
	struct tee_crypt_ctx *crypt_ctx;

	res = tee_get_crypt_ctx(&crypt_ctx);
	if (res != TEE_SUCCESS)
		return res;
	res = tee_crypt_get_state(crypt_ctx, state, &cs);
	if (res != TEE_SUCCESS)
		return res;
	tee_crypt_state_free(crypt_ctx, cs);

	return TEE_SUCCESS;
}


TEE_Result utee_crypt_state_copy(uint32_t dst, uint32_t src)
{
	return TEE_SUCCESS;
}


