#include "crypt_cipher.h"

TEE_Result utee_cipher_init(uint32_t state, const void *iv, size_t iv_len)
{
	TEE_Result res;
	struct tee_crypt_state *cs;
	struct tee_crypt_ctx *crypt_ctx;
	struct tee_obj *o;
	struct tee_crypt_obj_secret *key1;

	res = tee_get_crypt_ctx(&crypt_ctx);
	if (res != TEE_SUCCESS)
		return res;

	res = utee_crypt_get_state(crypt_ctx, state, &cs);
	if (res != TEE_SUCCESS)
		return res;

	res = tee_crypt_obj_get(crypt_ctx, cs->key1, &o);
	if (res != TEE_SUCCESS)
		return res;

	if ((o->info.handleFlags & TEE_HANDLE_FLAG_INITIALIZED) == 0)
		return TEE_ERROR_BAD_PARAMETERS;

	key1 = (struct tee_crypt_obj_secret *)o->data;
	//utee_mem_hexdump("cs->key1",(void*)(uint8_t *)(key1 + 1),*(uint8_t *)(key1),16,1);
	//utee_mem_hexdump("cs->ctx", cs->ctx, cs->ctx_size,16,1);
	if (tee_crypt_obj_get(crypt_ctx, cs->key2, &o) == TEE_SUCCESS) {
		struct tee_crypt_obj_secret *key2 =
		    (struct tee_crypt_obj_secret *)o->data;

		if ((o->info.handleFlags & TEE_HANDLE_FLAG_INITIALIZED) == 0)
			return TEE_ERROR_BAD_PARAMETERS;

		res = tee_cipher_init3(cs->ctx, cs->algo, cs->mode,
				       (uint8_t *)(key1 + 1), key1->key_size,
				       (uint8_t *)(key2 + 1), key2->key_size,
				       iv, iv_len);
	} else {
		res = tee_cipher_init2(cs->ctx, cs->algo, cs->mode,
			       (uint8_t *)(key1 + 1), key1->key_size,
				       iv, iv_len);
	}
	if (res != TEE_SUCCESS)
		return res;
	
	cs->ctx_finalize = (tee_crypt_ctx_finalize_func_t) tee_cipher_final;

	return TEE_SUCCESS;
}




static TEE_Result tee_cipher_update_helper(uint32_t state, bool last_block,
					       const void *src, size_t src_len,
					       void *dst, size_t *dst_len)
{
	TEE_Result res;
	struct tee_crypt_state *cs;
	struct tee_crypt_ctx *crypt_ctx;
	size_t dlen;

	res = tee_get_crypt_ctx(&crypt_ctx);
	if (res != TEE_SUCCESS)
		return res;

	res = utee_crypt_get_state(crypt_ctx, state, &cs);
	if (res != TEE_SUCCESS)
		return res;

	if (dst_len == NULL) {
		dlen = 0;
	} 
	else {
		res = utee_copy_from_user(NULL, &dlen, dst_len, sizeof(size_t));
		if (res != TEE_SUCCESS)
			return res;
	}

	if (dlen < src_len) {
		res = TEE_ERROR_SHORT_BUFFER;
		goto _ret_;
	}

	if (src_len > 0) {
		/* Permit src_len == 0 to finalize the operation */
		res = tee_cipher_update(cs->ctx, cs->algo, cs->mode, last_block,
					src, src_len, dst);
	}
	if (last_block && cs->ctx_finalize != NULL) {
		cs->ctx_finalize(cs->ctx, cs->algo);
		cs->ctx_finalize = NULL;
	}

_ret_:
	if ((res == TEE_SUCCESS || res == TEE_ERROR_SHORT_BUFFER) &&
	    dst_len != NULL) {
		TEE_Result res2 = utee_copy_to_user(NULL, dst_len, &src_len,
						       sizeof(size_t));
		if (res2 != TEE_SUCCESS)
			res = res2;
	}

	return res;
}

TEE_Result utee_cipher_update(uint32_t state, const void *src,
				 size_t src_len, void *dst, size_t *dst_len)
{
	return tee_cipher_update_helper(state, false /* last_block */,
					    src, src_len, dst, dst_len);
}

TEE_Result utee_cipher_final(uint32_t state, const void *src,
				size_t src_len, void *dst, size_t *dst_len)
{
	return tee_cipher_update_helper(state, true /* last_block */,
					    src, src_len, dst, dst_len);
}