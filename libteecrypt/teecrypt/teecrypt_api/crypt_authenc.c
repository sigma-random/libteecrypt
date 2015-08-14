#include "crypt_authenc.h"



TEE_Result utee_authenc_init(uint32_t state, const void *nonce,
				size_t nonce_len, size_t tag_len,
				size_t aad_len, size_t payload_len)
{
	TEE_Result res;
	struct tee_crypt_state *cs;
	struct tee_crypt_ctx *crypt_ctx;
	struct tee_obj *o;
	struct tee_crypt_obj_secret *key;

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

	key = (struct tee_crypt_obj_secret *)o->data;
	res = tee_authenc_init(cs->ctx, cs->algo, cs->mode,
			       (uint8_t *)(key + 1), key->key_size,
			       nonce, nonce_len, tag_len, aad_len, payload_len);
	if (res != TEE_SUCCESS)
		return res;

	cs->ctx_finalize = (tee_crypt_ctx_finalize_func_t)tee_authenc_final;
	return TEE_SUCCESS;
}

TEE_Result utee_authenc_update_aad(uint32_t state, const void *aad_data,
				      size_t aad_data_len)
{
	TEE_Result res;
	struct tee_crypt_state *cs;
	struct tee_crypt_ctx *crypt_ctx;

	res = tee_get_crypt_ctx(&crypt_ctx);
	if (res != TEE_SUCCESS)
		return res;

	res = utee_crypt_get_state(crypt_ctx, state, &cs);
	if (res != TEE_SUCCESS)
		return res;

	res = tee_authenc_update_aad(cs->ctx, cs->algo, cs->mode, aad_data,
				     aad_data_len);
	if (res != TEE_SUCCESS)
		return res;

	return TEE_SUCCESS;
}

TEE_Result utee_authenc_update_payload(uint32_t state, const void *src_data,
					  size_t src_len, void *dst_data,
					  size_t *dst_len)
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


	res = utee_copy_from_user(NULL, &dlen, dst_len, sizeof(size_t));
	if (res != TEE_SUCCESS)
		return res;

	if (dlen < src_len) {
		res = TEE_ERROR_SHORT_BUFFER;
		goto _ret_;
	}

	res = tee_authenc_update_payload(cs->ctx, cs->algo, cs->mode, src_data,
					 src_len, dst_data);

_ret_:
	if (res == TEE_SUCCESS || res == TEE_ERROR_SHORT_BUFFER) {
		TEE_Result res2 = utee_copy_to_user(NULL, dst_len, &src_len,
						       sizeof(size_t));
		if (res2 != TEE_SUCCESS)
			res = res2;
	}

	return res;
}

TEE_Result utee_authenc_enc_final(uint32_t state, const void *src_data,
				     size_t src_len, void *dst_data,
				     size_t *dst_len, void *tag,
				     size_t *tag_len)
{
	TEE_Result res;
	struct tee_crypt_state *cs;
	struct tee_crypt_ctx *crypt_ctx;
	size_t dlen;
	size_t tlen;

	res = tee_get_crypt_ctx(&crypt_ctx);
	if (res != TEE_SUCCESS)
		return res;

	res = utee_crypt_get_state(crypt_ctx, state, &cs);
	if (res != TEE_SUCCESS)
		return res;

	if (cs->mode != TEE_MODE_ENCRYPT)
		return TEE_ERROR_BAD_PARAMETERS;

	if (dst_len == NULL) {
		dlen = 0;
	} else {
		res = utee_copy_from_user(NULL, &dlen, dst_len, sizeof(size_t));
		if (res != TEE_SUCCESS)
			return res;
	}

	if (dlen < src_len) {
		res = TEE_ERROR_SHORT_BUFFER;
		goto _ret_;
	}

	res = utee_copy_from_user(NULL, &tlen, tag_len, sizeof(size_t));
	if (res != TEE_SUCCESS)
		return res;

	res = tee_authenc_enc_final(cs->ctx, cs->algo, src_data, src_len,
				    dst_data, tag, &tlen);

_ret_:
	if (res == TEE_SUCCESS || res == TEE_ERROR_SHORT_BUFFER) {
		TEE_Result res2;

		if (dst_len != NULL) {
			res2 = utee_copy_to_user(NULL, dst_len, &src_len, sizeof(size_t));
			if (res2 != TEE_SUCCESS)
				return res2;
		}

		res2 = utee_copy_to_user(NULL, tag_len, &tlen, sizeof(size_t));
		if (res2 != TEE_SUCCESS)
			return res2;
	}

	return res;
}

TEE_Result utee_authenc_dec_final(uint32_t state, const void *src_data,
				     size_t src_len, void *dst_data,
				     size_t *dst_len, const void *tag,
				     size_t tag_len)
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

	if (cs->mode != TEE_MODE_DECRYPT)
		return TEE_ERROR_BAD_PARAMETERS;

	if (dst_len == NULL) {
		dlen = 0;
	} else {
		res =
		    utee_copy_from_user(NULL, &dlen, dst_len,
					   sizeof(size_t));
		if (res != TEE_SUCCESS)
			return res;
	}

	if (dlen < src_len) {
		res = TEE_ERROR_SHORT_BUFFER;
		goto _ret_;
	}

	res = tee_authenc_dec_final(cs->ctx, cs->algo, src_data, src_len,
				    dst_data, tag, tag_len);

_ret_:
	if ((res == TEE_SUCCESS || res == TEE_ERROR_SHORT_BUFFER) &&
	    dst_len != NULL) {
		TEE_Result res2;

		res2 =
		    utee_copy_to_user(NULL, dst_len, &src_len, sizeof(size_t));
		if (res2 != TEE_SUCCESS)
			return res2;
	}

	return res;
}

