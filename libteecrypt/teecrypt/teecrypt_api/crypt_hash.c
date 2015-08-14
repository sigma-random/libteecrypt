#include "crypt_hash.h"

/* iv and iv_len are ignored for some algorithms */
TEE_Result 
utee_hash_init(uint32_t state, const void *iv, size_t iv_len)
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

	switch (TEE_ALG_GET_CLASS(cs->algo)) {
		case TEE_OPERATION_DIGEST:
			res = tee_hash_init(cs->ctx, cs->algo);
			if (res != TEE_SUCCESS)
				return res;
			break;
		case TEE_OPERATION_MAC: {
			struct tee_obj *o;
			struct tee_crypt_obj_secret *key;

			res = tee_crypt_obj_get(crypt_ctx, cs->key1, &o);
			if (res != TEE_SUCCESS) {
				return res;			
			}
			if ((o->info.handleFlags & TEE_HANDLE_FLAG_INITIALIZED) == 0) {
				return TEE_ERROR_BAD_PARAMETERS;
			}

			key = (struct tee_crypt_obj_secret *)o->data;
			res = tee_mac_init(cs->ctx, cs->algo, (void *)(key + 1),
					   key->key_size);
			if (res != TEE_SUCCESS) {
				return res;
			}
			break;
		}
		default:
			return TEE_ERROR_BAD_PARAMETERS;
	}

	return TEE_SUCCESS;
}


TEE_Result utee_hash_update(uint32_t state, const void *chunk,
			       size_t chunk_size)
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

	switch (TEE_ALG_GET_CLASS(cs->algo)) {
		case TEE_OPERATION_DIGEST:
			res = tee_hash_update(cs->ctx, cs->algo, chunk, chunk_size);
			if (res != TEE_SUCCESS)
				return res;
			break;
		case TEE_OPERATION_MAC:
			res = tee_mac_update(cs->ctx, cs->algo, chunk, chunk_size);
			if (res != TEE_SUCCESS)
				return res;
			break;
		default:
			return TEE_ERROR_BAD_PARAMETERS;
	}

	return TEE_SUCCESS;
}


TEE_Result utee_hash_final(uint32_t state, const void *chunk,
			      size_t chunk_size, void *hash, size_t *hash_len)
{
	TEE_Result res, res2;
	size_t hash_size;
	size_t hlen;
	struct tee_crypt_state *cs;
	struct tee_crypt_ctx *crypt_ctx;

	res = tee_get_crypt_ctx(&crypt_ctx);
	if (res != TEE_SUCCESS)
		return res;

	res = utee_copy_from_user(NULL, &hlen, hash_len, sizeof(size_t));
	if (res != TEE_SUCCESS)
		return res;

	res = utee_crypt_get_state(crypt_ctx, state, &cs);
	if (res != TEE_SUCCESS)
		return res;
	switch (TEE_ALG_GET_CLASS(cs->algo)) {
		case TEE_OPERATION_DIGEST:
			res = tee_hash_get_digest_size(cs->algo, &hash_size);
			if (res != TEE_SUCCESS)
				return res;
			if (*hash_len < hash_size) {
				utee_printf("[err] hash_len[%d] must >= %d Bytes\n", *hash_len, hash_size);
				res = TEE_ERROR_SHORT_BUFFER;
				goto out;
			}

			res = tee_hash_update(cs->ctx, cs->algo, chunk, chunk_size);
			if (res != TEE_SUCCESS)
				return res;
			res = tee_hash_final(cs->ctx, cs->algo, hash, hash_size);
			if (res != TEE_SUCCESS)
				return res;
			break;
		case TEE_OPERATION_MAC:
			res = tee_mac_get_digest_size(cs->algo, &hash_size);
			if (res != TEE_SUCCESS)
				return res;
			if (*hash_len < hash_size) {
				res = TEE_ERROR_SHORT_BUFFER;
				utee_printf("[err] mac_len[%d] must >= %d Bytes\n", *hash_len, hash_size);
				goto out;
			}

			res = tee_mac_final(cs->ctx, cs->algo, chunk, chunk_size, hash, hash_size);
			if (res != TEE_SUCCESS)
				return res;
			break;
		default:
			return TEE_ERROR_BAD_PARAMETERS;
	}
out:
	res2 =
	    utee_copy_to_user(NULL, hash_len, &hash_size, sizeof(*hash_len));
	if (res2 != TEE_SUCCESS)
		return res2;
	
	return res;
}