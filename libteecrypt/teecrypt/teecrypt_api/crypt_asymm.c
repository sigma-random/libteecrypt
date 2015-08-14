#include "crypt_asymm.h"


static void tee_asymm_pkcs1_get_salt_len(const TEE_Attribute *params,
					     uint32_t num_params, int *salt_len)
{
	size_t n;

	for (n = 0; n < num_params; n++) {
		if (params[n].attributeID == TEE_ATTR_RSA_PSS_SALT_LENGTH) {
			*salt_len = params[n].content.value.a;
			return;
		}
	}
	*salt_len = -1;
}


static TEE_Result tee_asymm_rsa_check_crt_exist(struct tee_obj *o,
						    bool *crt_exist)
{
	const struct tee_crypt_obj_type_props *type_props;
	int i;

	type_props = tee_find_crypt_obj_type_props(o->info.objectType);
	if (type_props == NULL)
		return TEE_ERROR_BAD_PARAMETERS;

	/*
	 * if one crt attribute exits all must exists and this is
	 * checked when populating it
	 */
	i = tee_crypt_obj_find_type_attr_idx(TEE_ATTR_RSA_PRIME1,
		type_props);

	if ((o->have_attrs & (1 << i)) != 0)
		*crt_exist = true;
	else
		*crt_exist = false;

	return TEE_SUCCESS;
}


TEE_Result utee_asymm_operate(uint32_t state, const TEE_Attribute *params,
				 uint32_t num_params, const void *src_data,
				 size_t src_len, void *dst_data,
				 size_t *dst_len)
{
	TEE_Result res;
	struct tee_crypt_state *cs;
	struct tee_crypt_ctx *crypt_ctx;
	size_t dlen;
	struct tee_obj *o;
	struct tee_rsa_public_key *tee_rsa_public_key;
	struct tee_rsa_key_pair *tee_rsa_key_pair;
	struct tee_dsa_key_pair *tee_dsa_key;
	union {
		rsa_key ltc_rsa_key;
		dsa_key ltc_dsa_key;
	} key_type;
	void *label = NULL;
	size_t label_len = 0;
	size_t n;
	bool crt_exist;
	int salt_len;

	res = tee_get_crypt_ctx(&crypt_ctx);
	if (res != TEE_SUCCESS)
		return res;

	res = utee_crypt_get_state(crypt_ctx, state, &cs);
	if (res != TEE_SUCCESS)
		return res;


	res = utee_copy_from_user(NULL, &dlen, dst_len, sizeof(size_t));
	if (res != TEE_SUCCESS)
		return res;

	res = tee_crypt_obj_get(crypt_ctx, cs->key1, &o);
	if (res != TEE_SUCCESS)
		return res;
	if ((o->info.handleFlags & TEE_HANDLE_FLAG_INITIALIZED) == 0)
		return TEE_ERROR_BAD_PARAMETERS;
	switch (cs->algo) {
		case TEE_ALG_RSA_NOPAD:
			if (cs->mode == TEE_MODE_ENCRYPT) {
				tee_rsa_public_key = o->data;
				tee_populate_rsa_public_key(
					&key_type.ltc_rsa_key, tee_rsa_public_key);
			} else if (cs->mode == TEE_MODE_DECRYPT) {
				tee_rsa_key_pair = o->data;
				res = tee_asymm_rsa_check_crt_exist(o, &crt_exist);
				if (res != TEE_SUCCESS)
					return res;
				tee_populate_rsa_key_pair(
					&key_type.ltc_rsa_key, tee_rsa_key_pair,
					crt_exist);

			} else {
				res = TEE_ERROR_BAD_PARAMETERS;
			}

			res = tee_acipher_rsadorep(
				&key_type.ltc_rsa_key,
				src_data, src_len, dst_data, &dlen);
			break;

		case TEE_ALG_RSAES_PKCS1_V1_5:
		case TEE_ALG_RSAES_PKCS1_OAEP_MGF1_SHA1:
		case TEE_ALG_RSAES_PKCS1_OAEP_MGF1_SHA224:
		case TEE_ALG_RSAES_PKCS1_OAEP_MGF1_SHA256:
		case TEE_ALG_RSAES_PKCS1_OAEP_MGF1_SHA384:
		case TEE_ALG_RSAES_PKCS1_OAEP_MGF1_SHA512:
			for (n = 0; n < num_params; n++) {
				if (params[n].attributeID == TEE_ATTR_RSA_OAEP_LABEL) {
					label = params[n].content.ref.buffer;
					label_len = params[n].content.ref.length;
					break;
				}
			}

			if (cs->mode == TEE_MODE_ENCRYPT) {
				tee_rsa_public_key = o->data;
				tee_populate_rsa_public_key(
					&key_type.ltc_rsa_key, tee_rsa_public_key);
				res = tee_acipher_rsaes_encrypt(
					cs->algo, &key_type.ltc_rsa_key,
					label, label_len,
					src_data, src_len, dst_data, &dlen);
			} else if (cs->mode == TEE_MODE_DECRYPT) {
				tee_rsa_key_pair = o->data;
				res = tee_asymm_rsa_check_crt_exist(o, &crt_exist);
				if (res != TEE_SUCCESS)
					return res;

				tee_populate_rsa_key_pair(
					&key_type.ltc_rsa_key,
					tee_rsa_key_pair, crt_exist);
				res = tee_acipher_rsaes_decrypt(
					cs->algo, &key_type.ltc_rsa_key,
					label, label_len,
					src_data, src_len, dst_data, &dlen);
			} else {
				res = TEE_ERROR_BAD_PARAMETERS;
			}
			break;

		case TEE_ALG_RSASSA_PKCS1_V1_5_MD5:
		case TEE_ALG_RSASSA_PKCS1_V1_5_SHA1:
		case TEE_ALG_RSASSA_PKCS1_V1_5_SHA224:
		case TEE_ALG_RSASSA_PKCS1_V1_5_SHA256: 
		case TEE_ALG_RSASSA_PKCS1_V1_5_SHA384:
		case TEE_ALG_RSASSA_PKCS1_V1_5_SHA512:
		case TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA1:
		case TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA224:
		case TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA256:
		case TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA384:
		case TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA512:
			if (cs->mode != TEE_MODE_SIGN) {
				res = TEE_ERROR_BAD_PARAMETERS;
				break;
			}
			tee_rsa_key_pair = o->data;
			res = tee_asymm_rsa_check_crt_exist(o, &crt_exist);
			if (res != TEE_SUCCESS)
				return res;

			tee_populate_rsa_key_pair( &key_type.ltc_rsa_key, tee_rsa_key_pair, crt_exist);

			tee_asymm_pkcs1_get_salt_len(params, num_params, &salt_len);

			res = tee_acipher_rsassa_sign( cs->algo, &key_type.ltc_rsa_key, salt_len,
											src_data, src_len, dst_data, &dlen);
			break;

		case TEE_ALG_DSA_SHA1:
			tee_dsa_key = o->data;
			tee_populate_dsa_key_pair(&key_type.ltc_dsa_key, tee_dsa_key);
			res = tee_acipher_dsa_sign(
				cs->algo, &key_type.ltc_dsa_key,
				src_data, src_len, dst_data, &dlen);
			break;

		default:
			res = TEE_ERROR_BAD_PARAMETERS;
			break;
	}

	if (res == TEE_SUCCESS || res == TEE_ERROR_SHORT_BUFFER) {
		TEE_Result res2;
		res2 = utee_copy_to_user(NULL, dst_len, &dlen, sizeof(size_t));
		if (res2 != TEE_SUCCESS)
			return res2;
	}

	return res;
}

TEE_Result utee_asymm_verify(uint32_t state, const TEE_Attribute *params,
				uint32_t num_params, const void *data,
				size_t data_len, const void *sig, size_t sig_len)
{
	TEE_Result res;
	struct tee_crypt_state *cs;
	struct tee_crypt_ctx *crypt_ctx;
	struct tee_obj *o;
	size_t hash_size;
	struct tee_rsa_public_key *tee_rsa_key;
	int salt_len;
	struct tee_dsa_public_key *tee_dsa_key;
	union {
		rsa_key ltc_rsa_key;
		dsa_key ltc_dsa_key;
	} key_type;

	res = tee_get_crypt_ctx(&crypt_ctx);
	if (res != TEE_SUCCESS)
		return res;

	res = utee_crypt_get_state(crypt_ctx, state, &cs);
	if (res != TEE_SUCCESS)
		return res;

	if (cs->mode != TEE_MODE_VERIFY)
		return TEE_ERROR_BAD_PARAMETERS;

	res = tee_crypt_obj_get(crypt_ctx, cs->key1, &o);
	if (res != TEE_SUCCESS)
		return res;
	if ((o->info.handleFlags & TEE_HANDLE_FLAG_INITIALIZED) == 0)
		return TEE_ERROR_BAD_PARAMETERS;

	res = tee_hash_get_digest_size(TEE_DIGEST_HASH_TO_ALGO(cs->algo), &hash_size);
	if (res != TEE_SUCCESS)
		return res;
	
	//TEE_STDOUT("[info] tee_hash_get_digest_size::hash_size = 0x%08x\n",hash_size);

	if (data_len != hash_size)
		return TEE_ERROR_BAD_PARAMETERS;

	switch (TEE_ALG_GET_MAIN_ALG(cs->algo)) {
		case TEE_MAIN_ALGO_RSA:
			tee_rsa_key = o->data;
			tee_asymm_pkcs1_get_salt_len(params, num_params, &salt_len);
			tee_populate_rsa_public_key(&key_type.ltc_rsa_key, tee_rsa_key);
			res = tee_acipher_rsassa_verify( cs->algo, &key_type.ltc_rsa_key, salt_len,
										data, data_len, sig, sig_len);
			break;

		case TEE_MAIN_ALGO_DSA:
			tee_dsa_key = o->data;
			tee_populate_dsa_public_key(&key_type.ltc_dsa_key, tee_dsa_key);
			res = tee_acipher_dsa_verify(
				cs->algo, &key_type.ltc_dsa_key,
				data, data_len, sig, sig_len);
			break;

		default:
			res = TEE_ERROR_NOT_SUPPORTED;
	}

	return res;
}
