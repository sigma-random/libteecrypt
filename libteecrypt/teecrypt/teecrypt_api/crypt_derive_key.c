#include "crypt_derive_key.h"

TEE_Result utee_crypt_derive_key(uint32_t state, const TEE_Attribute *params,
				   uint32_t param_count, uint32_t derived_key)
{
	TEE_Result res;
	struct tee_crypt_ctx *crypt_ctx;
	struct tee_obj *ko;
	struct tee_obj *so;
	struct tee_crypt_state *cs;
	struct tee_crypt_obj_secret *sk;
	const struct tee_crypt_obj_type_props *type_props;
	struct tee_bignumbers publicvalue;
	struct tee_bignumbers sharedsecret;
	struct tee_dh_key_pair *tee_dh_key;
	dh_key ltc_dh_key;

	res = tee_get_crypt_ctx(&crypt_ctx);
	if (res != TEE_SUCCESS)
		return res;

	res = utee_crypt_get_state(crypt_ctx, state, &cs);
	if (res != TEE_SUCCESS)
		return res;

	if ((param_count != 1) ||
	    (params[0].attributeID != TEE_ATTR_DH_PUBLIC_VALUE))
		return TEE_ERROR_BAD_PARAMETERS;

	/* get key set in operation */
	res = tee_crypt_obj_get(crypt_ctx, cs->key1, &ko);
	if (res != TEE_SUCCESS)
		return res;

	tee_dh_key = (struct tee_dh_key_pair *)ko->data;
	tee_populate_dh_key_pair(&ltc_dh_key, tee_dh_key);

	res = tee_crypt_obj_get(crypt_ctx, derived_key, &so);
	if (res != TEE_SUCCESS)
		return res;

	/* find information needed about the object to initialize */
	sk = (struct tee_crypt_obj_secret *)so->data;

	/* Find description of object */
	type_props = tee_find_crypt_obj_type_props(so->info.objectType);
	if (type_props == NULL)
		return TEE_ERROR_NOT_SUPPORTED;

	SET_MPA_ALLOCSIZE(&publicvalue);
	SET_MPA_ALLOCSIZE(&sharedsecret);

	/* extract information from the attributes passed to the function */
	mp_read_unsigned_bin(
		&publicvalue,
		params[0].content.ref.buffer,
		params[0].content.ref.length);
	res = tee_derive_dh_shared_secret(
		&ltc_dh_key, &publicvalue, &sharedsecret);

	if (res == TEE_SUCCESS) {
		sk->key_size = mp_unsigned_bin_size(&sharedsecret);
		mp_to_unsigned_bin(&sharedsecret, (uint8_t *)(sk + 1));
		so->info.handleFlags |= TEE_HANDLE_FLAG_INITIALIZED;
		SET_ATTRIBUTE(so, type_props, TEE_ATTR_SECRET_VALUE);
	}
	return res;
}