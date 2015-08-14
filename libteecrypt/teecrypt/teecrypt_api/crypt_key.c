#include "crypt_obj.h"


static void tee_dump_ltc_rsa_public_key(void *rsa_public_key, uint32_t rsaKeyBits, uint32_t rawdata)
{
	uint32_t rsa_key_size;
	uint32_t key_offset ;
	uint32_t key_hdr_size;
	struct tee_rsa_public_key *tee_ltc_rsa_public_key = (struct tee_rsa_public_key*)rsa_public_key;

	key_hdr_size = sizeof(tee_ltc_rsa_public_key->N.alloc) + sizeof(tee_ltc_rsa_public_key->N.size);
	if( 1 == rawdata) {		//raw key data 
		utee_printf("\n[RAW_RSA_KEY]\n");
		key_offset = 0;
		utee_mem_hexdump("RSA_PubKey::e", (void*)&tee_ltc_rsa_public_key->e + key_offset,
						key_hdr_size + tee_ltc_rsa_public_key->e.size * sizeof(tee_ltc_rsa_public_key->e.d[0]), 16, true);
		utee_mem_hexdump("RSA_PubKey::N", (void*)&tee_ltc_rsa_public_key->N + key_offset,
						key_hdr_size + tee_ltc_rsa_public_key->N.size * sizeof(tee_ltc_rsa_public_key->N.d[0]), 16, true);
	} else {
		key_offset = key_hdr_size;
		/* dump in reverse */
		utee_mem_hexdump("RSA_PubKey::e", (void*)&tee_ltc_rsa_public_key->e + key_offset, 
						tee_ltc_rsa_public_key->e.size * sizeof(tee_ltc_rsa_public_key->e.d[0]), 16, false);
		utee_mem_hexdump("RSA_PubKey::N", (void*)&tee_ltc_rsa_public_key->N + key_offset,
						tee_ltc_rsa_public_key->N.size * sizeof(tee_ltc_rsa_public_key->N.d[0]), 16, false);
	}
}

static void tee_dump_ltc_rsa_key_pair(void *rsa_key, uint32_t rsaKeyBits, uint32_t rawdata)
{
	uint32_t rsa_key_size;
	uint32_t key_offset ;
	uint32_t key_hdr_size;
	struct tee_rsa_key_pair *tee_ltc_rsa_key_pair = (struct tee_rsa_key_pair*)rsa_key;

	key_hdr_size = sizeof(tee_ltc_rsa_key_pair->N.alloc) + sizeof(tee_ltc_rsa_key_pair->N.size);

	if( 1 == rawdata) {		//raw key data , 8 prefix  bits
		utee_printf("\n[RAW_RSA_KEY]\n");
		key_offset = 0;
		utee_mem_hexdump("RSA_Key::e", (void*)&tee_ltc_rsa_key_pair->e + key_offset,
						key_hdr_size + tee_ltc_rsa_key_pair->e.size * sizeof(tee_ltc_rsa_key_pair->e.d[0]), 16, true);
		utee_mem_hexdump("RSA_Key::d", (void*)&tee_ltc_rsa_key_pair->d + key_offset,
						key_hdr_size + tee_ltc_rsa_key_pair->d.size * sizeof(tee_ltc_rsa_key_pair->d.d[0]), 16, true);
		utee_mem_hexdump("RSA_Key::N", (void*)&tee_ltc_rsa_key_pair->N + key_offset,
						key_hdr_size + tee_ltc_rsa_key_pair->N.size * sizeof(tee_ltc_rsa_key_pair->N.d[0]), 16, true);
		utee_mem_hexdump("RSA_Key::p", (void*)&tee_ltc_rsa_key_pair->p + key_offset,
						key_hdr_size + tee_ltc_rsa_key_pair->p.size * sizeof(tee_ltc_rsa_key_pair->p.d[0]), 16, true);
		utee_mem_hexdump("RSA_Key::q", (void*)&tee_ltc_rsa_key_pair->q + key_offset,
						key_hdr_size + tee_ltc_rsa_key_pair->q.size * sizeof(tee_ltc_rsa_key_pair->q.d[0]), 16, true);
		utee_mem_hexdump("RSA_Key::qP", (void*)&tee_ltc_rsa_key_pair->qP + key_offset,
						key_hdr_size + tee_ltc_rsa_key_pair->qP.size * sizeof(tee_ltc_rsa_key_pair->qP.d[0]), 16, true);
		utee_mem_hexdump("RSA_Key::dP", (void*)&tee_ltc_rsa_key_pair->dP + key_offset,
						key_hdr_size + tee_ltc_rsa_key_pair->dP.size * sizeof(tee_ltc_rsa_key_pair->dP.d[0]), 16, true);
		utee_mem_hexdump("RSA_Key::dQ", (void*)&tee_ltc_rsa_key_pair->dQ + key_offset,
						key_hdr_size + tee_ltc_rsa_key_pair->dQ.size * sizeof(tee_ltc_rsa_key_pair->dQ.d[0]), 16, true);
	}else {
		key_offset = key_hdr_size;
		/* dump in reverse */
		utee_mem_hexdump("RSA_Key::e", (void*)&tee_ltc_rsa_key_pair->e + key_offset,
						tee_ltc_rsa_key_pair->e.size * sizeof(tee_ltc_rsa_key_pair->e.d[0]), 16, false);
		utee_mem_hexdump("RSA_Key::d", (void*)&tee_ltc_rsa_key_pair->d + key_offset,
						tee_ltc_rsa_key_pair->d.size * sizeof(tee_ltc_rsa_key_pair->d.d[0]), 16, false);
		utee_mem_hexdump("RSA_Key::N", (void*)&tee_ltc_rsa_key_pair->N + key_offset,
						tee_ltc_rsa_key_pair->N.size * sizeof(tee_ltc_rsa_key_pair->N.d[0]), 16, false);
		utee_mem_hexdump("RSA_Key::p", (void*)&tee_ltc_rsa_key_pair->p + key_offset,
						tee_ltc_rsa_key_pair->p.size * sizeof(tee_ltc_rsa_key_pair->p.d[0]), 16, false);
		utee_mem_hexdump("RSA_Key::q", (void*)&tee_ltc_rsa_key_pair->q + key_offset,
						tee_ltc_rsa_key_pair->q.size * sizeof(tee_ltc_rsa_key_pair->q.d[0]), 16, false);
		utee_mem_hexdump("RSA_Key::qP", (void*)&tee_ltc_rsa_key_pair->qP + key_offset,
						tee_ltc_rsa_key_pair->qP.size * sizeof(tee_ltc_rsa_key_pair->qP.d[0]), 16, false);
		utee_mem_hexdump("RSA_Key::dP", (void*)&tee_ltc_rsa_key_pair->dP + key_offset,
						tee_ltc_rsa_key_pair->dP.size * sizeof(tee_ltc_rsa_key_pair->dP.d[0]), 16, false);
		utee_mem_hexdump("RSA_Key::dQ", (void*)&tee_ltc_rsa_key_pair->dQ + key_offset,
						tee_ltc_rsa_key_pair->dQ.size * sizeof(tee_ltc_rsa_key_pair->dQ.d[0]), 16, false);

	}
}


TEE_Result utee_dump_ltc_rsa_key_obj(uint32_t hKeyObject, uint32_t rsaKeyBits, 
					bool isRsaKeyPair, uint32_t rawdata) {
	
	TEE_Result res;

	if(!hKeyObject) {
		_PANIC_LOG_(TEE_ERROR_BAD_PARAMETERS);
		return TEE_ERROR_BAD_PARAMETERS;
	}
	struct tee_crypt_ctx *crypt_ctx;
	struct tee_obj *rsa_key_obj;

	res = tee_get_crypt_ctx(&crypt_ctx);
	if (res != TEE_SUCCESS) {
		_PANIC_LOG_(res);
		return res;		
	}

	res = tee_crypt_obj_get(crypt_ctx, hKeyObject, &rsa_key_obj);
	if (res != TEE_SUCCESS) {
		_PANIC_LOG_(res);
		return res;		
	}

	if(isRsaKeyPair) {
		tee_dump_ltc_rsa_key_pair(rsa_key_obj->data, rsaKeyBits, rawdata);
	}else {
		tee_dump_ltc_rsa_public_key(rsa_key_obj->data, rsaKeyBits, rawdata);		
	}

	return TEE_SUCCESS;

}


TEE_Result tee_crypt_check_key_type(const struct tee_obj *o,
					      uint32_t algo,
					      TEE_OperationMode mode)
{
	TEE_Result res;
	uint32_t req_key_type;

	switch (TEE_ALG_GET_MAIN_ALG(algo)) {
	case TEE_MAIN_ALGO_MD5:
		req_key_type = TEE_TYPE_HMAC_MD5;
		break;
	case TEE_MAIN_ALGO_SHA1:
		req_key_type = TEE_TYPE_HMAC_SHA1;
		break;
	case TEE_MAIN_ALGO_SHA224:
		req_key_type = TEE_TYPE_HMAC_SHA224;
		break;
	case TEE_MAIN_ALGO_SHA256:
		req_key_type = TEE_TYPE_HMAC_SHA256;
		break;
	case TEE_MAIN_ALGO_SHA384:
		req_key_type = TEE_TYPE_HMAC_SHA384;
		break;
	case TEE_MAIN_ALGO_SHA512:
		req_key_type = TEE_TYPE_HMAC_SHA512;
		break;
	case TEE_MAIN_ALGO_AES:
		req_key_type = TEE_TYPE_AES;
		break;
	case TEE_MAIN_ALGO_DES:
		req_key_type = TEE_TYPE_DES;
		break;
	case TEE_MAIN_ALGO_DES3:
		req_key_type = TEE_TYPE_DES3;
		break;
	
	case TEE_MAIN_ALGO_SM_SMS4:
		req_key_type = TEE_TYPE_SM_SMS4;
		break;


	case TEE_MAIN_ALGO_RSA:
		if (mode == TEE_MODE_ENCRYPT || mode == TEE_MODE_VERIFY)
			req_key_type = TEE_TYPE_RSA_PUBLIC_KEY;
		else
			req_key_type = TEE_TYPE_RSA_KEYPAIR;
		break;

	case TEE_MAIN_ALGO_DSA:
		if (mode == TEE_MODE_ENCRYPT || mode == TEE_MODE_VERIFY)
			req_key_type = TEE_TYPE_DSA_PUBLIC_KEY;
		else
			req_key_type = TEE_TYPE_DSA_KEYPAIR;
		break;

	case TEE_MAIN_ALGO_DH:
		req_key_type = TEE_TYPE_DH_KEYPAIR;
		break;

	default:
		utee_printf("[err] Bad Crypt Algo: 0x%08x\n", algo);
		return TEE_ERROR_BAD_PARAMETERS;

	}

	if (req_key_type != o->info.objectType)
		return TEE_ERROR_BAD_PARAMETERS;

	return TEE_SUCCESS;
}



/*
 * Populate the pointers in ltc_key, given struct tee_rsa_key_pair
 */
void tee_populate_rsa_key_pair( rsa_key *ltc_key, struct tee_rsa_key_pair *tee_key, bool crt)
{
	ltc_key->type = PK_PRIVATE;
	ltc_key->e = (char *)&tee_key->e;
	ltc_key->d = (char *)&tee_key->d;
	ltc_key->N = (char *)&tee_key->N;

	if (crt) {
		ltc_key->p = (char *)&tee_key->p;
		ltc_key->q = (char *)&tee_key->q;
		ltc_key->qP = (char *)&tee_key->qP;
		ltc_key->dP = (char *)&tee_key->dP;
		ltc_key->dQ = (char *)&tee_key->dQ;
	} else {
		ltc_key->p = 0;
		ltc_key->q = 0;
		ltc_key->qP = 0;
		ltc_key->dP = 0;
		ltc_key->dQ = 0;
	}

	SET_MPA_ALLOCSIZE(&tee_key->e);
	SET_MPA_ALLOCSIZE(&tee_key->d);
	SET_MPA_ALLOCSIZE(&tee_key->N);
	SET_MPA_ALLOCSIZE(&tee_key->p);
	SET_MPA_ALLOCSIZE(&tee_key->q);
	SET_MPA_ALLOCSIZE(&tee_key->qP);
	SET_MPA_ALLOCSIZE(&tee_key->dP);
	SET_MPA_ALLOCSIZE(&tee_key->dQ);
}


void tee_populate_rsa_public_key( rsa_key *ltc_key, struct tee_rsa_public_key *tee_key)
{
	utee_mem_fill((void*)ltc_key, sizeof(rsa_key), 0);
	ltc_key->type = PK_PUBLIC;
	ltc_key->e = (char *)&tee_key->e;
	ltc_key->N = (char *)&tee_key->N;
	SET_MPA_ALLOCSIZE(&tee_key->e);
	SET_MPA_ALLOCSIZE(&tee_key->N);
}

void tee_populate_dsa_key_pair( dsa_key *ltc_key, struct tee_dsa_key_pair *tee_key)
{
	ltc_key->type = PK_PRIVATE;
	ltc_key->g = (char *)&tee_key->g;
	ltc_key->p = (char *)&tee_key->p;
	ltc_key->q = (char *)&tee_key->q;
	ltc_key->y = (char *)&tee_key->y;
	ltc_key->x = (char *)&tee_key->x;

	SET_MPA_ALLOCSIZE(&tee_key->g);
	SET_MPA_ALLOCSIZE(&tee_key->p);
	SET_MPA_ALLOCSIZE(&tee_key->q);
	SET_MPA_ALLOCSIZE(&tee_key->y);
	SET_MPA_ALLOCSIZE(&tee_key->x);

	ltc_key->qord = mp_unsigned_bin_size(&tee_key->g);
}

void tee_populate_dsa_public_key( dsa_key *ltc_key, struct tee_dsa_public_key *tee_key)
{
	ltc_key->type = PK_PUBLIC;
	ltc_key->g = (char *)&tee_key->g;
	ltc_key->p = (char *)&tee_key->p;
	ltc_key->q = (char *)&tee_key->q;
	ltc_key->y = (char *)&tee_key->y;

	SET_MPA_ALLOCSIZE(&tee_key->g);
	SET_MPA_ALLOCSIZE(&tee_key->p);
	SET_MPA_ALLOCSIZE(&tee_key->q);
	SET_MPA_ALLOCSIZE(&tee_key->y);

	ltc_key->qord = mp_unsigned_bin_size(&tee_key->g);
}

void tee_populate_dh_key_pair(
	dh_key *ltc_key,
	struct tee_dh_key_pair *tee_key)
{
	ltc_key->type = PK_PRIVATE;
	ltc_key->g = (char *)&tee_key->g;
	ltc_key->p = (char *)&tee_key->p;
	ltc_key->x = (char *)&tee_key->x;
	ltc_key->y = (char *)&tee_key->y;

	SET_MPA_ALLOCSIZE(&tee_key->g);
	SET_MPA_ALLOCSIZE(&tee_key->p);
	SET_MPA_ALLOCSIZE(&tee_key->x);
	SET_MPA_ALLOCSIZE(&tee_key->y);

	/*
	 * q and xbits are not part of the dh key. They are only used to
	 * generate a key pair
	 * Alloc size must be set on 'q' anyway
	 */
	SET_MPA_ALLOCSIZE(&tee_key->q);
}


static TEE_Result tee_obj_set_rsa_public_key( struct tee_obj *o, 
						void *e, uint32_t e_bytes, 
						void *n, uint32_t n_bytes)
{
	struct tee_rsa_public_key *tee_rsa_public_key;
	rsa_key ltc_rsa_key;
	uint32_t len;
	unsigned char *p, *q;

	//TEE_ASSERT(sizeof(struct tee_rsa_public_key) == o->data_size);
	if(sizeof(struct tee_rsa_public_key) != o->data_size) {
		_PANIC_LOG_(TEE_ERROR_BAD_PARAMETERS);
		TEE_Panic(TEE_ERROR_BAD_PARAMETERS);
		return TEE_ERROR_BAD_PARAMETERS;
	}

	//utee_mem_fill(o->data, o->data_size, 0);
	tee_rsa_public_key = (struct tee_rsa_public_key *)o->data;

	tee_populate_rsa_public_key(&ltc_rsa_key, tee_rsa_public_key);

	/* implement by memcpy */
	// tee_rsa_public_key->e.size = ( e_bytes + ( sizeof(tee_rsa_public_key->e.d[0]) - 1 ) ) / sizeof(tee_rsa_public_key->e.d[0]);
	// utee_printf("tee_rsa_public_key->e.size = 0x%08x\n",tee_rsa_public_key->e.size);
	// tee_rsa_public_key->N.size = ( n_bytes + ( sizeof(tee_rsa_public_key->N.d[0]) - 1 ) ) / sizeof(tee_rsa_public_key->N.d[0]);
	// utee_printf("tee_rsa_public_key->N.size = 0x%08x\n",tee_rsa_public_key->N.size);
	// len = e_bytes - 1;
	// p = (unsigned char*)(&((struct tee_bignumbers*)&tee_rsa_public_key->e)->d);
	// while(len >= 0) { // store in reverse 
	// 	p[len] = *((unsigned char*)e + e_bytes - len - 1);
	// 	if((len--) == 0) {
	// 		break;
	// 	}
	// }
	// len = n_bytes - 1;
	// q = (unsigned char*)(&((struct tee_bignumbers*)&tee_rsa_public_key->N)->d);
	// while( len >=  0) { // store in reverse 
	// 	q[len] = *((unsigned char*)n + n_bytes - len - 1);
	// 	if( (len--) == 0) {
	// 		break;
	// 	}
	// }

	/* implement by func: mpa_set_oct_str */
	mpanum mpa_dest;
	bool negative = false;
	mpa_dest = (mpa_num_base *)&tee_rsa_public_key->e;
	if (mpa_set_oct_str(mpa_dest, (uint8_t*)e, e_bytes, negative) != 0) {
		return TEE_ERROR_OVERFLOW;		
	}
	mpa_dest = (mpa_num_base *)&tee_rsa_public_key->N;
	if (mpa_set_oct_str(mpa_dest, (uint8_t*)n, n_bytes, negative) != 0) {
		return TEE_ERROR_OVERFLOW;		
	}

	return TEE_SUCCESS;
}


static TEE_Result tee_obj_set_rsa_key_pair( struct tee_obj *o, 
						void *e, uint32_t e_bytes, 
						void *p, uint32_t p_bytes,
						void *q, uint32_t q_bytes)
{


	return TEE_SUCCESS;
}	

TEE_Result utee_obj_set_key_rsa(uint32_t hKeyObject, uint32_t rsaKeyBits, 
						void *e, uint32_t e_bytes, void *n, uint32_t n_bytes,
						bool isRsaKeyPair) {
	
	TEE_Result res = TEE_SUCCESS;
	struct tee_crypt_ctx *crypt_ctx;
	struct tee_obj *rsa_key_obj;
	const struct tee_crypt_obj_type_props *type_props;

	if(!hKeyObject || !e || !n) {
		res = TEE_ERROR_BAD_PARAMETERS;
		_PANIC_LOG_(res);
		goto _ret_;	
	}

	res = tee_get_crypt_ctx(&crypt_ctx);
	if (res != TEE_SUCCESS) {
		_PANIC_LOG_(res);
		goto _ret_;	
	}

	res = tee_crypt_obj_get(crypt_ctx, hKeyObject, &rsa_key_obj);
	if (res != TEE_SUCCESS) {
		_PANIC_LOG_(res);
		goto _ret_;	
	}

	/* Find description of object */
	type_props = tee_find_crypt_obj_type_props(rsa_key_obj->info.objectType);
	if (type_props == NULL) {
		res = TEE_ERROR_NOT_SUPPORTED;
		_PANIC_LOG_(res);
		goto _ret_;		
	}
	if (rsaKeyBits < type_props->min_size) {
		res = TEE_ERROR_NOT_SUPPORTED;		
		_PANIC_LOG_(res);
		goto _ret_;
	}

	if (rsaKeyBits > type_props->max_size){
		res = TEE_ERROR_NOT_SUPPORTED;	
		_PANIC_LOG_(res);
		goto _ret_;	
	}
	if(e_bytes < 0 || e_bytes > rsaKeyBits / 8) {
		res = TEE_ERROR_BAD_PARAMETERS;
		_PANIC_LOG_(res);
		goto _ret_;	
	}
	if(n_bytes < 0 || n_bytes > rsaKeyBits / 8) {
		res = TEE_ERROR_BAD_PARAMETERS;
		_PANIC_LOG_(res);
		goto _ret_;			
	}

	if(isRsaKeyPair) {


	}else {
		tee_obj_set_rsa_public_key(rsa_key_obj, e, e_bytes, n, n_bytes);
	}

	rsa_key_obj->info.objectSize = rsaKeyBits;
	rsa_key_obj->info.handleFlags |= TEE_HANDLE_FLAG_INITIALIZED;
	
	/* Set bits for all known attributes for this object type */
	rsa_key_obj->have_attrs = (1 << type_props->num_type_attrs) - 1;

_ret_:

	return res;
}
 
 
static TEE_Result tee_obj_generate_key_rsa( struct tee_obj *o, const struct tee_crypt_obj_type_props *type_props,
											uint32_t key_size)
{
	TEE_Result res;
	struct tee_rsa_key_pair *tee_rsa_key;
	rsa_key ltc_rsa_key;

	//TEE_ASSERT(sizeof(struct tee_rsa_key_pair) == o->data_size);
	if(sizeof(struct tee_rsa_key_pair) != o->data_size) {
		_PANIC_LOG_(0);
		TEE_Panic(0);
	}
	tee_rsa_key = (struct tee_rsa_key_pair *)o->data;
	tee_populate_rsa_key_pair(&ltc_rsa_key, tee_rsa_key, true);
	res = tee_acipher_gen_rsa_keys(&ltc_rsa_key, key_size);
	if (res != TEE_SUCCESS)
		return res;

	/* Set bits for all known attributes for this object type */
	o->have_attrs = (1 << type_props->num_type_attrs) - 1;
	return TEE_SUCCESS;
}


static TEE_Result tee_obj_generate_key_dsa( struct tee_obj *o,
											const struct tee_crypt_obj_type_props *type_props,
											uint32_t key_size)
{
	TEE_Result res;
	struct tee_dsa_key_pair *tee_dsa_key;
	dsa_key ltc_dsa_key;

	//TEE_ASSERT(sizeof(struct tee_dsa_key_pair) == o->data_size);
	if(sizeof(struct tee_dsa_key_pair) != o->data_size) {
		_PANIC_LOG_(0);
		TEE_Panic(0);
	}
	tee_dsa_key = (struct tee_dsa_key_pair *)o->data;
	tee_populate_dsa_key_pair(&ltc_dsa_key, tee_dsa_key);
	res = tee_acipher_gen_dsa_keys(&ltc_dsa_key, key_size);
	if (res != TEE_SUCCESS)
		return res;

	/* Set bits for all known attributes for this object type */
	o->have_attrs = (1 << type_props->num_type_attrs) - 1;
	return TEE_SUCCESS;
}


TEE_Result tee_crypt_obj_generate_key( uint32_t obj, 
	                                   uint32_t key_size,
                                       const TEE_Attribute *params, 
                                       uint32_t param_count)
{
	TEE_Result res;
	struct tee_crypt_ctx *crypt_ctx;
	const struct tee_crypt_obj_type_props *type_props;
	struct tee_obj *o;
	struct tee_crypt_obj_secret *key;
	size_t byte_size;

	res = tee_get_crypt_ctx(&crypt_ctx);
	if (res != TEE_SUCCESS) {
		return res;		
	}

	res = tee_crypt_obj_get(crypt_ctx, obj, &o);
	if (res != TEE_SUCCESS) {
		return res;		
	}
	/* Must be a transient object */
	if ((o->info.handleFlags & TEE_HANDLE_FLAG_PERSISTENT) != 0) {
		return TEE_ERROR_BAD_STATE;	
	}

	/* Must not be initialized already */
	if ((o->info.handleFlags & TEE_HANDLE_FLAG_INITIALIZED) != 0) {
		return TEE_ERROR_BAD_STATE;	
	}

	/* Find description of object */
	type_props = tee_find_crypt_obj_type_props(o->info.objectType);
	if (type_props == NULL) {
		_PANIC_LOG_(TEE_ERROR_NOT_SUPPORTED);
		return TEE_ERROR_NOT_SUPPORTED;
	}

	/* Check that maxObjectSize follows restrictions */
	if (key_size % type_props->quanta != 0)
		return TEE_ERROR_NOT_SUPPORTED;
	if (key_size < type_props->min_size)
		return TEE_ERROR_NOT_SUPPORTED;
	if (key_size > type_props->max_size)
		return TEE_ERROR_NOT_SUPPORTED;


	res = tee_crypt_check_attr(ATTR_USAGE_GENERATE_KEY, type_props,
				      (TEE_Attribute *)params, param_count);
	if (res != TEE_SUCCESS) {
		_PANIC_LOG_(res);
		return res;		
	}

	switch (o->info.objectType) {
		case TEE_TYPE_SM_SMS4:
		case TEE_TYPE_AES:
		case TEE_TYPE_DES:
		case TEE_TYPE_DES3:
		case TEE_TYPE_HMAC_MD5:
		case TEE_TYPE_HMAC_SHA1:
		case TEE_TYPE_HMAC_SHA224:
		case TEE_TYPE_HMAC_SHA256:
		case TEE_TYPE_HMAC_SHA384:
		case TEE_TYPE_HMAC_SHA512:
		case TEE_TYPE_GENERIC_SECRET:
			byte_size = key_size / 8;

			if (o->info.objectType == TEE_TYPE_DES ||
			    o->info.objectType == TEE_TYPE_DES3) {
				byte_size = (key_size + key_size / 7) / 8;
			}
			key = (struct tee_crypt_obj_secret *)o->data;
			if (byte_size > (o->data_size - sizeof(*key)))
				return TEE_ERROR_EXCESS_DATA;

			res = tee_get_rng_array((void *)(key + 1), byte_size);
			if (res != TEE_SUCCESS) {
				return res;		
			}
			
			/* Force the last bit to have exactly a value on byte_size */
			((char *)key)[sizeof(key->key_size) + byte_size - 1] |= 0x80;
			key->key_size = byte_size;

			/* Set bits for all known attributes for this object type */
			o->have_attrs = (1 << type_props->num_type_attrs) - 1;

			utee_mem_hexdump("generate_key", 
					(void *)((struct tee_crypt_obj_secret *)o->data + 1),  
					((struct tee_crypt_obj_secret *)(o->data))->key_size, 16, true);

			break;

		case TEE_TYPE_RSA_KEYPAIR:
			res = tee_obj_generate_key_rsa(o, type_props, key_size);
			if (res != TEE_SUCCESS) {
				return res;		
			}
			break;

		case TEE_TYPE_DSA_KEYPAIR:
			res = tee_obj_generate_key_dsa(o, type_props, key_size);
			if (res != TEE_SUCCESS) {
				return res;		
			}
			break;

		case TEE_TYPE_DH_KEYPAIR:
			//res = tee_svc_obj_generate_key_dh(sess, o, type_props, key_size, params, param_count);
			if (res != TEE_SUCCESS) {
				return res;		
			}
			break;

		default: {	
			case TEE_TYPE_RSA_PUBLIC_KEY: {
				utee_printf("TEE_ERROR_BAD_FORMAT :: TEE_TYPE_RSA_PUBLIC_KEY\n");
			}
			return TEE_ERROR_BAD_FORMAT;
		}
	}

	o->info.objectSize = key_size;
	o->info.handleFlags |= TEE_HANDLE_FLAG_INITIALIZED;

	return TEE_SUCCESS;
}



TEE_Result tee_openssl_to_lct_rsa_key() {

	return TEE_SUCCESS;
}
