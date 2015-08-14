#include "crypt_obj.h"


/* Transient Object Functions */
TEE_Result utee_crypt_obj_alloc(TEE_ObjectType obj_type, uint32_t max_obj_size, uint32_t *obj)
{
	TEE_Result res;
	struct tee_crypt_ctx *crypt_ctx;
	const struct tee_crypt_obj_type_props *type_props;
	struct tee_obj *o;

	res = tee_get_crypt_ctx(&crypt_ctx);
	if (res != TEE_SUCCESS) {
		return res;		
	}
	/*
	 * Verify that maxObjectSize is supported and find out how
	 * much should be allocated.
	 */
	// Find description of object
	type_props = tee_find_crypt_obj_type_props(obj_type);
	if (type_props == NULL) {
		return TEE_ERROR_NOT_SUPPORTED;
	}
	// Check that maxObjectSize follows restrictions
	if (max_obj_size % type_props->quanta != 0) {
		utee_printf("[err] maxKeySize[%d] may only be an multiple of %d bits\n", max_obj_size, type_props->quanta);
		return TEE_ERROR_NOT_SUPPORTED;
	}
	if (max_obj_size < type_props->min_size) {
		utee_printf("[err] maxKeySize[%d] should be >= %d bits\n", max_obj_size, type_props->min_size);
		return TEE_ERROR_NOT_SUPPORTED;
	}
	if (max_obj_size > type_props->max_size) {
		utee_printf("[err] maxKeySize[%d] should be <= %d bits\n", max_obj_size, type_props->max_size);
		return TEE_ERROR_NOT_SUPPORTED;
	}
	o = utee_mem_calloc(1, sizeof(*o));
	if (o == NULL) {
		return TEE_ERROR_OUT_OF_MEMORY;
	}
	utee_mem_fill(o, 0, sizeof(*o));
	o->data = utee_mem_calloc(1, type_props->alloc_size);
	if (o->data == NULL)  {
		utee_mem_free(o);
		return TEE_ERROR_OUT_OF_MEMORY;
	}
	utee_mem_fill(o->data, 0, type_props->alloc_size);
	o->data_size = type_props->alloc_size;
	o->info.objectType = obj_type;
	o->info.maxObjectSize = max_obj_size;
	o->info.objectUsage = TEE_USAGE_DEFAULT;
	o->info.handleFlags = 0;
	tee_crypt_obj_add(crypt_ctx, o);
	res = utee_copy_to_user(NULL, obj, &o, sizeof(o));
	if (res != TEE_SUCCESS) {
		tee_crypt_obj_close(crypt_ctx, o);
	}
	
	return res;
}

TEE_Result utee_crypt_obj_close(uint32_t obj)
{
	TEE_Result res;
	struct tee_crypt_ctx *crypt_ctx;
	struct tee_obj *o;

	res = tee_get_crypt_ctx(&crypt_ctx);
	if (res != TEE_SUCCESS) {
		_PANIC_LOG_(res);
		return res;		
	}
	res = tee_crypt_obj_get(crypt_ctx, obj, &o);
	if (res != TEE_SUCCESS) {
		_PANIC_LOG_(res);
		return res;		
	}
	/*
	 * If it's busy it's used by an operation, a client should never have
	 * this handle.
	 */
	if (o->busy)
		return TEE_ERROR_ITEM_NOT_FOUND;

	tee_crypt_obj_close(crypt_ctx, o);

	return TEE_SUCCESS;
}


TEE_Result utee_crypt_obj_reset(uint32_t obj)
{
	TEE_Result res;
	struct tee_crypt_ctx *crypt_ctx;
	struct tee_obj *o;

	res = tee_get_crypt_ctx(&crypt_ctx);
	if (res != TEE_SUCCESS) {
		_PANIC_LOG_(res);
		return res;		
	}
	res = tee_crypt_obj_get(crypt_ctx, obj, &o);
	if (res != TEE_SUCCESS) {
		_PANIC_LOG_(res);
		return res;		
	}
	if ((o->info.handleFlags & TEE_HANDLE_FLAG_PERSISTENT) == 0) {
		memset(o->data, 0, o->data_size);
		o->info.objectSize = 0;
		o->info.objectUsage = TEE_USAGE_DEFAULT;
	} else {
		return TEE_ERROR_BAD_PARAMETERS;
	}

	return TEE_SUCCESS;
}


static TEE_Result tee_crypt_obj_get_raw_data( struct tee_obj *o, const struct tee_crypt_obj_type_props *type_props,
		size_t idx, void **data, size_t *size)
{
	const struct tee_cryp_obj_type_attrs *type_attr = type_props->type_attrs + idx;

	if (type_attr->raw_size == 0) {
		struct tee_crypt_obj_secret *key = (struct tee_crypt_obj_secret *)o->data;
		/* Handle generic secret */
		if (type_attr->raw_offs != 0) {
			return TEE_ERROR_BAD_STATE;			
		}
		*size = key->key_size;
	} 
	else  {
		*size = type_attr->raw_size;
	}
	*data = (uint8_t *)o->data + type_attr->raw_offs;

	return TEE_SUCCESS;
}


static TEE_Result tee_crypt_obj_store_attr_raw(void *sess, uint16_t conv_func,
						  const TEE_Attribute *attr,
						  void *data, size_t data_size)
{
	TEE_Result res;

	if (attr == NULL) {
		return TEE_ERROR_BAD_STATE;		
	}
	if (conv_func != TEE_TYPE_CONV_FUNC_VALUE &&  attr->content.ref.buffer == NULL) {
		return TEE_ERROR_BAD_PARAMETERS;		
	}
	switch (conv_func)  {
		case TEE_TYPE_CONV_FUNC_NONE: {
			/* No conversion data size has to match exactly */
			if (attr->content.ref.length != data_size) {
				return TEE_ERROR_BAD_PARAMETERS;			
			}
			return utee_copy_from_user(NULL, data, attr->content.ref.buffer, data_size);			
		}
		case TEE_TYPE_CONV_FUNC_SECRET: {
			struct tee_crypt_obj_secret *obj;
			if (!TEE_ALIGNMENT_IS_OK(data, struct tee_crypt_obj_secret)) {
				 return TEE_ERROR_BAD_STATE;				
			}
			obj = (struct tee_crypt_obj_secret *)(void *)data;
			/* Data size has to fit in allocated buffer */
			if (attr->content.ref.length > (data_size - sizeof(struct tee_crypt_obj_secret))) {
				/* ?? checking  number overflow ??
				 *   if data_size == 0 , then data_size - sizeof(struct tee_crypt_obj_secret) will be negative when int type contains 32 bits
				 */
				return TEE_ERROR_BAD_PARAMETERS;				
			}
			res = utee_copy_from_user(NULL, obj + 1, attr->content.ref.buffer, attr->content.ref.length);
			if (res == TEE_SUCCESS) {
				obj->key_size = attr->content.ref.length;				
			}
			return res;
		}

		case TEE_TYPE_CONV_FUNC_BIGINT: {
			/*
			 * Check that the converted result fits in the
			 * allocated buffer
			 */
			if (attr->content.ref.length > (data_size + sizeof(uint32_t) * MPA_NUMBASE_METADATA_SIZE_IN_U32)) {
				return TEE_ERROR_BAD_PARAMETERS;				
			}
			/*
			 * read the array of bytes (stored in attr->content.ref.buffer)
			 * and save it as a mpa number (stored in data)
			 */
			SET_MPA_ALLOCSIZE(data);

			mp_read_unsigned_bin( data, attr->content.ref.buffer, attr->content.ref.length);

			return TEE_SUCCESS;
		}
		case TEE_TYPE_CONV_FUNC_VALUE:
		{
			/*
			 * a value attribute consists of two uint32 but have not
			 * seen anything that actaully would need that so this fills
			 * the data from the first value and discards the second value
			 */
			*(uint32_t *)data = attr->content.value.a;

			return TEE_SUCCESS;
		}
		default:
			return TEE_ERROR_BAD_STATE;

	}
}

TEE_Result tee_crypt_check_attr(
		enum attr_usage usage,
		const struct tee_crypt_obj_type_props *type_props,
		TEE_Attribute *attrs,
		uint32_t attr_count)
{
	uint32_t required_flag;
	uint32_t opt_flag;
	bool all_opt_needed;
	uint32_t req_attrs = 0;
	uint32_t opt_grp_attrs = 0;
	uint32_t attrs_found = 0;
	size_t n;

	if (usage == ATTR_USAGE_POPULATE) {
		required_flag = TEE_TYPE_ATTR_REQUIRED;
		opt_flag = TEE_TYPE_ATTR_OPTIONAL_GROUP;
		all_opt_needed = true;
	} else {
		required_flag = TEE_TYPE_ATTR_GEN_KEY_REQ;
		opt_flag = TEE_TYPE_ATTR_GEN_KEY_OPT;
		all_opt_needed = false;
	}
	/*
	 * First find out which attributes are required and which belong to
	 * the optional group
	 */
	for (n = 0; n < type_props->num_type_attrs; n++) {
		uint32_t bit = 1 << n;
		uint32_t flags = type_props->type_attrs[n].flags;

		if (flags & required_flag)
			req_attrs |= bit;
		else if (flags & opt_flag)
			opt_grp_attrs |= bit;
	}
	/*
	 * Verify that all required attributes are in place and
	 * that the same attribute isn't repeated.
	 */
	for (n = 0; n < attr_count; n++) {
		int idx = tee_crypt_obj_find_type_attr_idx(attrs[n].attributeID, type_props);
		if (idx >= 0) {
			uint32_t bit = 1 << idx;
			if ((attrs_found & bit) != 0)
				return TEE_ERROR_ITEM_NOT_FOUND;
			attrs_found |= bit;
		}
	}
	/* Required attribute missing */
	if ((attrs_found & req_attrs) != req_attrs)
		return TEE_ERROR_ITEM_NOT_FOUND;
	/*
	 * If the flag says that "if one of the optional attributes are included
	 * all of them has to be included" this must be checked.
	 */
	if (all_opt_needed && (attrs_found & opt_grp_attrs) != 0 &&
	    (attrs_found & opt_grp_attrs) != opt_grp_attrs)
		return TEE_ERROR_ITEM_NOT_FOUND;


	/*  check key size */
	for (n = 0; n < attr_count; n++) {
		if( attrs[n].attributeID == TEE_ATTR_SECRET_VALUE ) {
			if ( attrs[n].content.ref.length   % (type_props->quanta/8) != 0) {
				utee_printf("[err] key_size[%d] may only be an multiple of %d Bytes\n", attrs[n].content.ref.length, type_props->quanta/8);
				return TEE_ERROR_NOT_SUPPORTED;
			}
			if ( attrs[n].content.ref.length < (type_props->min_size/8) ) {
				utee_printf("[err] key_size[%d] should be >= %d Bytes\n", attrs[n].content.ref.length, type_props->min_size/8);
				return TEE_ERROR_NOT_SUPPORTED;
			}
			if ( attrs[n].content.ref.length > (type_props->max_size/8) ) {
				utee_printf("[err] key_size[%d] should be <= %d Bytes\n", attrs[n].content.ref.length, type_props->max_size/8);
				return TEE_ERROR_NOT_SUPPORTED;
			}
		}
	}

	return TEE_SUCCESS;
}

static TEE_Result tee_crypt_obj_populate_type( void *sess, struct tee_obj *o,
		const struct tee_crypt_obj_type_props *type_props,
		const TEE_Attribute *attrs,
		uint32_t attr_count)
{
	TEE_Result res;
	uint32_t have_attrs = 0;
	size_t obj_size = 0;
	size_t n;

	for (n = 0; n < attr_count; n++)  {
		size_t raw_size;
		void *raw_data;
		int idx = tee_crypt_obj_find_type_attr_idx(attrs[n].attributeID, type_props);
		if (idx < 0) {
			continue;			
		}
		have_attrs |= 1 << idx;
		res = tee_crypt_obj_get_raw_data(o, type_props, idx, &raw_data, &raw_size);
		if (res != TEE_SUCCESS) {
			return res;			
		}

		res =  tee_crypt_obj_store_attr_raw( NULL, type_props->type_attrs[idx].conv_func, 
											attrs + n, raw_data, raw_size);
		if (res != TEE_SUCCESS) {
			return res;
		}
		struct tee_crypt_obj_secret *obj_secret = (struct tee_crypt_obj_secret *)raw_data;
		/*
		 * First attr_idx signifies the attribute that gives the size
		 * of the object
		 */
		if (type_props->type_attrs[idx].flags & TEE_TYPE_ATTR_SIZE_INDICATOR) {
			obj_size += attrs[n].content.ref.length * 8;
		}
	}
	/*
	 * We have to do it like this because the parity bits aren't counted
	 * when telling the size of the key in bits.
	 */
	if (o->info.objectType == TEE_TYPE_DES || o->info.objectType == TEE_TYPE_DES3) {
		obj_size -= obj_size / 8; /* Exclude parity in size of key */
	}

	o->have_attrs = have_attrs;
	o->info.objectSize = obj_size;

	return TEE_SUCCESS;
}


TEE_Result utee_crypt_obj_populate(uint32_t obj, TEE_Attribute *attrs, uint32_t attr_count)
{
	TEE_Result res;
	struct tee_crypt_ctx *crypt_ctx;
	const struct tee_crypt_obj_type_props *type_props;
	struct tee_obj *o;

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
		utee_printf("(o->info.handleFlags & TEE_HANDLE_FLAG_PERSISTENT) != 0\n");
		return TEE_ERROR_BAD_PARAMETERS;
	}
	/* Must not be initialized already */
	if ((o->info.handleFlags & TEE_HANDLE_FLAG_INITIALIZED) != 0) {
		utee_printf("(o->info.handleFlags & TEE_HANDLE_FLAG_INITIALIZED) != 0\n");
		return TEE_ERROR_BAD_PARAMETERS;
	}
	type_props = tee_find_crypt_obj_type_props(o->info.objectType);
	if (type_props == NULL) {
		utee_printf("tee_find_crypt_obj_type_props::type_props == NULL\n");
		return TEE_ERROR_NOT_IMPLEMENTED;
	}
	res = tee_crypt_check_attr(ATTR_USAGE_POPULATE, type_props, attrs, attr_count);
	if (res != TEE_SUCCESS) {
		return res;		
	}
	res = tee_crypt_obj_populate_type(NULL, o, type_props, attrs, attr_count);
	if (res == TEE_SUCCESS) {
		o->info.handleFlags |= TEE_HANDLE_FLAG_INITIALIZED;	
	}

	return res;
}


TEE_Result utee_crypt_obj_copy(uint32_t dst_obj, uint32_t src_obj)
{
	TEE_Result res;
	struct tee_crypt_ctx *crypt_ctx;
	struct tee_obj *dst_o;
	struct tee_obj *src_o;

	res = tee_get_crypt_ctx(&crypt_ctx);
	if (res != TEE_SUCCESS) {
		return res;
	}
	res = tee_crypt_obj_get(crypt_ctx, dst_obj, &dst_o);
	if (res != TEE_SUCCESS) {
		return res;
	}
	res = tee_crypt_obj_get(crypt_ctx, src_obj, &src_o);
	if (res != TEE_SUCCESS) {
		return res;
	}
	if ((src_o->info.handleFlags & TEE_HANDLE_FLAG_INITIALIZED) == 0) {
		return TEE_ERROR_BAD_PARAMETERS;
	}
	if ((dst_o->info.handleFlags & TEE_HANDLE_FLAG_PERSISTENT) != 0) {
		return TEE_ERROR_BAD_PARAMETERS;
	}	
	if ((dst_o->info.handleFlags & TEE_HANDLE_FLAG_INITIALIZED) != 0) {
		return TEE_ERROR_BAD_PARAMETERS;
	}
	if (dst_o->info.objectType == src_o->info.objectType)  {
		/* Generic case */
		if (dst_o->data_size != src_o->data_size) {
			return TEE_ERROR_BAD_STATE;
		}
		dst_o->have_attrs = src_o->have_attrs;
		utee_mem_copy(dst_o->data, src_o->data, src_o->data_size);
	} 
	else if (dst_o->info.objectType == TEE_TYPE_RSA_PUBLIC_KEY &&
		   src_o->info.objectType == TEE_TYPE_RSA_KEYPAIR)  {
		/* Extract public key from RSA key pair */
		struct tee_rsa_key_pair *key_pair = src_o->data;
		struct tee_rsa_public_key *pub_key = dst_o->data;
		size_t n;

		utee_mem_copy(&pub_key->e, &key_pair->e, sizeof(pub_key->e));
		utee_mem_copy(&pub_key->N, &key_pair->N, sizeof(pub_key->N));
		/* Set the attributes */
		dst_o->have_attrs = 0;
		for (n = 0; n < TEE_ARRAY_SIZE(tee_cryp_obj_rsa_pub_key_attrs); n++) {
			dst_o->have_attrs |= 1 << n;
		}
	} 
	else if (dst_o->info.objectType == TEE_TYPE_DSA_PUBLIC_KEY &&
		   src_o->info.objectType == TEE_TYPE_DSA_KEYPAIR)  {
		/* Extract public key from DSA key pair */
		struct tee_dsa_key_pair *key_pair = src_o->data;
		struct tee_dsa_public_key *pub_key = dst_o->data;
		size_t n;

		utee_mem_copy(&pub_key->g, &key_pair->g, sizeof(pub_key->g));
		utee_mem_copy(&pub_key->p, &key_pair->p, sizeof(pub_key->p));
		utee_mem_copy(&pub_key->q, &key_pair->q, sizeof(pub_key->q));
		utee_mem_copy(&pub_key->y, &key_pair->y, sizeof(pub_key->y));
		/* Set the attributes */
		dst_o->have_attrs = 0;
		for (n = 0; n < TEE_ARRAY_SIZE(tee_cryp_obj_dsa_pub_key_attrs); n++) {
			dst_o->have_attrs |= 1 << n;
		}
	} 
	else {
		return TEE_ERROR_BAD_PARAMETERS;
	}
	dst_o->info.handleFlags |= TEE_HANDLE_FLAG_INITIALIZED;
	dst_o->info.objectSize = src_o->info.objectSize;
	dst_o->info.objectUsage = src_o->info.objectUsage;

	return TEE_SUCCESS;
}


 
TEE_Result utee_crypt_obj_get_info(uint32_t obj, TEE_ObjectInfo *info)
{
	TEE_Result res;
	struct tee_crypt_ctx *crypt_ctx;
	struct tee_obj *o;

	res = tee_get_crypt_ctx(&crypt_ctx);
	if (res != TEE_SUCCESS) {
		return res;		
	}
	res = tee_crypt_obj_get(crypt_ctx, obj, &o);
	if (res != TEE_SUCCESS) {
		return res;		
	}

	return utee_copy_to_user(NULL, info, &o->info, sizeof(o->info));
}

/* Transient Object Property Set Functions */
const struct tee_crypt_obj_type_props *tee_find_crypt_obj_type_props(TEE_ObjectType obj_type)
{
	size_t n;

	for (n = 0; n < TEE_ARRAY_SIZE(tee_cryp_obj_props); n++)  {
		if (tee_cryp_obj_props[n].obj_type == obj_type) {
			return tee_cryp_obj_props + n;
		}
	}

	return NULL;
}

int tee_crypt_obj_find_type_attr_idx(
		uint32_t attr_id,
		const struct tee_crypt_obj_type_props *type_props)
{
	size_t n;

	for (n = 0; n < type_props->num_type_attrs; n++) {
		if (attr_id == type_props->type_attrs[n].attr_id)
			return n;
	}

	return -1;
}


void tee_crypt_obj_add(struct tee_crypt_ctx *crypt_ctx, struct tee_obj *crypt_obj)
{
	TAILQ_INSERT_TAIL(&crypt_ctx->objects, crypt_obj, link);
}

TEE_Result tee_crypt_obj_get(struct tee_crypt_ctx *crypt_ctx, uint32_t obj_id, struct tee_obj **crypt_obj)
{
	struct tee_obj *o;

	TAILQ_FOREACH(o, &crypt_ctx->objects, link)  {
		if (obj_id == (uint32_t) o) {
			*crypt_obj = o;
			return TEE_SUCCESS;
		}
	}
	return TEE_ERROR_BAD_PARAMETERS;
}

void tee_crypt_obj_close(struct tee_crypt_ctx *crypt_ctx, struct tee_obj *crypt_obj)
{

	TAILQ_REMOVE(&crypt_ctx->objects, crypt_obj, link);

	if ((crypt_obj->info.handleFlags & TEE_HANDLE_FLAG_PERSISTENT) && crypt_obj->fd)  {
		//tee_fs_close(crypt_obj->fd);
		//tee_pobj_release(crypt_obj->pobj);
	}
	
	if(crypt_obj) {
		if(crypt_obj->data) {
			utee_mem_free(crypt_obj->data);
		}
		utee_mem_free(crypt_obj);
	}
}

void tee_crypt_obj_close_all(struct tee_crypt_ctx *crypt_ctx)
{
	struct tee_obj_head *objects = &crypt_ctx->objects;

	while (!TAILQ_EMPTY(objects)) {
		tee_crypt_obj_close(crypt_ctx, TAILQ_FIRST(objects));
	}
}

