#ifndef CRYPT_OBJ_H
#define CRYPT_OBJ_H

#include <tee_api_types.h>
#include <tee_obj.h>
#include <utee_mem.h>

#include "crypt_ctx.h"
#include "crypt_key.h"



#define TEE_USAGE_DEFAULT				0xffffffff

#define TEE_ATTR_BIT_PROTECTED			(1 << 28)

#define TEE_MEMBER_SIZE(type, member) 	sizeof(((type *)0)->member)

#define TEE_ARRAY_SIZE(a) 				(sizeof(a) / sizeof((a)[0]))


/* Set an attribute on an object */
#define SET_ATTRIBUTE(_object, _props, _attr)	\
	(_object)->have_attrs |= \
		(1 << (tee_crypt_obj_find_type_attr_idx((_attr), (_props))))
		
/* Get an attribute on an object */
#define GET_ATTRIBUTE(_object, _props, _attr)	\
	((_object)->have_attrs & \
		(1 << (tee_crypt_obj_find_type_attr_idx((_attr), (_props)))))


struct tee_crypt_obj_secret {
	uint32_t key_size;

	/*
	 * Pseudo code visualize layout of structure
	 * Next follows data, such as:
	 *	uint8_t data[key_size]
	 * key_size must never exceed
	 * (obj->data_size - sizeof(struct tee_crypt_obj_secret)).
	 */
};

#define TEE_TYPE_ATTR_OPTIONAL       0x0
#define TEE_TYPE_ATTR_REQUIRED       0x1
#define TEE_TYPE_ATTR_OPTIONAL_GROUP 0x2
#define TEE_TYPE_ATTR_SIZE_INDICATOR 0x4
#define TEE_TYPE_ATTR_GEN_KEY_OPT    0x8
#define TEE_TYPE_ATTR_GEN_KEY_REQ    0x10

#define TEE_TYPE_CONV_FUNC_NONE       0
    /* Handle storing of generic secret keys of varying lengths */
#define TEE_TYPE_CONV_FUNC_SECRET     1
    /* Convert Array of bytes to/from Big Number from mpa (used by LTC). */
#define TEE_TYPE_CONV_FUNC_BIGINT     2
    /* Convert to/from value attribute depending on direction */
#define TEE_TYPE_CONV_FUNC_VALUE      4


struct tee_cryp_obj_type_attrs {
	uint32_t attr_id;
	uint16_t flags;
	uint16_t conv_func;
	uint16_t raw_offs;
	uint16_t raw_size;
};

#define RAW_DATA(_x, _y)	\
	.raw_offs = offsetof(_x, _y), .raw_size = TEE_MEMBER_SIZE(_x, _y)


static const struct tee_cryp_obj_type_attrs
	tee_crypt_obj_secret_value_attrs[] = {
	{
	.attr_id = TEE_ATTR_SECRET_VALUE,
	.flags = TEE_TYPE_ATTR_REQUIRED | TEE_TYPE_ATTR_SIZE_INDICATOR,
	.conv_func = TEE_TYPE_CONV_FUNC_SECRET,
	.raw_offs = 0,
	.raw_size = 0
	},
};

static const struct tee_cryp_obj_type_attrs 
tee_cryp_obj_rsa_pub_key_attrs[] = {
	{
	.attr_id = TEE_ATTR_RSA_MODULUS,
	.flags = TEE_TYPE_ATTR_REQUIRED | TEE_TYPE_ATTR_SIZE_INDICATOR,
	.conv_func = TEE_TYPE_CONV_FUNC_BIGINT,
	RAW_DATA(struct tee_rsa_public_key, N)
	},

	{
	.attr_id = TEE_ATTR_RSA_PUBLIC_EXPONENT,
	.flags = TEE_TYPE_ATTR_REQUIRED,
	.conv_func = TEE_TYPE_CONV_FUNC_BIGINT,
	RAW_DATA(struct tee_rsa_public_key, e)
	},
};

static const struct tee_cryp_obj_type_attrs 
tee_cryp_obj_rsa_keypair_attrs[] = {
	{
	.attr_id = TEE_ATTR_RSA_MODULUS,
	.flags = TEE_TYPE_ATTR_REQUIRED | TEE_TYPE_ATTR_SIZE_INDICATOR,
	.conv_func = TEE_TYPE_CONV_FUNC_BIGINT,
	RAW_DATA(struct tee_rsa_key_pair, N)
	},

	{
	.attr_id = TEE_ATTR_RSA_PUBLIC_EXPONENT,
	.flags = TEE_TYPE_ATTR_REQUIRED,
	.conv_func = TEE_TYPE_CONV_FUNC_BIGINT,
	RAW_DATA(struct tee_rsa_key_pair, e)
	},

	{
	.attr_id = TEE_ATTR_RSA_PRIVATE_EXPONENT,
	.flags = TEE_TYPE_ATTR_REQUIRED,
	.conv_func = TEE_TYPE_CONV_FUNC_BIGINT,
	RAW_DATA(struct tee_rsa_key_pair, d)
	},

	{
	.attr_id = TEE_ATTR_RSA_PRIME1,
	.flags = TEE_TYPE_ATTR_OPTIONAL_GROUP,
	.conv_func = TEE_TYPE_CONV_FUNC_BIGINT,
	RAW_DATA(struct tee_rsa_key_pair, p)
	},

	{
	.attr_id = TEE_ATTR_RSA_PRIME2,
	.flags = TEE_TYPE_ATTR_OPTIONAL_GROUP,
	.conv_func = TEE_TYPE_CONV_FUNC_BIGINT,
	RAW_DATA(struct tee_rsa_key_pair, q)
	},

	{
	.attr_id = TEE_ATTR_RSA_EXPONENT1,
	.flags = TEE_TYPE_ATTR_OPTIONAL_GROUP,
	.conv_func = TEE_TYPE_CONV_FUNC_BIGINT,
	RAW_DATA(struct tee_rsa_key_pair, dP)
	},

	{
	.attr_id = TEE_ATTR_RSA_EXPONENT2,
	.flags = TEE_TYPE_ATTR_OPTIONAL_GROUP,
	.conv_func = TEE_TYPE_CONV_FUNC_BIGINT,
	RAW_DATA(struct tee_rsa_key_pair, dQ)
	},

	{
	.attr_id = TEE_ATTR_RSA_COEFFICIENT,
	.flags = TEE_TYPE_ATTR_OPTIONAL_GROUP,
	.conv_func = TEE_TYPE_CONV_FUNC_BIGINT,
	RAW_DATA(struct tee_rsa_key_pair, qP)
	},
};

static const struct tee_cryp_obj_type_attrs 
tee_cryp_obj_dsa_pub_key_attrs[] = {
	{
	.attr_id = TEE_ATTR_DSA_PRIME,
	.flags = TEE_TYPE_ATTR_REQUIRED,
	.conv_func = TEE_TYPE_CONV_FUNC_BIGINT,
	RAW_DATA(struct tee_dsa_public_key, p)
	},

	{
	.attr_id = TEE_ATTR_DSA_SUBPRIME,
	.flags = TEE_TYPE_ATTR_REQUIRED | TEE_TYPE_ATTR_SIZE_INDICATOR,
	.conv_func = TEE_TYPE_CONV_FUNC_BIGINT,
	RAW_DATA(struct tee_dsa_public_key, q)
	},

	{
	.attr_id = TEE_ATTR_DSA_BASE,
	.flags = TEE_TYPE_ATTR_REQUIRED,
	.conv_func = TEE_TYPE_CONV_FUNC_BIGINT,
	RAW_DATA(struct tee_dsa_public_key, g)
	},

	{
	.attr_id = TEE_ATTR_DSA_PUBLIC_VALUE,
	.flags = TEE_TYPE_ATTR_REQUIRED,
	.conv_func = TEE_TYPE_CONV_FUNC_BIGINT,
	RAW_DATA(struct tee_dsa_public_key, y)
	},
};

static const struct tee_cryp_obj_type_attrs 
tee_cryp_obj_dsa_keypair_attrs[] = {
	{
	.attr_id = TEE_ATTR_DSA_PRIME,
	.flags = TEE_TYPE_ATTR_REQUIRED | TEE_TYPE_ATTR_GEN_KEY_REQ,
	.conv_func = TEE_TYPE_CONV_FUNC_BIGINT,
	RAW_DATA(struct tee_dsa_key_pair, p)
	},

	{
	.attr_id = TEE_ATTR_DSA_SUBPRIME,
	.flags = TEE_TYPE_ATTR_REQUIRED | TEE_TYPE_ATTR_SIZE_INDICATOR |
		 TEE_TYPE_ATTR_GEN_KEY_REQ,
	.conv_func = TEE_TYPE_CONV_FUNC_BIGINT,
	RAW_DATA(struct tee_dsa_key_pair, q)
	},

	{
	.attr_id = TEE_ATTR_DSA_BASE,
	.flags = TEE_TYPE_ATTR_REQUIRED | TEE_TYPE_ATTR_GEN_KEY_REQ,
	.conv_func = TEE_TYPE_CONV_FUNC_BIGINT,
	RAW_DATA(struct tee_dsa_key_pair, g)
	},

	{
	.attr_id = TEE_ATTR_DSA_PRIVATE_VALUE,
	.flags = TEE_TYPE_ATTR_REQUIRED,
	.conv_func = TEE_TYPE_CONV_FUNC_BIGINT,
	RAW_DATA(struct tee_dsa_key_pair, x)
	},

	{
	.attr_id = TEE_ATTR_DSA_PUBLIC_VALUE,
	.flags = TEE_TYPE_ATTR_REQUIRED,
	.conv_func = TEE_TYPE_CONV_FUNC_BIGINT,
	RAW_DATA(struct tee_dsa_key_pair, y)
	},
};

static const struct tee_cryp_obj_type_attrs 
tee_cryp_obj_dh_keypair_attrs[] = {
	{
	.attr_id = TEE_ATTR_DH_PRIME,
	.flags = TEE_TYPE_ATTR_REQUIRED | TEE_TYPE_ATTR_SIZE_INDICATOR |
		 TEE_TYPE_ATTR_GEN_KEY_REQ,
	.conv_func = TEE_TYPE_CONV_FUNC_BIGINT,
	RAW_DATA(struct tee_dh_key_pair, p)
	},

	{
	.attr_id = TEE_ATTR_DH_BASE,
	.flags = TEE_TYPE_ATTR_REQUIRED | TEE_TYPE_ATTR_GEN_KEY_REQ,
	.conv_func = TEE_TYPE_CONV_FUNC_BIGINT,
	RAW_DATA(struct tee_dh_key_pair, g)
	},

	{
	.attr_id = TEE_ATTR_DH_PUBLIC_VALUE,
	.flags = TEE_TYPE_ATTR_REQUIRED,
	.conv_func = TEE_TYPE_CONV_FUNC_BIGINT,
	RAW_DATA(struct tee_dh_key_pair, y)
	},

	{
	.attr_id = TEE_ATTR_DH_PRIVATE_VALUE,
	.flags = TEE_TYPE_ATTR_REQUIRED,
	.conv_func = TEE_TYPE_CONV_FUNC_BIGINT,
	RAW_DATA(struct tee_dh_key_pair, x)
	},

	{
	.attr_id = TEE_ATTR_DH_SUBPRIME,
	.flags = TEE_TYPE_ATTR_OPTIONAL_GROUP |	 TEE_TYPE_ATTR_GEN_KEY_OPT,
	.conv_func = TEE_TYPE_CONV_FUNC_BIGINT,
	RAW_DATA(struct tee_dh_key_pair, q)
	},

	{
	.attr_id = TEE_ATTR_DH_X_BITS,
	.flags = TEE_TYPE_ATTR_GEN_KEY_OPT,
	.conv_func = TEE_TYPE_CONV_FUNC_VALUE,
	RAW_DATA(struct tee_dh_key_pair, xbits)
	},
};


struct tee_crypt_obj_type_props {
	TEE_ObjectType obj_type;
	uint16_t min_size;	/* may not be smaller than this */
	uint16_t max_size;	/* may not be larger than this */
	uint16_t alloc_size;	/* this many bytes are allocated to hold data */
	uint8_t quanta;		/* may only be an multiple of this */

	uint8_t num_type_attrs;
	const struct tee_cryp_obj_type_attrs *type_attrs;
};


#define PROP(obj_type, quanta, min_size, max_size, alloc_size, type_attrs) \
		{ (obj_type), (min_size), (max_size), (alloc_size), (quanta), \
		  TEE_ARRAY_SIZE(type_attrs), (type_attrs) }



static const struct tee_crypt_obj_type_props tee_cryp_obj_props[] = {


	PROP(TEE_TYPE_SM_SMS4, 128, 128, 128,	
		128 / 8 + sizeof(struct tee_crypt_obj_secret),
		tee_crypt_obj_secret_value_attrs),


	PROP(TEE_TYPE_AES, 64, 128, 256,	/* valid sizes 128, 192, 256 */
		256 / 8 + sizeof(struct tee_crypt_obj_secret),
		tee_crypt_obj_secret_value_attrs),


	//PROP(TEE_TYPE_DES, 56, 56, 56,
	PROP(TEE_TYPE_DES, 64, 64, 64,

		/*
		* Valid size 56 without parity, note that we still allocate
		* for 64 bits since the key is supplied with parity.
		*/
		64 / 8 + sizeof(struct tee_crypt_obj_secret),
		tee_crypt_obj_secret_value_attrs),


	//PROP(TEE_TYPE_DES3, 56, 112, 168,
	PROP(TEE_TYPE_DES3, 64, 128, 192,

		/*
		* Valid sizes 112, 168 without parity, note that we still
		* allocate for with space for the parity since the key is
		* supplied with parity.
		*/
		192 / 8 + sizeof(struct tee_crypt_obj_secret),
		tee_crypt_obj_secret_value_attrs),


	//PROP(TEE_TYPE_HMAC_MD5, 8, 64, 512,
	PROP(TEE_TYPE_HMAC_MD5, 8, 8, 512,

		512 / 8 + sizeof(struct tee_crypt_obj_secret),
		tee_crypt_obj_secret_value_attrs),


	PROP(TEE_TYPE_HMAC_SHA1, 8, 80, 512,
		512 / 8 + sizeof(struct tee_crypt_obj_secret),
		tee_crypt_obj_secret_value_attrs),


	PROP(TEE_TYPE_HMAC_SHA224, 8, 112, 512,
		512 / 8 + sizeof(struct tee_crypt_obj_secret),
		tee_crypt_obj_secret_value_attrs),


	PROP(TEE_TYPE_HMAC_SHA256, 8, 192, 1024,
		1024 / 8 + sizeof(struct tee_crypt_obj_secret),
		tee_crypt_obj_secret_value_attrs),


	PROP(TEE_TYPE_HMAC_SHA384, 8, 256, 1024,
		1024 / 8 + sizeof(struct tee_crypt_obj_secret),
		tee_crypt_obj_secret_value_attrs),


	PROP(TEE_TYPE_HMAC_SHA512, 8, 256, 1024,
		1024 / 8 + sizeof(struct tee_crypt_obj_secret),
		tee_crypt_obj_secret_value_attrs),


	PROP(TEE_TYPE_GENERIC_SECRET, 8, 0, 4096,
		4096 / 8 + sizeof(struct tee_crypt_obj_secret),
		tee_crypt_obj_secret_value_attrs),


	PROP(TEE_TYPE_RSA_PUBLIC_KEY, 1, 256, 2048,
		sizeof(struct tee_rsa_public_key),
		tee_cryp_obj_rsa_pub_key_attrs),


	PROP(TEE_TYPE_RSA_KEYPAIR, 1, 256, 2048,
		sizeof(struct tee_rsa_key_pair),
		tee_cryp_obj_rsa_keypair_attrs),


	PROP(TEE_TYPE_DSA_PUBLIC_KEY, 64, 512, 1024,
		sizeof(struct tee_dsa_public_key),
		tee_cryp_obj_dsa_pub_key_attrs),


	PROP(TEE_TYPE_DSA_KEYPAIR, 64, 512, 1024,
		sizeof(struct tee_dsa_key_pair),
		tee_cryp_obj_dsa_keypair_attrs),


	PROP(TEE_TYPE_DH_KEYPAIR, 1, 256, 2048,
		sizeof(struct tee_dh_key_pair),
		tee_cryp_obj_dh_keypair_attrs),


};

enum attr_usage {
	ATTR_USAGE_POPULATE,
	ATTR_USAGE_GENERATE_KEY
};

TEE_Result tee_crypt_check_attr( enum attr_usage usage, const struct tee_crypt_obj_type_props *type_props,
		TEE_Attribute *attrs, uint32_t attr_count);


/* Transient Object Property Set Functions */
const struct tee_crypt_obj_type_props *tee_find_crypt_obj_type_props(TEE_ObjectType obj_type);


int tee_crypt_obj_find_type_attr_idx( uint32_t attr_id, const struct tee_crypt_obj_type_props *type_props);



/* Transient Object Functions */
TEE_Result utee_crypt_obj_alloc(TEE_ObjectType obj_type, uint32_t max_obj_size, 
					uint32_t *crypt_obj);

TEE_Result utee_crypt_obj_close(uint32_t crypt_obj);

TEE_Result utee_crypt_obj_reset(uint32_t crypt_obj);

TEE_Result utee_crypt_obj_populate(uint32_t crypt_obj, TEE_Attribute *attrs, 
					uint32_t attr_count);

TEE_Result utee_crypt_obj_copy(uint32_t dst_obj, uint32_t src_obj);


TEE_Result utee_crypt_obj_get_info(uint32_t obj, TEE_ObjectInfo *info);

TEE_Result tee_crypt_obj_get(struct tee_crypt_ctx *crypt_ctx, uint32_t obj_id, 
					struct tee_obj **crypt_obj);

void tee_crypt_obj_add(struct tee_crypt_ctx *crypt_ctx, struct tee_obj *crypt_obj);

void tee_crypt_obj_close(struct tee_crypt_ctx *crypt_ctx, struct tee_obj *crypt_obj);

void tee_crypt_obj_close_all(struct tee_crypt_ctx *crypt_ctx);


#endif
