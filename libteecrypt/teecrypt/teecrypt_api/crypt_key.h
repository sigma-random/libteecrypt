#ifndef CRYPT_KEY_H
#define CRYPT_KEY_H

#include <tee_obj.h>
#include <tee_api.h>
#include <utee_defines.h>
#include <utee_mem.h>

#include "crypt_ctx.h"
#include "crypt_random.h"
#include "crypt_engine.h"
	
/*
 * Big Numbers, used by LTC, allocation size
 */
#define tee_bignumbers_ALLOC_SIZE \
	((mpa_StaticVarSizeInU32(LTC_MAX_BITS_PER_VARIABLE)) * sizeof(uint32_t))



/*
 * Set the allocation bytes used for a big number. This is the first uint32_t
 * member of the array representing the big number
 * Equals the total allocation size
 *   minus 4 for the 'alloc' member
 *   minus 4 for the 'size' member
 */
#define SET_MPA_ALLOCSIZE(_x) \
	((uint32_t *)(_x))[0] = (tee_bignumbers_ALLOC_SIZE - 8)

/*
 * Following set of structures contains the "plain" data used by LibTomCrypt
 * Translation to the real LTC types "mpa_numbase_struct"(that is only a collection of pointers)
 * is then straightforward
 */

struct tee_bignumbers {
	uint32_t alloc;
	int32_t size;
	/* store in reverse */
	uint32_t d[ tee_bignumbers_ALLOC_SIZE - sizeof(uint32_t) - sizeof(int32_t) ];
};


/*
 * RSA key pair. Contains the public and private keys.
 * rsa_key is the original type from LTC
 */

struct tee_rsa_key_pair {
	struct tee_bignumbers e;	/* the public exponent */
	struct tee_bignumbers d;	/* The private exponent */
	struct tee_bignumbers N;	/* The modulus */

	/* Next are the CRT parameters, that are optional */
	struct tee_bignumbers p;	/* The p factor of N */
	struct tee_bignumbers q;	/* The q factor of N */
	struct tee_bignumbers qP;	/* The 1/q mod p */
	struct tee_bignumbers dP;	/* The d mod (p - 1) */
	struct tee_bignumbers dQ;	/* The d mod (q - 1) */
};

/*
 * RSA public key. rsa_key is the original type from LTC, with type PK_PUBLIC
 */
struct tee_rsa_public_key {
	struct tee_bignumbers e;	/* the public exponent */
	struct tee_bignumbers N;	/* The modulus */
};

/*
 * DSA key pair. dsa_key is the original type from LTC, with type PK_PRIVATE
 */
struct tee_dsa_key_pair {
	struct tee_bignumbers g;	/* Base generator */
	struct tee_bignumbers p;	/* Prime modulus */
	struct tee_bignumbers q;	/* Order of subgroup */
	struct tee_bignumbers y;	/* Public key */
	struct tee_bignumbers x;	/* Private key */
};

/*
 * DSA public key. dsa_key is the original type from LTC, with type PK_PUBLIC
 */
struct tee_dsa_public_key {
	struct tee_bignumbers g;	/* Base generator */
	struct tee_bignumbers p;	/* Prime modulus */
	struct tee_bignumbers q;	/* Order of subgroup */
	struct tee_bignumbers y;	/* Public key */
};

/*
 * DH key pair. dsa_key is the original type from LTC, with type PK_PRIVATE
 */
struct tee_dh_key_pair {
	struct tee_bignumbers g;	/* Base generator */
	struct tee_bignumbers p;	/* Prime modulus */
	struct tee_bignumbers x;	/* Private key */
	struct tee_bignumbers y;	/* Public key */

	/* other parameters */
	struct tee_bignumbers q;	/* Sub Prime */
	uint32_t xbits;
};



TEE_Result tee_crypt_check_key_type(const struct tee_obj *o, uint32_t algo, TEE_OperationMode mode);

/*
 * Populate the pointers in ltc_key, given struct tee_rsa_key_pair
 */
void tee_populate_rsa_key_pair( rsa_key *ltc_key, struct tee_rsa_key_pair *tee_key, bool crt);

void tee_populate_rsa_public_key( rsa_key *ltc_key, struct tee_rsa_public_key *tee_key);

void tee_populate_dsa_key_pair( dsa_key *ltc_key, struct tee_dsa_key_pair *tee_key);

void tee_populate_dsa_public_key( dsa_key *ltc_key, struct tee_dsa_public_key *tee_key);

void tee_populate_dh_key_pair( dh_key *ltc_key, struct tee_dh_key_pair *tee_key);



/* */
TEE_Result tee_crypt_obj_generate_key(uint32_t obj, uint32_t key_size, 
						const TEE_Attribute *params, uint32_t param_count);

void tee_crypt_free_key(TEE_ObjectHandle hKeyObject);


TEE_Result utee_dump_ltc_rsa_key_obj(uint32_t hKeyObject, uint32_t rsa_key_bits, 
						bool is_KeyPair, uint32_t rawdata);

TEE_Result utee_obj_set_key_rsa(uint32_t hKeyObject, uint32_t rsaKeyBits, 
						void *e, uint32_t e_size, void *n, uint32_t n_size,
						bool isRsaKeyPair);

#endif