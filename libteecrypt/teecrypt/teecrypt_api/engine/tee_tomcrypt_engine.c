#include "tee_tomcrypt_engine.h"


#define LTC_VARIABLE_NUMBER         (50)

static uint32_t _ltc_mempool_u32[mpa_scratch_mem_size_in_U32(
	LTC_VARIABLE_NUMBER, LTC_MAX_BITS_PER_VARIABLE) ];

static void tee_ltc_alloc_mpa(void)
{
	mpa_scratch_mem pool;
	pool = (mpa_scratch_mem_base *) &_ltc_mempool_u32;
	init_mpa_tomcrypt(pool);
	mpa_init_scratch_mem(pool, LTC_VARIABLE_NUMBER, LTC_MAX_BITS_PER_VARIABLE);
}

static void tee_ltc_dealloc_mpa(void)
{
	/*
	 * Nothing to be done as the memory is static
	 */
}

/* Random generator */
static int prng_mpa_start(prng_state *prng)
{
	return CRYPT_OK;
}

static int prng_mpa_add_entropy(const unsigned char *in, unsigned long inlen, prng_state *prng)
{
	// No entropy is required
	return CRYPT_OK;
}

static int prng_mpa_ready(prng_state *prng)
{
	return CRYPT_OK;
}

extern TEE_Result get_rng_array(void *buf, size_t blen);
static unsigned long prng_mpa_read(unsigned char *out, unsigned long outlen, prng_state *prng)
{
	if (TEE_SUCCESS == get_rng_array(out, outlen))
		return outlen;
	else
		return 0;
}

static int prng_mpa_done(prng_state *prng)
{
	return CRYPT_OK;
}

static int prng_mpa_export(unsigned char *out, unsigned long *outlen, prng_state *prng)
{
	return CRYPT_OK;
}

static int prng_mpa_import(const unsigned char *in, unsigned long  inlen, prng_state *prng)
{
	return CRYPT_OK;
}

static int prng_mpa_test(void)
{
	return CRYPT_OK;
}

static const struct ltc_prng_descriptor prng_mpa_desc =
{
	.name = "prng_mpa",
	.export_size = 64,
	.start = &prng_mpa_start,
	.add_entropy = &prng_mpa_add_entropy,
	.ready = &prng_mpa_ready,
	.read = &prng_mpa_read,
	.done = &prng_mpa_done,
	.pexport = &prng_mpa_export,
	.pimport = &prng_mpa_import,
	.test = &prng_mpa_test,
};

/*
 * tee_ltc_reg_algs(): Registers
 *	- algorithms
 *	- hash
 *	- prng (pseudo random generator)
 * This function is copied from reg_algs() from libtomcrypt/test/x86_prof.c
 */

static void tee_ltc_reg_algs(void)
{
#ifdef LTC_RIJNDAEL
	register_cipher(&aes_desc);
#endif
#ifdef LTC_BLOWFISH
	register_cipher(&blowfish_desc);
#endif
#ifdef LTC_XTEA
	register_cipher(&xtea_desc);
#endif
#ifdef LTC_RC5
	register_cipher(&rc5_desc);
#endif
#ifdef LTC_RC6
	register_cipher(&rc6_desc);
#endif
#ifdef LTC_SAFERP
	register_cipher(&saferp_desc);
#endif
#ifdef LTC_TWOFISH
	register_cipher(&twofish_desc);
#endif
#ifdef LTC_SAFER
	register_cipher(&safer_k64_desc);
	register_cipher(&safer_sk64_desc);
	register_cipher(&safer_k128_desc);
	register_cipher(&safer_sk128_desc);
#endif
#ifdef LTC_RC2
	register_cipher(&rc2_desc);
#endif
#ifdef LTC_DES
	register_cipher(&des_desc);
	register_cipher(&des3_desc);
#endif
#ifdef LTC_CAST5
	register_cipher(&cast5_desc);
#endif
#ifdef LTC_NOEKEON
	register_cipher(&noekeon_desc);
#endif
#ifdef LTC_SKIPJACK
	register_cipher(&skipjack_desc);
#endif
#ifdef LTC_KHAZAD
	register_cipher(&khazad_desc);
#endif
#ifdef LTC_ANUBIS
	register_cipher(&anubis_desc);
#endif
#ifdef LTC_KSEED
	register_cipher(&kseed_desc);
#endif
#ifdef LTC_KASUMI
	register_cipher(&kasumi_desc);
#endif

/************************* register SM **************************/
#ifdef LTC_SM_SMS4
	register_cipher(&sm_sms4_desc);
#endif	



#ifdef LTC_TIGER
	register_hash(&tiger_desc);
#endif
#ifdef LTC_MD2
	register_hash(&md2_desc);
#endif
#ifdef LTC_MD4
	register_hash(&md4_desc);
#endif
#ifdef LTC_MD5
	register_hash(&md5_desc);
#endif
#ifdef LTC_SHA1
	register_hash(&sha1_desc);
#endif
#ifdef LTC_SHA224
	register_hash(&sha224_desc);
#endif
#ifdef LTC_SHA256
	register_hash(&sha256_desc);
#endif
#ifdef LTC_SHA384
	register_hash(&sha384_desc);
#endif
#ifdef LTC_SHA512
	register_hash(&sha512_desc);
#endif
#ifdef LTC_RIPEMD128
	register_hash(&rmd128_desc);
#endif
#ifdef LTC_RIPEMD160
	register_hash(&rmd160_desc);
#endif
#ifdef LTC_RIPEMD256
	register_hash(&rmd256_desc);
#endif
#ifdef LTC_RIPEMD320
	register_hash(&rmd320_desc);
#endif
#ifdef LTC_WHIRLPOOL
	register_hash(&whirlpool_desc);
#endif
#ifdef LTC_CHC_HASH
#error LTC_CHC_HASH is not supported
	register_hash(&chc_desc);
	if ((err = chc_register(register_cipher(&aes_desc))) != CRYPT_OK) {
		tee_fprintf(stderr, "chc_register error: %s\n",
		error_to_string(err));
		exit(EXIT_FAILURE);
	}
#endif

#ifndef LTC_NO_PRNGS
#ifndef LTC_YARROW
#error This demo requires Yarrow.
#endif
	register_prng(&yarrow_desc);
#ifdef LTC_FORTUNA
	register_prng(&fortuna_desc);
#endif
#ifdef LTC_RC4
	register_prng(&rc4_desc);
#endif
#ifdef LTC_SPRNG
	register_prng(&sprng_desc);
#endif

	/*
	if ((err = rng_make_prng(128, find_prng("yarrow"),
	     &yarrow_prng, NULL)) != CRYPT_OK) {
		fprintf(stderr, "rng_make_prng failed: %s\n", error_to_string(err));
		exit(EXIT_FAILURE);
	}
	*/
#endif

	register_prng(&prng_mpa_desc);


}


/*
 * Compute the LibTomCrypt "hashindex" given a TEE Algorithm "algo"
 * Return
 * - TEE_SUCCESS in case of success,
 * - TEE_ERROR_BAD_PARAMETERS in case algo is not a valid algo
 * - TEE_ERROR_NOT_SUPPORTED in case algo is not supported by LTC
 * Return -1 in case of error
 */
TEE_Result tee_algo_to_ltc_hashindex(uint32_t algo, int *ltc_hashindex)
{
	switch (algo) {
		case TEE_ALG_RSASSA_PKCS1_V1_5_SHA1:
		case TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA1:
		case TEE_ALG_RSAES_PKCS1_OAEP_MGF1_SHA1:
		case TEE_ALG_SHA1:
		case TEE_ALG_DSA_SHA1:
		case TEE_ALG_HMAC_SHA1:
			*ltc_hashindex = find_hash("sha1");
			break;

		case TEE_ALG_RSASSA_PKCS1_V1_5_MD5:
		case TEE_ALG_MD5:
		case TEE_ALG_HMAC_MD5:
			*ltc_hashindex = find_hash("md5");
			break;

		case TEE_ALG_RSASSA_PKCS1_V1_5_SHA224:
		case TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA224:
		case TEE_ALG_RSAES_PKCS1_OAEP_MGF1_SHA224:
		case TEE_ALG_SHA224:
		case TEE_ALG_HMAC_SHA224:
			*ltc_hashindex = find_hash("sha224");
			break;

		case TEE_ALG_RSASSA_PKCS1_V1_5_SHA256:
		case TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA256:
		case TEE_ALG_RSAES_PKCS1_OAEP_MGF1_SHA256:
		case TEE_ALG_SHA256:
		case TEE_ALG_HMAC_SHA256:
			*ltc_hashindex = find_hash("sha256");
			break;

		case TEE_ALG_RSASSA_PKCS1_V1_5_SHA384:
		case TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA384:
		case TEE_ALG_RSAES_PKCS1_OAEP_MGF1_SHA384:
		case TEE_ALG_SHA384:
		case TEE_ALG_HMAC_SHA384:
			*ltc_hashindex = find_hash("sha384");
			break;

		case TEE_ALG_RSASSA_PKCS1_V1_5_SHA512:
		case TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA512:
		case TEE_ALG_RSAES_PKCS1_OAEP_MGF1_SHA512:
		case TEE_ALG_SHA512:
		case TEE_ALG_HMAC_SHA512:
			*ltc_hashindex = find_hash("sha512");
			break;

		case TEE_ALG_RSAES_PKCS1_V1_5:
			*ltc_hashindex = -1;	/* invalid one. but it should not be used anyway */
			return TEE_SUCCESS;

		default:
			return TEE_ERROR_BAD_PARAMETERS;
	}

	if (*ltc_hashindex < 0)
		return TEE_ERROR_NOT_SUPPORTED;
	else
		return TEE_SUCCESS;
}

/*
 * Compute the LibTomCrypt "cipherindex" given a TEE Algorithm "algo"
 * Return
 * - TEE_SUCCESS in case of success,
 * - TEE_ERROR_BAD_PARAMETERS in case algo is not a valid algo
 * - TEE_ERROR_NOT_SUPPORTED in case algo is not supported by LTC
 * Return -1 in case of error
 */
TEE_Result tee_algo_to_ltc_cipherindex(uint32_t algo, int *ltc_cipherindex)
{

	switch (algo) {
		case TEE_ALG_AES_CBC_MAC_NOPAD:
		case TEE_ALG_AES_CBC_MAC_PKCS5:
		case TEE_ALG_AES_CMAC:
		case TEE_ALG_AES_ECB_NOPAD:
		case TEE_ALG_AES_CBC_NOPAD:
		case TEE_ALG_AES_CTR:
		case TEE_ALG_AES_CTS:
		case TEE_ALG_AES_XTS:
		case TEE_ALG_AES_CCM:
		case TEE_ALG_AES_GCM:
			*ltc_cipherindex = find_cipher("aes");
			break;

		case TEE_ALG_DES_CBC_MAC_NOPAD:
		case TEE_ALG_DES_CBC_MAC_PKCS5:
		case TEE_ALG_DES_ECB_NOPAD:
		case TEE_ALG_DES_CBC_NOPAD:
			*ltc_cipherindex = find_cipher("des");
			break;

		case TEE_ALG_DES3_CBC_MAC_NOPAD:
		case TEE_ALG_DES3_CBC_MAC_PKCS5:
		case TEE_ALG_DES3_ECB_NOPAD:
		case TEE_ALG_DES3_CBC_NOPAD:
			*ltc_cipherindex = find_cipher("3des");
			break;

		case TEE_ALG_SM_SMS4_CBC_NOPAD:
		case TEE_ALG_SM_SMS4_ECB_NOPAD:
			*ltc_cipherindex = find_cipher("sm_sms4");
			break;		
		default:
			return TEE_ERROR_BAD_PARAMETERS;

	}

	if (*ltc_cipherindex < 0)
		return TEE_ERROR_NOT_SUPPORTED;
	else
		return TEE_SUCCESS;

}

void tee_ltc_init(void)
{
	tee_ltc_alloc_mpa();
	tee_ltc_reg_algs();
}

void tee_ltc_deinit(void)
{
	tee_ltc_dealloc_mpa();
}

/*
 * Get the RNG index to use
 */

int tee_ltc_get_rng_mpa(void)
{
	static int first = 1;
	static int lindex = -1;

	if (first) {
		lindex = find_prng("prng_mpa");
		first = 0;
	}
	return lindex;
}


/**************************************** synmm cipher Algorithm *****************************************/

/*
 * From Global Platform: CTS = CBC-CS3
 */

struct symmetric_CTS {
	symmetric_ECB ecb;
	symmetric_CBC cbc;
};

TEE_Result tee_cipher_get_block_size(uint32_t algo, size_t *size)
{
	TEE_Result res;
	int ltc_cipherindex;

	res = tee_algo_to_ltc_cipherindex(algo, &ltc_cipherindex);
	if (res != TEE_SUCCESS)
		return TEE_ERROR_NOT_SUPPORTED;

	*size = cipher_descriptor[ltc_cipherindex].block_length;
	return TEE_SUCCESS;
}

TEE_Result tee_cipher_get_ctx_size(uint32_t algo, size_t *size)
{
	switch (algo) {
		case TEE_ALG_AES_ECB_NOPAD:
			*size = sizeof(symmetric_ECB);
			break;
		case TEE_ALG_AES_CBC_NOPAD:
			*size = sizeof(symmetric_CBC);
			break;
		case TEE_ALG_AES_CTR:
			*size = sizeof(symmetric_CTR);
			break;
		case TEE_ALG_AES_CTS:
			*size = sizeof(struct symmetric_CTS);
			break;
		case TEE_ALG_AES_XTS:
			*size = sizeof(symmetric_xts);
			break;
		case TEE_ALG_DES_ECB_NOPAD:
			*size = sizeof(symmetric_ECB);
			break;
		case TEE_ALG_DES_CBC_NOPAD:
			*size = sizeof(symmetric_CBC);
			break;
		case TEE_ALG_DES3_ECB_NOPAD:
			*size = sizeof(symmetric_ECB);
			break;
		case TEE_ALG_DES3_CBC_NOPAD:
			*size = sizeof(symmetric_CBC);
			break;

		case TEE_ALG_SM_SMS4_ECB_NOPAD:
			*size = sizeof(symmetric_ECB);
			break;

		case TEE_ALG_SM_SMS4_CBC_NOPAD:
			*size = sizeof(symmetric_CBC);
			break;

		default:
			return TEE_ERROR_NOT_SUPPORTED;

	}

	return TEE_SUCCESS;
}

TEE_Result tee_cipher_init(void *ctx, uint32_t algo,
			   TEE_OperationMode mode, const uint8_t *key,
			   size_t key_len)
{
	return tee_cipher_init3(ctx, algo, mode, key, key_len, NULL, 0, NULL,
				0);
}

TEE_Result tee_cipher_init2(void *ctx, uint32_t algo,
			    TEE_OperationMode mode, const uint8_t *key,
			    size_t key_len, const uint8_t *iv, size_t iv_len)
{
	return tee_cipher_init3(ctx, algo, mode, key, key_len, NULL, 0, iv,
				iv_len);
}

static void get_des2_key(
	const uint8_t *key, size_t key_len,
	uint8_t *key_intermediate,
	uint8_t **real_key, size_t *real_key_len)
{
	if (key_len == 16) {
		/*
		 * This corresponds to a 2DES key. The 2DES encryption
		 * algorithm is similar to 3DES. Both perform and
		 * encryption step, then a decryption step, followed
		 * by another encryption step (EDE). However 2DES uses
		 * the same key for both of the encryption (E) steps.
		 */
		utee_mem_copy(key_intermediate, key, 16);
		utee_mem_copy(key_intermediate+16, key, 8);
		*real_key = key_intermediate;
		*real_key_len = 24;
	} else {
		*real_key = (uint8_t *)key;
		*real_key_len = key_len;
	}
}

TEE_Result tee_cipher_init3(void *ctx, uint32_t algo,
			    TEE_OperationMode mode, const uint8_t *key1,
			    size_t key1_len, const uint8_t *key2,
			    size_t key2_len, const uint8_t *iv, size_t iv_len)
{
	TEE_Result res;
	int ltc_res, ltc_cipherindex;
	uint8_t *real_key, key_array[24];
	size_t real_key_len;
	struct symmetric_CTS *cts;

	res = tee_algo_to_ltc_cipherindex(algo, &ltc_cipherindex);
	if (res != TEE_SUCCESS)
		return TEE_ERROR_NOT_SUPPORTED;

	//utee_printf(" ++++++++++++ ltc_cipherindex = %d ++++++++++++\n",ltc_cipherindex);
	//utee_mem_hexdump("cipher key1",(void*)key1, key1_len, 16, 1);

	switch (algo) {
		case TEE_ALG_AES_ECB_NOPAD:

		case TEE_ALG_DES_ECB_NOPAD:

		case TEE_ALG_SM_SMS4_ECB_NOPAD:

			ltc_res = ecb_start( ltc_cipherindex, key1, key1_len, 0, (symmetric_ECB *)ctx);
			if(ltc_res != 0) {
				utee_printf("[err] ECB_NOPAD::ecb_start\n");
				return TEE_ERROR_NOT_SUPPORTED;
			}
			break;

		case TEE_ALG_DES3_ECB_NOPAD:
			/* either des3 or des2, depending on the size of the key */
			get_des2_key(key1, key1_len, key_array, &real_key, &real_key_len);
			ltc_res = ecb_start( ltc_cipherindex, real_key, real_key_len, 0, (symmetric_ECB *)ctx);
			break;

		
		case TEE_ALG_AES_CBC_NOPAD:
		
		case TEE_ALG_DES_CBC_NOPAD:
		
		case TEE_ALG_SM_SMS4_CBC_NOPAD:
		
			if (iv_len != (size_t)cipher_descriptor[ltc_cipherindex].block_length) {
				utee_printf("iv_len[%d] must be %d Bytes\n",iv_len, (size_t)cipher_descriptor[ltc_cipherindex].block_length);
				return TEE_ERROR_BAD_PARAMETERS;
			}
		
			ltc_res = cbc_start( ltc_cipherindex, iv, key1, key1_len, 0, (symmetric_CBC *)ctx);
			if(ltc_res != 0) {
				utee_printf("[err] CBC_NOPAD::cbc_start\n");
				return TEE_ERROR_NOT_SUPPORTED;
			}
			break;

		case TEE_ALG_DES3_CBC_NOPAD:
			/* either des3 or des2, depending on the size of the key */
			get_des2_key(key1, key1_len, key_array, &real_key, &real_key_len);
			if (iv_len != (size_t)cipher_descriptor[ltc_cipherindex].block_length) {
				utee_printf("iv_len[%d] must be %d Bytes\n",iv_len, (size_t)cipher_descriptor[ltc_cipherindex].block_length);
				return TEE_ERROR_BAD_PARAMETERS;
			}
			ltc_res = cbc_start( ltc_cipherindex, iv, real_key, real_key_len, 0, (symmetric_CBC *)ctx);
			break;

		case TEE_ALG_AES_CTR:
			if (iv_len != (size_t)cipher_descriptor[ltc_cipherindex].block_length) {
				utee_printf("iv_len[%d] must be %d Bytes\n",iv_len, (size_t)cipher_descriptor[ltc_cipherindex].block_length);
				return TEE_ERROR_BAD_PARAMETERS;
			}
			ltc_res = ctr_start( ltc_cipherindex, iv, key1, key1_len, 0, CTR_COUNTER_BIG_ENDIAN, (symmetric_CTR *)ctx);
			break;

		case TEE_ALG_AES_CTS:
			cts = (struct symmetric_CTS *)ctx;
			res = tee_cipher_init3( (void *)(&(cts->ecb)), TEE_ALG_AES_ECB_NOPAD, mode,
					key1, key1_len, key2, key2_len, iv, iv_len);
			if (res != TEE_SUCCESS)
				return res;
			res = tee_cipher_init3( (void *)(&(cts->cbc)), TEE_ALG_AES_CBC_NOPAD, mode,
					key1, key1_len, key2, key2_len, iv, iv_len);
			if (res != TEE_SUCCESS)
				return res;
			ltc_res = CRYPT_OK;
			break;

		case TEE_ALG_AES_XTS:
			if (key1_len != key2_len)
				return TEE_ERROR_BAD_PARAMETERS;
			ltc_res = xts_start( ltc_cipherindex, key1, key2, key1_len, 0, (symmetric_xts *)ctx);
			break;
		default:
			return TEE_ERROR_NOT_SUPPORTED;
	}

	if (ltc_res == CRYPT_OK)
		return TEE_SUCCESS;
	else
		return TEE_ERROR_BAD_STATE;
}

TEE_Result tee_cipher_update(void *ctx, uint32_t algo,
			     TEE_OperationMode mode, bool last_block,
			     const uint8_t *data, size_t len, uint8_t *dst)
{
	TEE_Result res;
	int ltc_res = CRYPT_OK;
	size_t block_size;
	uint8_t tmp_block[64], tmp2_block[64];
	int nb_blocks, len_last_block;
	struct symmetric_CTS *cts;

	/*
	 * Check that the block contains the correct number of data, apart
	 * for the last block in some XTS / CTR / XTS mode
	 */
	res = tee_cipher_get_block_size(algo, &block_size);
	if (res != TEE_SUCCESS)
		return res;
	if ((len % block_size) != 0) {
		if (!last_block)
			return TEE_ERROR_BAD_PARAMETERS;

		switch (algo) {
			case TEE_ALG_SM_SMS4_ECB_NOPAD:
			case TEE_ALG_SM_SMS4_CBC_NOPAD:
			case TEE_ALG_AES_ECB_NOPAD:
			case TEE_ALG_DES_ECB_NOPAD:
			case TEE_ALG_DES3_ECB_NOPAD:
			case TEE_ALG_AES_CBC_NOPAD:
			case TEE_ALG_DES_CBC_NOPAD:
			case TEE_ALG_DES3_CBC_NOPAD:
				utee_printf("[err] size of last_block must be %d Bytes\n", block_size);		
				return TEE_ERROR_BAD_PARAMETERS;

			case TEE_ALG_AES_CTR:
			case TEE_ALG_AES_XTS:
			case TEE_ALG_AES_CTS:
				/*
				 * These modes doesn't require padding for the last
				 * block.
				 *
				 * This isn't entirely true, both XTS and CTS can only
				 * encrypt minimum one block and also they need at least
				 * one complete block in the last update to finish the
				 * encryption. The algorithms are supposed to detect
				 * that, we're only making sure that all data fed up to
				 * that point consists of complete blocks.
				 */
				break;

			default:
				return TEE_ERROR_NOT_SUPPORTED;
		}
	}

	switch (algo) {
		
		case TEE_ALG_AES_ECB_NOPAD:
		
		case TEE_ALG_DES_ECB_NOPAD:
		
		case TEE_ALG_DES3_ECB_NOPAD:

		case TEE_ALG_SM_SMS4_ECB_NOPAD:
		
			if (mode == TEE_MODE_ENCRYPT) {
			    ltc_res = ecb_encrypt(data, dst, len, (symmetric_ECB *)ctx);
				if(ltc_res != 0) {
					utee_printf("[err] ECB_NOPAD::ecb_encrypt\n");
					return TEE_ERROR_NOT_SUPPORTED;
				}
			}
			else {
			    ltc_res = ecb_decrypt(data, dst, len, (symmetric_ECB *)ctx);
				if(ltc_res != 0) {
					utee_printf("[err] ECB_NOPAD::ecb_decrypt\n");
					return TEE_ERROR_NOT_SUPPORTED;
				}
			}
			break;


		case TEE_ALG_AES_CBC_NOPAD:
		
		case TEE_ALG_DES_CBC_NOPAD:
		
		case TEE_ALG_DES3_CBC_NOPAD:

		case TEE_ALG_SM_SMS4_CBC_NOPAD:
		
			if (mode == TEE_MODE_ENCRYPT) {
			    ltc_res = cbc_encrypt(data, dst, len, (symmetric_CBC *)ctx);
				if(ltc_res != 0) {
					utee_printf("[err] CBC_NOPAD::cbc_encrypt\n");
					return TEE_ERROR_NOT_SUPPORTED;
				}
			}
			else {
			    ltc_res = cbc_decrypt(data, dst, len, (symmetric_CBC *)ctx);
				if(ltc_res != 0) {
					utee_printf("[err] CBC_NOPAD::cbc_decrypt\n");
					return TEE_ERROR_NOT_SUPPORTED;
				}
			}
			break;

		case TEE_ALG_AES_CTR:
			if (mode == TEE_MODE_ENCRYPT)
			    ltc_res = ctr_encrypt(data, dst, len, (symmetric_CTR *)ctx);
			else
			    ltc_res = ctr_decrypt(data, dst, len, (symmetric_CTR *)ctx);
			break;

		case TEE_ALG_AES_XTS:
			return TEE_ERROR_NOT_SUPPORTED;

			break;

		case TEE_ALG_AES_CTS:
			/*
			 * From http://en.wikipedia.org/wiki/Ciphertext_stealing
			 * CBC ciphertext stealing encryption using a standard
			 * CBC interface:
			 *	1. Pad the last partial plaintext block with 0.
			 *	2. Encrypt the whole padded plaintext using the
			 *	   standard CBC mode.
			 *	3. Swap the last two ciphertext blocks.
			 *	4. Truncate the ciphertext to the length of the
			 *	   original plaintext.
			 *
			 * CBC ciphertext stealing decryption using a standard
			 * CBC interface
			 *	1. Dn = Decrypt (K, Cn-1). Decrypt the second to last
			 *	   ciphertext block.
			 *	2. Cn = Cn || Tail (Dn, B-M). Pad the ciphertext to the
			 *	   nearest multiple of the block size using the last
			 *	   B-M bits of block cipher decryption of the
			 *	   second-to-last ciphertext block.
			 *	3. Swap the last two ciphertext blocks.
			 *	4. Decrypt the (modified) ciphertext using the standard
			 *	   CBC mode.
			 *	5. Truncate the plaintext to the length of the original
			 *	   ciphertext.
			 */
			cts = (struct symmetric_CTS *)ctx;
			if (!last_block)
				return tee_cipher_update(
					&cts->cbc, TEE_ALG_AES_CBC_NOPAD, mode,
					last_block, data, len, dst);

			/* Compute the last block length and check constraints */
			if (block_size > 64)
				return TEE_ERROR_BAD_STATE;
			nb_blocks = ((len + block_size - 1) / block_size);
			if (nb_blocks < 2)
				return TEE_ERROR_BAD_STATE;
			len_last_block = len % block_size;
			if (len_last_block == 0)
				len_last_block = block_size;

			if (mode == TEE_MODE_ENCRYPT) {
				utee_mem_copy(tmp_block,
				       data + ((nb_blocks - 1) * block_size),
				       len_last_block);
				utee_mem_fill(tmp_block + len_last_block,
				       0,
				       block_size - len_last_block);

				res = tee_cipher_update(
					&cts->cbc, TEE_ALG_AES_CBC_NOPAD, mode, 0,
					data, (nb_blocks - 1) * block_size, dst);
				if (res != TEE_SUCCESS)
					return res;

				utee_mem_copy(dst + (nb_blocks - 1) * block_size,
				       dst + (nb_blocks - 2) * block_size,
				       len_last_block);

				res = tee_cipher_update(
					&cts->cbc, TEE_ALG_AES_CBC_NOPAD, mode, 0,
					tmp_block,
					block_size,
					dst + (nb_blocks - 2) * block_size);
				if (res != TEE_SUCCESS)
					return res;
			} else {
				/* 1. Decrypt the second to last ciphertext block */
				res = tee_cipher_update(
					&cts->ecb, TEE_ALG_AES_ECB_NOPAD, mode, 0,
					data + (nb_blocks - 2) * block_size,
					block_size,
					tmp2_block);
				if (res != TEE_SUCCESS)
					return res;

				/* 2. Cn = Cn || Tail (Dn, B-M) */
				utee_mem_copy(tmp_block,
				       data + ((nb_blocks - 1) * block_size),
				       len_last_block);
				utee_mem_copy(tmp_block + len_last_block,
				       tmp2_block + len_last_block,
				       block_size - len_last_block);

				/* 3. Swap the last two ciphertext blocks */
				/* done by passing the correct buffers in step 4. */

				/* 4. Decrypt the (modified) ciphertext */
				if (nb_blocks > 2) {
					res = tee_cipher_update(
						&cts->cbc, TEE_ALG_AES_CBC_NOPAD,
						mode, 0,
						data,
						(nb_blocks - 2) * block_size,
						dst);
					if (res != TEE_SUCCESS)
						return res;
				}

				res = tee_cipher_update(
					&cts->cbc, TEE_ALG_AES_CBC_NOPAD, mode, 0,
					tmp_block,
					block_size,
					dst + ((nb_blocks - 2) * block_size));
				if (res != TEE_SUCCESS)
					return res;

				res = tee_cipher_update(
					&cts->cbc, TEE_ALG_AES_CBC_NOPAD, mode, 0,
					data + ((nb_blocks - 2) * block_size),
					block_size,
					tmp_block);
				if (res != TEE_SUCCESS)
					return res;

				/* 5. Truncate the plaintext */
				utee_mem_copy(dst + (nb_blocks - 1) * block_size,
				       tmp_block,
				       len_last_block);
				break;
			}
			break;

		default:
			return TEE_ERROR_NOT_SUPPORTED;
	}

	if (ltc_res == CRYPT_OK)
		return TEE_SUCCESS;
	else
		return TEE_ERROR_BAD_STATE;
}

void tee_cipher_final(void *ctx, uint32_t algo)
{
	switch (algo) {

		case TEE_ALG_AES_ECB_NOPAD:
		
		case TEE_ALG_DES_ECB_NOPAD:
		
		case TEE_ALG_DES3_ECB_NOPAD:
		
		case TEE_ALG_SM_SMS4_ECB_NOPAD:
			ecb_done((symmetric_ECB *)ctx);
			break;


		case TEE_ALG_AES_CBC_NOPAD:

		case TEE_ALG_DES_CBC_NOPAD:

		case TEE_ALG_DES3_CBC_NOPAD:

		case TEE_ALG_SM_SMS4_CBC_NOPAD:
			cbc_done((symmetric_CBC *)ctx);
			break;

		case TEE_ALG_AES_CTR:
			ctr_done((symmetric_CTR *)ctx);
			break;

		case TEE_ALG_AES_XTS:
			xts_done((symmetric_xts *)ctx);
			break;

		case TEE_ALG_AES_CTS:
			cbc_done(&(((struct symmetric_CTS *)ctx)->cbc));
			ecb_done(&(((struct symmetric_CTS *)ctx)->ecb));
			break;

		default:
			/* TEE_ERROR_NOT_SUPPORTED; */
			break;
	}
}





/**************************************** HASH Algorithm *****************************************/

#define MAX_DIGEST 64

TEE_Result tee_hash_get_digest_size(uint32_t algo, size_t *size)
{
	int ltc_res, ltc_hashindex;

	ltc_res = tee_algo_to_ltc_hashindex(algo, &ltc_hashindex);
	if (ltc_res != TEE_SUCCESS)
		return TEE_ERROR_NOT_SUPPORTED;

	*size = hash_descriptor[ltc_hashindex].hashsize;
	return TEE_SUCCESS;
	
}

TEE_Result tee_hash_get_ctx_size(uint32_t algo, size_t *size)
{
	switch (algo) {
	case TEE_ALG_MD5:
	case TEE_ALG_SHA224:
	case TEE_ALG_SHA1:
	case TEE_ALG_SHA256:
	case TEE_ALG_SHA384:
	case TEE_ALG_SHA512:
	case TEE_ALG_HMAC_MD5:
	case TEE_ALG_HMAC_SHA224:
	case TEE_ALG_HMAC_SHA1:
	case TEE_ALG_HMAC_SHA256:
	case TEE_ALG_HMAC_SHA384:
	case TEE_ALG_HMAC_SHA512:
		*size = sizeof(hash_state);
		break;
	default:
		return TEE_ERROR_NOT_SUPPORTED;
	}

	return TEE_SUCCESS;
}

TEE_Result tee_hash_init(void *ctx, uint32_t algo)
{
	int ltc_res, ltc_hashindex;

	ltc_res = tee_algo_to_ltc_hashindex(algo, &ltc_hashindex);
	if (ltc_res != TEE_SUCCESS)
		return TEE_ERROR_NOT_SUPPORTED;

	if (hash_descriptor[ltc_hashindex].init(ctx) == CRYPT_OK)
		return TEE_SUCCESS;
	else
		return TEE_ERROR_BAD_STATE;
}

TEE_Result tee_hash_update(void *ctx, uint32_t algo,
			   const uint8_t *data, size_t len)
{
	int ltc_res, ltc_hashindex;

	ltc_res = tee_algo_to_ltc_hashindex(algo, &ltc_hashindex);
	if (ltc_res != TEE_SUCCESS)
		return TEE_ERROR_NOT_SUPPORTED;

	if (hash_descriptor[ltc_hashindex].process(ctx, data, len) == CRYPT_OK)
		return TEE_SUCCESS;
	else
		return TEE_ERROR_BAD_STATE;
}

TEE_Result tee_hash_final(void *ctx, uint32_t algo, uint8_t *digest, size_t len)
{
	int ltc_res, ltc_hashindex;
	size_t hash_size;
	uint8_t block_digest[MAX_DIGEST], *tmp_digest;

	ltc_res = tee_algo_to_ltc_hashindex(algo, &ltc_hashindex);
	if (ltc_res != TEE_SUCCESS)
		return TEE_ERROR_NOT_SUPPORTED;

	if (len == 0)
		return TEE_ERROR_BAD_PARAMETERS;

	hash_size = hash_descriptor[ltc_hashindex].hashsize;
	if ((hash_size < len) || (hash_size > MAX_DIGEST)) {
		/*
		 * Caller is asking for more bytes than the computation
		 * will produce ... might be something wrong
		 */
		return  TEE_ERROR_BAD_PARAMETERS;
	}

	if (hash_size > len) {
		/* use a tempory buffer */
		tmp_digest = block_digest;
	} else {
		tmp_digest = digest;
	}

	if (hash_descriptor[ltc_hashindex].done(ctx, tmp_digest) == CRYPT_OK) {
		if (hash_size > len)
			utee_mem_copy(digest, tmp_digest, len);
	} else {
		return TEE_ERROR_BAD_STATE;
	}

	return TEE_SUCCESS;
}

TEE_Result tee_hash_createdigest(
		uint32_t algo,
		const uint8_t *data, size_t datalen,
		uint8_t *digest, size_t digestlen)
{
	TEE_Result res = TEE_ERROR_BAD_STATE;
	void *ctx = NULL;
	size_t ctxsize;

	if (tee_hash_get_ctx_size(algo, &ctxsize) != TEE_SUCCESS) {
		res = TEE_ERROR_NOT_SUPPORTED;
		goto out;
	}

	ctx = utee_mem_alloc(ctxsize);
	if (ctx == NULL) {
		res = TEE_ERROR_OUT_OF_MEMORY;
		goto out;
	}

	if (tee_hash_init(ctx, algo) != TEE_SUCCESS)
		goto out;

	if (datalen != 0) {
		if (tee_hash_update(ctx, algo, data, datalen) != TEE_SUCCESS)
			goto out;
	}

	if (tee_hash_final(ctx, algo, digest, digestlen) != TEE_SUCCESS)
		goto out;

	res = TEE_SUCCESS;

out:
	if (ctx)
		utee_mem_free(ctx);

	return res;
}

TEE_Result tee_hash_check(
		uint32_t algo,
		const uint8_t *hash, size_t hash_size,
		const uint8_t *data, size_t data_size)
{
	TEE_Result res;
	uint8_t digest[MAX_DIGEST];
	size_t digestlen;

	res = tee_hash_get_digest_size(algo, &digestlen);
	if (res != TEE_SUCCESS)
		return TEE_ERROR_BAD_PARAMETERS;
	if ((hash_size == 0) ||
	    (digestlen < hash_size) ||
	    (digestlen > MAX_DIGEST))
		return TEE_ERROR_BAD_PARAMETERS;

	res = tee_hash_createdigest(algo, data, data_size, digest, digestlen);
	if (res != TEE_SUCCESS)
		return res;

	if (utee_mem_cmp(digest, hash, hash_size) != 0)
		return TEE_ERROR_SECURITY;

	return TEE_SUCCESS;
}



/**************************************** MAC Algorithm *****************************************/


/*
 * CBC-MAC is not implemented in Libtomcrypt
 * This is implemented here as being the plain text which is encoded with IV=0.
 * Result of the CBC-MAC is the last 16-bytes cipher.
 */

#define CBCMAC_MAX_BLOCK_LEN 16
struct cbc_state {
	symmetric_CBC cbc;
	uint8_t block[CBCMAC_MAX_BLOCK_LEN];
	uint8_t digest[CBCMAC_MAX_BLOCK_LEN];
	size_t current_block_len, block_len;
	int is_computed;
};

TEE_Result tee_mac_get_digest_size(uint32_t algo, size_t *size)
{
	TEE_Result res;

	switch (algo) {
	case TEE_ALG_HMAC_MD5:
	case TEE_ALG_HMAC_SHA224:
	case TEE_ALG_HMAC_SHA1:
	case TEE_ALG_HMAC_SHA256:
	case TEE_ALG_HMAC_SHA384:
	case TEE_ALG_HMAC_SHA512:
		res = tee_hash_get_digest_size(algo, size);
		return res;
	case TEE_ALG_AES_CBC_MAC_NOPAD:
	case TEE_ALG_AES_CBC_MAC_PKCS5:
	case TEE_ALG_AES_CMAC:
	case TEE_ALG_DES_CBC_MAC_NOPAD:
	case TEE_ALG_DES_CBC_MAC_PKCS5:
	case TEE_ALG_DES3_CBC_MAC_NOPAD:
	case TEE_ALG_DES3_CBC_MAC_PKCS5:
		res = tee_cipher_get_block_size(algo, size);
		return res;

	default:
		return TEE_ERROR_NOT_SUPPORTED;
	}
}

TEE_Result tee_mac_get_ctx_size(uint32_t algo, size_t *size)
{
	switch (algo) {
	case TEE_ALG_HMAC_MD5:
	case TEE_ALG_HMAC_SHA224:
	case TEE_ALG_HMAC_SHA1:
	case TEE_ALG_HMAC_SHA256:
	case TEE_ALG_HMAC_SHA384:
	case TEE_ALG_HMAC_SHA512:
		*size = sizeof(hmac_state);
		break;

	case TEE_ALG_AES_CBC_MAC_NOPAD:
	case TEE_ALG_AES_CBC_MAC_PKCS5:
	case TEE_ALG_DES_CBC_MAC_NOPAD:
	case TEE_ALG_DES_CBC_MAC_PKCS5:
	case TEE_ALG_DES3_CBC_MAC_NOPAD:
	case TEE_ALG_DES3_CBC_MAC_PKCS5:
		*size = sizeof(struct cbc_state);
		break;

	case TEE_ALG_AES_CMAC:
		*size = sizeof(omac_state);
		break;

	default:
		return TEE_ERROR_NOT_SUPPORTED;
	}

	return TEE_SUCCESS;
}

TEE_Result tee_mac_init(
	void *ctx, uint32_t algo, const uint8_t *key, size_t len)
{
	TEE_Result res;
	int ltc_hashindex, ltc_cipherindex;
	uint8_t iv[CBCMAC_MAX_BLOCK_LEN];
	struct cbc_state *cbc;

	switch (algo) {
	case TEE_ALG_HMAC_MD5:
	case TEE_ALG_HMAC_SHA224:
	case TEE_ALG_HMAC_SHA1:
	case TEE_ALG_HMAC_SHA256:
	case TEE_ALG_HMAC_SHA384:
	case TEE_ALG_HMAC_SHA512:
		res = tee_algo_to_ltc_hashindex(algo, &ltc_hashindex);
		if (res != TEE_SUCCESS)
		{
			return res;
		}
		if (CRYPT_OK != hmac_init((hmac_state *)ctx, ltc_hashindex, key, len))
		{
			return TEE_ERROR_BAD_STATE;
		}
		break;

	case TEE_ALG_AES_CBC_MAC_NOPAD:
	case TEE_ALG_AES_CBC_MAC_PKCS5:
	case TEE_ALG_DES_CBC_MAC_NOPAD:
	case TEE_ALG_DES_CBC_MAC_PKCS5:
	case TEE_ALG_DES3_CBC_MAC_NOPAD:
	case TEE_ALG_DES3_CBC_MAC_PKCS5:
		cbc = (struct cbc_state *)ctx;

		res = tee_algo_to_ltc_cipherindex(algo, &ltc_cipherindex);
		if (res != TEE_SUCCESS)
			return res;

		cbc->block_len =
			cipher_descriptor[ltc_cipherindex].block_length;
		if (CBCMAC_MAX_BLOCK_LEN < cbc->block_len)
			return TEE_ERROR_BAD_PARAMETERS;
		utee_mem_fill(iv, 0, cbc->block_len);

		if (CRYPT_OK != cbc_start(
			ltc_cipherindex, iv, key, len, 0, &cbc->cbc))
				return TEE_ERROR_BAD_STATE;
		cbc->is_computed = 0;
		cbc->current_block_len = 0;
		break;

	case TEE_ALG_AES_CMAC:
		res = tee_algo_to_ltc_cipherindex(algo, &ltc_cipherindex);
		if (res != TEE_SUCCESS)
			return res;
		if (CRYPT_OK != omac_init((omac_state *)ctx, ltc_cipherindex,
					  key, len))
			return TEE_ERROR_BAD_STATE;
		break;
	default:
		return TEE_ERROR_NOT_SUPPORTED;
	}

	return TEE_SUCCESS;
}

TEE_Result tee_mac_update(
	void *ctx, uint32_t algo, const uint8_t *data, size_t len)
{
	int ltc_res;
	struct cbc_state *cbc;
	size_t pad_len;

	switch (algo) {
	case TEE_ALG_HMAC_MD5:
	case TEE_ALG_HMAC_SHA224:
	case TEE_ALG_HMAC_SHA1:
	case TEE_ALG_HMAC_SHA256:
	case TEE_ALG_HMAC_SHA384:
	case TEE_ALG_HMAC_SHA512:
		if (CRYPT_OK != hmac_process((hmac_state *)ctx, data, len))
		{
			return TEE_ERROR_BAD_STATE;			
		}
		break;

	case TEE_ALG_AES_CBC_MAC_NOPAD:
	case TEE_ALG_AES_CBC_MAC_PKCS5:
	case TEE_ALG_DES_CBC_MAC_NOPAD:
	case TEE_ALG_DES_CBC_MAC_PKCS5:
	case TEE_ALG_DES3_CBC_MAC_NOPAD:
	case TEE_ALG_DES3_CBC_MAC_PKCS5:
		cbc = (struct cbc_state *)ctx;

		if ((cbc->current_block_len > 0) &&
		    (len + cbc->current_block_len >= cbc->block_len)) {
			pad_len = cbc->block_len - cbc->current_block_len;
			utee_mem_copy(cbc->block + cbc->current_block_len,
			       data, pad_len);
			data += pad_len;
			len -= pad_len;
			ltc_res = cbc_encrypt(cbc->block, cbc->digest,
					      cbc->block_len, &cbc->cbc);
			if (CRYPT_OK != ltc_res)
				return TEE_ERROR_BAD_STATE;
			cbc->is_computed = 1;
		}

		while (len >= cbc->block_len) {
			ltc_res = cbc_encrypt(data, cbc->digest,
					      cbc->block_len, &cbc->cbc);
			if (CRYPT_OK != ltc_res)
				return TEE_ERROR_BAD_STATE;
			cbc->is_computed = 1;
			data += cbc->block_len;
			len -= cbc->block_len;
		}

		if (len > 0)
			utee_mem_copy(cbc->block, data, len);
		cbc->current_block_len = len;
		break;

	case TEE_ALG_AES_CMAC:
		if (CRYPT_OK != omac_process((omac_state *)ctx, data, len))
			return TEE_ERROR_BAD_STATE;
		break;

	default:
		return TEE_ERROR_NOT_SUPPORTED;
	}
	
	return TEE_SUCCESS;
}

TEE_Result tee_mac_final(
	void *ctx, uint32_t algo,
	const uint8_t *data, size_t data_len,
	uint8_t *digest, size_t digest_len)
{
	struct cbc_state *cbc;
	size_t pad_len;

	switch (algo) {
	case TEE_ALG_HMAC_MD5:
	case TEE_ALG_HMAC_SHA224:
	case TEE_ALG_HMAC_SHA1:
	case TEE_ALG_HMAC_SHA256:
	case TEE_ALG_HMAC_SHA384:
	case TEE_ALG_HMAC_SHA512:
		if (CRYPT_OK != hmac_process((hmac_state *)ctx, data, data_len))
			return TEE_ERROR_BAD_STATE;

		if (CRYPT_OK != hmac_done((hmac_state *)ctx, digest,
					  (unsigned long *)&digest_len))
			return TEE_ERROR_BAD_STATE;
		break;

	case TEE_ALG_AES_CBC_MAC_NOPAD:
	case TEE_ALG_AES_CBC_MAC_PKCS5:
	case TEE_ALG_DES_CBC_MAC_NOPAD:
	case TEE_ALG_DES_CBC_MAC_PKCS5:
	case TEE_ALG_DES3_CBC_MAC_NOPAD:
	case TEE_ALG_DES3_CBC_MAC_PKCS5:
		cbc = (struct cbc_state *)ctx;

		if (TEE_SUCCESS != tee_mac_update(ctx, algo, data, data_len))
			return TEE_ERROR_BAD_STATE;

		/* Padding is required */
		switch (algo) {
		case TEE_ALG_AES_CBC_MAC_PKCS5:
		case TEE_ALG_DES_CBC_MAC_PKCS5:
		case TEE_ALG_DES3_CBC_MAC_PKCS5:
			/*
			 * Padding is in whole bytes. The value of each added
			 * byte is the number of bytes that are added, i.e. N
			 * bytes, each of value N are added
			 */
			pad_len = cbc->block_len - cbc->current_block_len;
			utee_mem_fill(cbc->block+cbc->current_block_len,
			       pad_len, pad_len);
			cbc->current_block_len = 0;
			if (TEE_SUCCESS != tee_mac_update(
				ctx, algo, cbc->block, cbc->block_len))
					return TEE_ERROR_BAD_STATE;
			break;
		default:
			/* nothing to do */
			break;
		}

		if ((!cbc->is_computed) || (cbc->current_block_len != 0))
			return TEE_ERROR_BAD_STATE;

		utee_mem_copy(digest, cbc->digest, MIN(digest_len, cbc->block_len));
		tee_cipher_final(&cbc->cbc, algo);
		break;

	case TEE_ALG_AES_CMAC:
		if (CRYPT_OK != omac_process((omac_state *)ctx, data, data_len))
			return TEE_ERROR_BAD_STATE;
		if (CRYPT_OK != omac_done((omac_state *)ctx, digest,
					  (unsigned long *)&digest_len))
			return TEE_ERROR_BAD_STATE;
		break;
	default:
		return TEE_ERROR_NOT_SUPPORTED;
	}

	return TEE_SUCCESS;
}






/**************************************** asynmm cipher Algorithm *****************************************/



TEE_Result tee_acipher_gen_rsa_keys(rsa_key *ltc_key, size_t key_size)
{
	TEE_Result res;
	rsa_key ltc_tmp_key;
	int ltc_res;

	/* Get the rsa key */
	ltc_res = rsa_make_key(
		0, tee_ltc_get_rng_mpa(), key_size/8, 65537, &ltc_tmp_key);
	if (ltc_res != CRYPT_OK) {
		res = TEE_ERROR_BAD_PARAMETERS;
	} else if ((size_t)mp_count_bits(ltc_tmp_key.N) != key_size) {
		rsa_free(&ltc_tmp_key);
		res = TEE_ERROR_BAD_PARAMETERS;
	} else {
		/* copy the key */
		ltc_mp.copy(ltc_tmp_key.e,  ltc_key->e);
		ltc_mp.copy(ltc_tmp_key.d,  ltc_key->d);
		ltc_mp.copy(ltc_tmp_key.N,  ltc_key->N);
		ltc_mp.copy(ltc_tmp_key.p,  ltc_key->p);
		ltc_mp.copy(ltc_tmp_key.q,  ltc_key->q);
		ltc_mp.copy(ltc_tmp_key.qP, ltc_key->qP);
		ltc_mp.copy(ltc_tmp_key.dP, ltc_key->dP);
		ltc_mp.copy(ltc_tmp_key.dQ, ltc_key->dQ);

		/* utee_mem_free the tempory key */
		rsa_free(&ltc_tmp_key);
		res = TEE_SUCCESS;
	}
	return res;
}

TEE_Result tee_acipher_gen_dh_keys(dh_key *ltc_key, void *q, size_t xbits)
{
	TEE_Result res;
	dh_key ltc_tmp_key;
	int ltc_res;

	/* Get the dh key */
	ltc_tmp_key.g = ltc_key->g;
	ltc_tmp_key.p = ltc_key->p;
	ltc_res = dh_make_key(
		0, tee_ltc_get_rng_mpa(),
		q, xbits, &ltc_tmp_key);
	if (ltc_res != CRYPT_OK) {
		res = TEE_ERROR_BAD_PARAMETERS;
	} else {
		ltc_mp.copy(ltc_tmp_key.y,  ltc_key->y);
		ltc_mp.copy(ltc_tmp_key.x,  ltc_key->x);

		/* utee_mem_free the tempory key */
		dh_free(&ltc_tmp_key);
		res = TEE_SUCCESS;
	}
	return res;
}

TEE_Result tee_acipher_gen_dsa_keys(dsa_key *ltc_key, size_t key_size)
{
	TEE_Result res;
	dsa_key ltc_tmp_key;
	size_t group_size, modulus_size = key_size/8;
	int ltc_res;

	if (modulus_size <= 128)
		group_size = 20;
	else if (modulus_size <= 256)
		group_size = 30;
	else if (modulus_size <= 384)
		group_size = 35;
	else
		group_size = 40;

	/* Get the dsa key */
	ltc_res = dsa_make_key(
		0, tee_ltc_get_rng_mpa(),
		group_size, modulus_size, &ltc_tmp_key);
	if (ltc_res != CRYPT_OK) {
		res = TEE_ERROR_BAD_PARAMETERS;
	} else if ((size_t)mp_count_bits(ltc_tmp_key.p) != key_size) {
		dsa_free(&ltc_tmp_key);
		res = TEE_ERROR_BAD_PARAMETERS;
	} else {
		/* copy the key */
		ltc_mp.copy(ltc_tmp_key.g,  ltc_key->g);
		ltc_mp.copy(ltc_tmp_key.p,  ltc_key->p);
		ltc_mp.copy(ltc_tmp_key.q,  ltc_key->q);
		ltc_mp.copy(ltc_tmp_key.y,  ltc_key->y);
		ltc_mp.copy(ltc_tmp_key.x,  ltc_key->x);

		/* utee_mem_free the tempory key */
		dsa_free(&ltc_tmp_key);
		res = TEE_SUCCESS;
	}
	return res;
}

TEE_Result tee_derive_dh_shared_secret(
		dh_key *private_key, void *public_key, void *secret)
{
	int err;
	err = dh_shared_secret(private_key, public_key, secret);

	return ((err == CRYPT_OK) ? TEE_SUCCESS : TEE_ERROR_BAD_PARAMETERS);
}

TEE_Result tee_acipher_rsadorep(
	rsa_key *ltc_key,
	const uint8_t *src, size_t src_len, uint8_t *dst, size_t *dst_len)
{
	TEE_Result res = TEE_SUCCESS;
	uint8_t *buf = NULL;
	uint32_t blen, offset;
	int ltc_res;

	/*
	 * Use a temporary buffer since we don't know exactly how large the
	 * required size of the out buffer without doing a partial decrypt.
	 * We know the upper bound though.
	 */
	blen = (mpa_StaticTempVarSizeInU32(LTC_MAX_BITS_PER_VARIABLE)) *
	       sizeof(uint32_t);
	buf = utee_mem_alloc(blen);
	if (buf == NULL) {
		res = TEE_ERROR_OUT_OF_MEMORY;
		goto out;
	}

	ltc_res = rsa_exptmod(
		src, src_len,	/* input message and length */
		buf, (unsigned long *)(&blen),	/* decrypted message and len */
		ltc_key->type,
		ltc_key);
	if (ltc_res != CRYPT_OK) {
		//EMSG("rsa_exptmod() returned %d\n", ltc_res);
		res = TEE_ERROR_BAD_PARAMETERS;
		goto out;
	}

	if (*dst_len < blen) {
		*dst_len = blen;
		res = TEE_ERROR_SHORT_BUFFER;
		goto out;
	}

	res = TEE_SUCCESS;
	if (ltc_key->type == PK_PUBLIC) {
		/* encrypting / signing */
		*dst_len = blen;
		offset = 0;
	} else {
		/* remove the zero-padding */
		offset = 0;
		while ((buf[offset] == 0) && (offset < blen))
			offset++;
		*dst_len = blen - offset;
	}
	utee_mem_copy(dst, (char *)buf + offset, *dst_len);

out:
	if (buf)
		utee_mem_free(buf);

	return res;
}

TEE_Result tee_acipher_rsaes_decrypt(
	uint32_t algo, rsa_key *ltc_key, const uint8_t *label, size_t label_len,
	const uint8_t *src, size_t src_len, uint8_t *dst, size_t *dst_len)
{
	TEE_Result res = TEE_SUCCESS;
	void *buf = NULL;
	uint32_t blen;
	int ltc_hashindex, ltc_res, ltc_stat, ltc_rsa_algo;
	size_t mod_size;

	/* Get the algorithm */
	res = tee_algo_to_ltc_hashindex(algo, &ltc_hashindex);
	if (res != TEE_SUCCESS) {
		//EMSG("tee_algo_to_ltc_hashindex() returned %d\n", (int)res);
		goto out;
	}

	if (algo == TEE_ALG_RSAES_PKCS1_V1_5) {
		mod_size = ltc_mp.unsigned_size((void *)(ltc_key->N));
		/*
		 * Use a temporary buffer since we don't know exactly how large
		 * the required size of the out buffer without doing a partial
		 * decrypt. We know the upper bound though.
		 */
		blen = mod_size - 11;
		ltc_rsa_algo = LTC_LTC_PKCS_1_V1_5;
	} else {
		/*
		 * Use a temporary buffer since we don't know exactly how
		 * large the required size of the out buffer without doing a
		 * partial decrypt. We know the upper bound though: the length
		 * of the decoded message is lower than the encrypted message
		 */
		blen = src_len;
		ltc_rsa_algo = LTC_LTC_PKCS_1_OAEP;
	}

	buf = utee_mem_alloc(blen);
	if (buf == NULL) {
		res = TEE_ERROR_OUT_OF_MEMORY;
		goto out;
	}

	ltc_res = rsa_decrypt_key_ex(
		src, src_len,	/* input message and length */
		buf, (unsigned long *)(&blen),	/* decrypted message and len */
		((label_len == 0) ? 0 : label), label_len, /* label and len */
		ltc_hashindex,	/* hash index, based on the algo */
		ltc_rsa_algo,
		&ltc_stat,
		ltc_key);
	if ((ltc_res != CRYPT_OK) || (ltc_stat != 1)) {
		//EMSG("rsa_decrypt_key_ex() returned %d and %d\n",
		//    ltc_res, ltc_stat);
		res = TEE_ERROR_BAD_PARAMETERS;
		goto out;
	}

	if (*dst_len < blen) {
		*dst_len = blen;
		res = TEE_ERROR_SHORT_BUFFER;
		goto out;
	}

	res = TEE_SUCCESS;
	*dst_len = blen;
	utee_mem_copy(dst, buf, blen);

out:
	if (buf)
		utee_mem_free(buf);

	return res;
}

TEE_Result tee_acipher_rsaes_encrypt(
	uint32_t algo, rsa_key *ltc_key, const uint8_t *label, size_t label_len,
	const uint8_t *src, size_t src_len, uint8_t *dst, size_t *dst_len)
{
	TEE_Result res;
	uint32_t mod_size;
	int ltc_hashindex, ltc_res, ltc_rsa_algo;

	mod_size =  ltc_mp.unsigned_size((void *)(ltc_key->N));
	if (*dst_len < mod_size) {
		*dst_len = mod_size;
		return TEE_ERROR_SHORT_BUFFER;
	}
	*dst_len = mod_size;

	/* Get the algorithm */
	res = tee_algo_to_ltc_hashindex(algo, &ltc_hashindex);
	if (res != TEE_SUCCESS) {
		//EMSG("tee_algo_to_ltc_hashindex() returned %d\n", (int)res);
		goto out;
	}

	if (algo == TEE_ALG_RSAES_PKCS1_V1_5)
		ltc_rsa_algo = LTC_LTC_PKCS_1_V1_5;
	else
		ltc_rsa_algo = LTC_LTC_PKCS_1_OAEP;

	ltc_res = rsa_encrypt_key_ex(
		src, src_len,	/* input message and length */
		dst, (unsigned long *)(dst_len), /* encrypted message and len */
		label, label_len, /* label and  length */
		0, tee_ltc_get_rng_mpa(),
		ltc_hashindex,	/* hash index, based on the algo */
		ltc_rsa_algo,
		ltc_key);
	if (ltc_res != CRYPT_OK) {
		//EMSG("rsa_encrypt_key_ex() returned %d\n", ltc_res);
		res = TEE_ERROR_BAD_PARAMETERS;
		goto out;
	}
	res = TEE_SUCCESS;

out:
	return res;
}


TEE_Result tee_acipher_rsassa_sign(
	uint32_t algo, rsa_key *ltc_key, int salt_len,
	const uint8_t *msg, size_t msg_len, uint8_t *sig, size_t *sig_len)
{
	TEE_Result res;
	size_t hash_size;
	size_t mod_size;
	int ltc_res, ltc_rsa_algo, ltc_hashindex;

	switch (algo) {
	case TEE_ALG_RSASSA_PKCS1_V1_5_MD5:
	case TEE_ALG_RSASSA_PKCS1_V1_5_SHA1:
	case TEE_ALG_RSASSA_PKCS1_V1_5_SHA224:
	case TEE_ALG_RSASSA_PKCS1_V1_5_SHA256:
	case TEE_ALG_RSASSA_PKCS1_V1_5_SHA384:
	case TEE_ALG_RSASSA_PKCS1_V1_5_SHA512:
		ltc_rsa_algo = LTC_LTC_PKCS_1_V1_5;
		break;
	case TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA1:
	case TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA224:
	case TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA256:
	case TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA384:
	case TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA512:
		ltc_rsa_algo = LTC_LTC_PKCS_1_PSS;
		break;
	default:
		return TEE_ERROR_BAD_PARAMETERS;
	}

	ltc_res = tee_algo_to_ltc_hashindex(algo, &ltc_hashindex);
	if (ltc_res != CRYPT_OK)
		return TEE_ERROR_BAD_PARAMETERS;

	res =
	    tee_hash_get_digest_size(TEE_DIGEST_HASH_TO_ALGO(algo), &hash_size);
	if (res != TEE_SUCCESS)
		return res;

	if (msg_len != hash_size)
		return TEE_ERROR_BAD_PARAMETERS;

	mod_size = ltc_mp.unsigned_size((void *)(ltc_key->N));

	if (*sig_len < mod_size) {
		*sig_len = mod_size;
		return TEE_ERROR_SHORT_BUFFER;
	}

	*sig_len = mod_size;

	ltc_res = rsa_sign_hash_ex(
		msg, msg_len,
		sig, (unsigned long *)(&sig_len),
		ltc_rsa_algo,
		0, tee_ltc_get_rng_mpa(),
		ltc_hashindex,
		salt_len,
		ltc_key);

	if (ltc_res != CRYPT_OK) {
		//EMSG("rsa_encrypt_key_ex() returned %d\n", ltc_res);
		return TEE_ERROR_BAD_PARAMETERS;
	}

	return TEE_SUCCESS;
}

TEE_Result tee_acipher_rsassa_verify(
	uint32_t algo, rsa_key *ltc_key, int salt_len,
	const uint8_t *msg, size_t msg_len, const uint8_t *sig, size_t sig_len)
{
	TEE_Result res;
	uint32_t bigint_size;
	int stat, ltc_hashindex, ltc_res, ltc_rsa_algo;

	bigint_size = ltc_mp.unsigned_size(ltc_key->N);
	if (sig_len < bigint_size)
		return TEE_ERROR_SIGNATURE_INVALID;


	/* Get the algorithm */
	res = tee_algo_to_ltc_hashindex(algo, &ltc_hashindex);
	if (res != TEE_SUCCESS) {
		//EMSG("tee_algo_to_ltc_hashindex() returned %d\n", (int)res);
		return res;
	}

	switch (algo) {
	case TEE_ALG_RSASSA_PKCS1_V1_5_MD5:
	case TEE_ALG_RSASSA_PKCS1_V1_5_SHA1:
	case TEE_ALG_RSASSA_PKCS1_V1_5_SHA224:
	case TEE_ALG_RSASSA_PKCS1_V1_5_SHA256:
	case TEE_ALG_RSASSA_PKCS1_V1_5_SHA384:
	case TEE_ALG_RSASSA_PKCS1_V1_5_SHA512:
		ltc_rsa_algo = LTC_LTC_PKCS_1_V1_5;
		break;
	case TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA1:
	case TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA224:
	case TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA256:
	case TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA384:
	case TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA512:
		ltc_rsa_algo = LTC_LTC_PKCS_1_PSS;
		break;
	default:
		return TEE_ERROR_BAD_PARAMETERS;
	}

	ltc_res = rsa_verify_hash_ex(
		sig, sig_len,
		msg, msg_len,
		ltc_rsa_algo, ltc_hashindex,
		salt_len,
		&stat,
		ltc_key);
	if ((ltc_res != CRYPT_OK) || (stat != 1)) {
		//EMSG("rsa_encrypt_key_ex() returned %d\n", ltc_res);
		return TEE_ERROR_SIGNATURE_INVALID;
	}

	return TEE_SUCCESS;
}

TEE_Result tee_acipher_dsa_sign(
	uint32_t algo, dsa_key *ltc_key,
	const uint8_t *msg, size_t msg_len, uint8_t *sig, size_t *sig_len)
{
	TEE_Result res;
	int ltc_res;
	void *r, *s;
	if (*sig_len < 2 * mp_unsigned_bin_size(ltc_key->q)) {
		*sig_len = 2 * mp_unsigned_bin_size(ltc_key->q);
		return TEE_ERROR_SHORT_BUFFER;
	}

	ltc_res = mp_init_multi(&r, &s, NULL);
	if (ltc_res != CRYPT_OK)
		return TEE_ERROR_OUT_OF_MEMORY;
	ltc_res = dsa_sign_hash_raw(
		msg, msg_len, r, s, 0, tee_ltc_get_rng_mpa(), ltc_key);

	if (ltc_res == CRYPT_OK) {
		*sig_len = 2 * mp_unsigned_bin_size(ltc_key->q);
		utee_mem_fill(sig, 0, *sig_len);
		mp_to_unsigned_bin(
			r,
			(uint8_t *)sig + *sig_len/2 - mp_unsigned_bin_size(r));
		mp_to_unsigned_bin(
			s,
			(uint8_t *)sig + *sig_len   - mp_unsigned_bin_size(s));
		res = TEE_SUCCESS;
	} else {
		res = TEE_ERROR_GENERIC;
	}

	mp_clear_multi(r, s, NULL);
	return res;
}

TEE_Result tee_acipher_dsa_verify(
	uint32_t algo, dsa_key *ltc_key,
	const uint8_t *msg, size_t msg_len, const uint8_t *sig, size_t sig_len)
{
	TEE_Result res;
	int ltc_stat, ltc_res;
	void *r, *s;

	ltc_res = mp_init_multi(&r, &s, NULL);
	if (ltc_res != CRYPT_OK)
		return TEE_ERROR_OUT_OF_MEMORY;
	mp_read_unsigned_bin(r, (uint8_t *)sig, sig_len/2);
	mp_read_unsigned_bin(s, (uint8_t *)sig + sig_len/2, sig_len/2);
	ltc_res = dsa_verify_hash_raw(r, s, msg, msg_len, &ltc_stat, ltc_key);
	mp_clear_multi(r, s, NULL);

	if ((ltc_res == CRYPT_OK) && (ltc_stat == 1))
		res = TEE_SUCCESS;
	else
		res = TEE_ERROR_GENERIC;

	mp_clear_multi(r, s, NULL);
	return res;
}



/**************************************** Auth Cipher Algorithm *****************************************/


/*
 * From Libtomcrypt documentation
 * CCM is a NIST proposal for encrypt + authenticate that is centered around
 * using AES (or any 16-byte cipher) as a primitive.  Unlike EAX and OCB mode,
 * it is only meant for packet  mode where the length of the input is known in
 * advance. Since it is a packet mode function, CCM only has one function that
 * performs the protocol
 */

#define TEE_CCM_KEY_MAX_LENGTH		32
#define TEE_CCM_NONCE_MAX_LENGTH	13
#define TEE_CCM_TAG_MAX_LENGTH		32

struct ccm_state {
	uint8_t key[TEE_CCM_KEY_MAX_LENGTH];		/* the key */
	size_t key_len;					/* the key length */
	uint8_t nonce[TEE_CCM_NONCE_MAX_LENGTH];	/* the nonce */
	size_t nonce_len;			/* nonce length */
	uint8_t tag[TEE_CCM_TAG_MAX_LENGTH];	/* computed tag on last data */
	size_t tag_len;			/* tag length */
	size_t aad_len;
	size_t payload_len;		/* final expected payload length */
	uint8_t *payload;		/* the payload */
	size_t current_payload_len;	/* the current payload length */
	uint8_t *res_payload;		/* result with the whole payload */
	int ltc_cipherindex;		/* the libtomcrypt cipher index */
	uint8_t *header;		/* the header (aad) */
	size_t header_len;		/* header length */
};

TEE_Result tee_authenc_get_ctx_size(uint32_t algo, size_t *size)
{
	switch (algo) {
	case TEE_ALG_AES_CCM:
		*size = sizeof(struct ccm_state);
		break;
	case TEE_ALG_AES_GCM:
		*size = sizeof(gcm_state);
		break;
	default:
		return TEE_ERROR_NOT_SUPPORTED;
	}
	return TEE_SUCCESS;
}

TEE_Result tee_authenc_init(
	void *ctx, uint32_t algo, TEE_OperationMode mode, const uint8_t *key,
	size_t key_len, const uint8_t *nonce,
	size_t nonce_len, size_t tag_len, size_t aad_len, size_t payload_len)
{
	TEE_Result res;
	int ltc_res;
	int ltc_cipherindex;
	unsigned char *payload, *res_payload;
	struct ccm_state *ccm;

	res = tee_algo_to_ltc_cipherindex(algo, &ltc_cipherindex);
	if (res != TEE_SUCCESS)
		return TEE_ERROR_NOT_SUPPORTED;
	switch (algo) {
	case TEE_ALG_AES_CCM:
		/* Check the key length */
		if ((!key) || (key_len > TEE_CCM_KEY_MAX_LENGTH))
			return TEE_ERROR_BAD_PARAMETERS;

		/* check the nonce */
		if (nonce_len > TEE_CCM_NONCE_MAX_LENGTH)
			return TEE_ERROR_BAD_PARAMETERS;

		/* check the tag len */
		if ((tag_len < 4) ||
		    (tag_len > TEE_CCM_TAG_MAX_LENGTH) ||
		    (tag_len % 2 != 0))
			return TEE_ERROR_NOT_SUPPORTED;

		/* allocate payload */
		payload = utee_mem_alloc(payload_len + TEE_CCM_KEY_MAX_LENGTH);
		if (!payload)
			return TEE_ERROR_OUT_OF_MEMORY;
		res_payload = utee_mem_alloc(payload_len + TEE_CCM_KEY_MAX_LENGTH);
		if (!res_payload) {
			utee_mem_free(payload);
			return TEE_ERROR_OUT_OF_MEMORY;
		}

		/* initialize the structure */
		ccm = (struct ccm_state *)ctx;
		utee_mem_fill(ccm, 0, sizeof(struct ccm_state));
		utee_mem_copy(ccm->key, key, key_len);
		ccm->key_len = key_len;			/* the key length */
		if (nonce && nonce_len) {
			utee_mem_copy(ccm->nonce, nonce, nonce_len);
			ccm->nonce_len = nonce_len;
		} else {
			ccm->nonce_len = 0;
		}
		ccm->tag_len = tag_len;
		ccm->aad_len = aad_len;
		ccm->payload_len = payload_len;
		ccm->payload = payload;
		ccm->res_payload = res_payload;
		ccm->ltc_cipherindex = ltc_cipherindex;

		if (ccm->aad_len) {
			ccm->header = utee_mem_alloc(ccm->aad_len);
			if (!ccm->header) {
				utee_mem_free(payload);
				utee_mem_free(res_payload);
				return TEE_ERROR_OUT_OF_MEMORY;
			}
		}

		/* utee_mem_fill the payload to 0 that will be used for padding */
		utee_mem_fill(ccm->payload, 0, payload_len + TEE_CCM_KEY_MAX_LENGTH);
		break;

	case TEE_ALG_AES_GCM:
		/* reset the state */
		ltc_res = gcm_init(
			(gcm_state *)ctx, ltc_cipherindex, key, key_len);
		if (ltc_res != CRYPT_OK)
			return TEE_ERROR_BAD_STATE;

		/* Add the IV */
		ltc_res = gcm_add_iv((gcm_state *)ctx, nonce, nonce_len);
		if (ltc_res != CRYPT_OK)
			return TEE_ERROR_BAD_STATE;
		break;

	default:
		return TEE_ERROR_NOT_SUPPORTED;
	}

	return TEE_SUCCESS;
}

TEE_Result tee_authenc_update_aad(
	void *ctx, uint32_t algo, TEE_OperationMode mode,
	  const uint8_t *data, size_t len)
{
	struct ccm_state *ccm;
	int ltc_res;

	switch (algo) {
	case TEE_ALG_AES_CCM:
		ccm = (struct ccm_state *)ctx;
		if (ccm->aad_len < ccm->header_len + len)
			return TEE_ERROR_BAD_PARAMETERS;
		utee_mem_copy(ccm->header + ccm->header_len, data, len);
		ccm->header_len += len;
		break;

	case TEE_ALG_AES_GCM:
		/* Add the AAD (note: aad can be NULL if aadlen == 0) */
		ltc_res = gcm_add_aad((gcm_state *)ctx, data, len);
		if (ltc_res != CRYPT_OK)
			return TEE_ERROR_BAD_STATE;
		break;

	default:
		return TEE_ERROR_NOT_SUPPORTED;
	}

	return TEE_SUCCESS;
}

TEE_Result tee_authenc_update_payload(
	void *ctx, uint32_t algo, TEE_OperationMode mode,
	const uint8_t *src_data, size_t src_len, uint8_t *dst_data)
{
	TEE_Result res;
	int ltc_res, dir;
	struct ccm_state *ccm;
	unsigned char *pt, *ct;	/* the plain and the cipher text */

	if (mode == TEE_MODE_ENCRYPT) {
		pt = (unsigned char *)src_data;
		ct = dst_data;
	} else {
		pt = dst_data;
		ct = (unsigned char *)src_data;
	}

	switch (algo) {
	case TEE_ALG_AES_CCM:
		/* Check aad has been correctly added */
		ccm = (struct ccm_state *)ctx;
		if (ccm->aad_len != ccm->header_len)
			return TEE_ERROR_BAD_STATE;

		/*
		 * check we do not add more data than what was defined at
		 * the init
		 */
		if (ccm->current_payload_len + src_len > ccm->payload_len)
			return TEE_ERROR_BAD_PARAMETERS;
		utee_mem_copy(ccm->payload + ccm->current_payload_len,
		       src_data, src_len);
		ccm->current_payload_len += src_len;

		dir = (mode == TEE_MODE_ENCRYPT ? CCM_ENCRYPT : CCM_DECRYPT);
		ltc_res = ccm_memory(
			ccm->ltc_cipherindex,
			ccm->key, ccm->key_len,
			0,	/* not presecheduled */
			ccm->nonce,  ccm->nonce_len,
			ccm->header, ccm->header_len,
			pt, src_len, ct,
			ccm->tag, (unsigned long *)&ccm->tag_len, dir);
		if (ltc_res != CRYPT_OK)
			return TEE_ERROR_BAD_STATE;
		break;

	case TEE_ALG_AES_GCM:
		/* aad is optional ==> add one without length */
		if (((gcm_state *)ctx)->mode == LTC_GCM_MODE_IV) {
			res = tee_authenc_update_aad(ctx, algo, mode, 0, 0);
			if (res != TEE_SUCCESS)
				return res;
		}

		/* process the data */
		dir = (mode == TEE_MODE_ENCRYPT ? GCM_ENCRYPT : GCM_DECRYPT);
		ltc_res = gcm_process((gcm_state *)ctx,	pt, src_len, ct, dir);
		if (ltc_res != CRYPT_OK)
			return TEE_ERROR_BAD_STATE;
		break;

	default:
		return TEE_ERROR_NOT_SUPPORTED;
	}

	return TEE_SUCCESS;
}

TEE_Result tee_authenc_enc_final(
	void *ctx, uint32_t algo, const uint8_t *src_data,
	size_t src_len, uint8_t *dst_data,
	uint8_t *dst_tag, size_t *dst_tag_len)
{
	TEE_Result res, final_res = TEE_ERROR_MAC_INVALID;
	struct ccm_state *ccm;
	size_t digest_size;
	int ltc_res;
	int init_len;

	/* Check the resulting buffer is not too short */
	res = tee_cipher_get_block_size(algo, &digest_size);
	if (res != TEE_SUCCESS) {
		final_res = res;
		goto out;
	}

	switch (algo) {
	case TEE_ALG_AES_CCM:
		ccm = (struct ccm_state *)ctx;

		init_len = ccm->current_payload_len;
		if (src_len) {
			utee_mem_copy(ccm->payload + ccm->current_payload_len,
			       src_data, src_len);
			ccm->current_payload_len += src_len;
		}

		if (ccm->payload_len != ccm->current_payload_len)
			return TEE_ERROR_BAD_PARAMETERS;

		ltc_res = ccm_memory(
			ccm->ltc_cipherindex,
			ccm->key, ccm->key_len,
			0,	/* not presecheduled */
			ccm->nonce,  ccm->nonce_len,
			ccm->header, ccm->header_len,
			ccm->payload, ccm->current_payload_len,
			ccm->res_payload,
			dst_tag, (unsigned long *)dst_tag_len, CCM_ENCRYPT);
		if (ltc_res != CRYPT_OK)
			return TEE_ERROR_BAD_STATE;

		if (src_len)
			utee_mem_copy(dst_data, ccm->res_payload + init_len, src_len);
		break;

	case TEE_ALG_AES_GCM:
		/* Finalize the remaining buffer */
		res = tee_authenc_update_payload(
			ctx, algo, TEE_MODE_ENCRYPT,
			src_data, src_len, dst_data);
		if (res != TEE_SUCCESS) {
			final_res = res;
			goto out;
		}

		/* Process the last buffer, if any */
		ltc_res = gcm_done(
			(gcm_state *)ctx,
			dst_tag, (unsigned long *)dst_tag_len);
		if (ltc_res != CRYPT_OK)
			goto out;
		break;

	default:
		return TEE_ERROR_NOT_SUPPORTED;
	}
	final_res = TEE_SUCCESS;

out:
	return final_res;
}

TEE_Result tee_authenc_dec_final(
	void *ctx, uint32_t algo, const uint8_t *src_data,
	size_t src_len, uint8_t *dst_data, const uint8_t *tag, size_t tag_len)
{
	TEE_Result res = TEE_ERROR_BAD_STATE;
	struct ccm_state *ccm;
	int ltc_res;
	uint8_t *dst_tag;
	size_t dst_len, init_len;

	res = tee_cipher_get_block_size(algo, &dst_len);
	if (res != TEE_SUCCESS)
		return res;

	if (tag_len == 0)
		return TEE_ERROR_SHORT_BUFFER;
	dst_len = tag_len;
	dst_tag = utee_mem_alloc(tag_len);
	if (!dst_tag)
		return TEE_ERROR_OUT_OF_MEMORY;

	switch (algo) {
	case TEE_ALG_AES_CCM:
		ccm = (struct ccm_state *)ctx;

		init_len = ccm->current_payload_len;
		if (src_len) {
			utee_mem_copy(ccm->payload + ccm->current_payload_len,
			       src_data, src_len);
			ccm->current_payload_len += src_len;
		}

		if (ccm->payload_len != ccm->current_payload_len)
			return TEE_ERROR_BAD_PARAMETERS;

		ltc_res = ccm_memory(
			ccm->ltc_cipherindex,
			ccm->key, ccm->key_len,
			0,	/* not presecheduled */
			ccm->nonce,  ccm->nonce_len,
			ccm->header, ccm->header_len,
			ccm->res_payload,
			ccm->current_payload_len, ccm->payload,
			dst_tag, (unsigned long *)&tag_len, CCM_DECRYPT);
		if (ltc_res != CRYPT_OK)
			return TEE_ERROR_BAD_STATE;

		if (src_len)
			utee_mem_copy(dst_data, ccm->res_payload + init_len, src_len);
		break;


	case TEE_ALG_AES_GCM:
		/* Process the last buffer, if any */
		res = tee_authenc_update_payload(
			ctx, algo, TEE_MODE_DECRYPT,
			src_data, src_len, dst_data);
		if (res != TEE_SUCCESS)
			goto out;

		/* Finalize the authentification */
		ltc_res = gcm_done(
			(gcm_state *)ctx,
			dst_tag, (unsigned long *)&tag_len);
		if (ltc_res != CRYPT_OK)
			goto out;
		break;

	default:
		res = TEE_ERROR_NOT_SUPPORTED;
		goto out;
	}

	if (utee_mem_cmp(dst_tag, tag, tag_len) != 0)
		res = TEE_ERROR_MAC_INVALID;
	else
		res = TEE_SUCCESS;

out:
	if (dst_tag)
		utee_mem_free(dst_tag);
	return res;
}

void tee_authenc_final(void *ctx, uint32_t algo)
{
	struct ccm_state *ccm;

	switch (algo) {
	case TEE_ALG_AES_CCM:
		ccm = (struct ccm_state *)ctx;
		if (ccm->payload)
			utee_mem_free(ccm->payload);
		if (ccm->res_payload)
			utee_mem_free(ccm->res_payload);
		ccm->payload_len = 0;
		if (ccm->header)
			utee_mem_free(ccm->header);
		ccm->aad_len = 0;
		ccm->header_len = 0;
		break;
	case TEE_ALG_AES_GCM:
		gcm_reset((gcm_state *)ctx);
		break;
	default:
		break;
	}
}
























