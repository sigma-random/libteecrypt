#ifndef __TEE_TOMCRYPT_ENGINE_H_
#define __TEE_TOMCRYPT_ENGINE_H_


#include <tomcrypt_mpa.h>

#include <tee_api_types.h>
#include <utee_defines.h>
#include <utee_mem.h>


#define LTC_MAX_BITS_PER_VARIABLE   (4096)

void tee_ltc_init(void);
void tee_ltc_deinit(void);
TEE_Result tee_algo_to_ltc_hashindex(uint32_t algo, int *ltc_hashindex);
TEE_Result tee_algo_to_ltc_cipherindex(uint32_t algo, int *ltc_cipherindex);
int tee_ltc_get_rng_mpa(void);



/*
 * Algorithms in this files are as specified with the TEE_ALG_XXX from
 * TEE Internal API.
 */

/**************************************** synmm cipher Algorithm *****************************************/

TEE_Result tee_cipher_get_ctx_size(uint32_t algo, size_t *size);

TEE_Result tee_cipher_init(void *ctx, uint32_t algo,
			   TEE_OperationMode mode, const uint8_t *key,
			   size_t key_len);

TEE_Result tee_cipher_init2(void *ctx, uint32_t algo,
			    TEE_OperationMode mode, const uint8_t *key,
			    size_t key_len, const uint8_t *iv, size_t iv_len);

TEE_Result tee_cipher_init3(void *ctx, uint32_t algo,
			    TEE_OperationMode mode, const uint8_t *key1,
			    size_t key1_len, const uint8_t *key2,
			    size_t key2_len, const uint8_t *iv, size_t iv_len);

TEE_Result tee_cipher_update(void *ctx, uint32_t algo,
			     TEE_OperationMode mode, bool last_block,
			     const uint8_t *data, size_t len, uint8_t *dst);

void tee_cipher_final(void *ctx, uint32_t algo);

TEE_Result tee_cipher_get_block_size(uint32_t algo, size_t *size);




/**************************************** HASH Algorithm *****************************************/

TEE_Result tee_hash_get_digest_size(uint32_t algo, size_t *size);

/* Returns required size of context for the specified algorithm */
TEE_Result tee_hash_get_ctx_size(uint32_t algo, size_t *size);

TEE_Result tee_hash_init(void *ctx, uint32_t algo);

TEE_Result tee_hash_update(void *ctx, uint32_t algo,
			   const uint8_t *data, size_t len);

TEE_Result tee_hash_final(void *ctx, uint32_t algo,
			  uint8_t *digest, size_t len);

TEE_Result tee_hash_createdigest(uint32_t algo, const uint8_t *data,
				 size_t datalen, uint8_t *digest,
				 size_t digestlen);

TEE_Result tee_hash_check(
		uint32_t algo,
		const uint8_t *hash, size_t hash_size,
		const uint8_t *data, size_t data_size);


/**************************************** MAC Algorithm *****************************************/


TEE_Result tee_mac_get_digest_size(uint32_t algo, size_t *size);

/* Returns required size of context for the specified algorithm */
TEE_Result tee_mac_get_ctx_size(uint32_t algo, size_t *size);

TEE_Result tee_mac_init(
	void *ctx, uint32_t algo, const uint8_t *key, size_t len);

TEE_Result tee_mac_update(
	void *ctx, uint32_t algo, const uint8_t *data, size_t len);

TEE_Result tee_mac_final(
	void *ctx, uint32_t algo,
	const uint8_t *data, size_t data_len,
	uint8_t *digest, size_t digest_len);



/**************************************** asynmm cipher Algorithm *****************************************/

TEE_Result tee_acipher_gen_rsa_keys(rsa_key *ltc_key, size_t key_size);

TEE_Result tee_acipher_gen_dh_keys(dh_key *ltc_key, void *q, size_t xbits);

TEE_Result tee_acipher_gen_dsa_keys(dsa_key *ltc_key, size_t key_size);

/*
 * Public_key is an input big number
 * Secret is an output big number
 */
TEE_Result tee_derive_dh_shared_secret(
		dh_key *private_key, void *public_key, void *secret);

TEE_Result tee_acipher_rsadorep(
	rsa_key *ltc_key,
	const uint8_t *src, size_t src_len, uint8_t *dst, size_t *dst_len);

TEE_Result tee_acipher_rsaes_decrypt(
	uint32_t algo, rsa_key *ltc_key, const uint8_t *label, size_t label_len,
	const uint8_t *src, size_t src_len, uint8_t *dst, size_t *dst_len);

TEE_Result tee_acipher_rsaes_encrypt(
	uint32_t algo, rsa_key *ltc_key, const uint8_t *label, size_t label_len,
	const uint8_t *src, size_t src_len, uint8_t *dst, size_t *dst_len);

/* passing salt_len == -1 -> use default value */
TEE_Result tee_acipher_rsassa_sign(
	uint32_t algo, rsa_key *ltc_key, int salt_len,
	const uint8_t *msg, size_t msg_len, uint8_t *sig, size_t *sig_len);

/* passing salt_len == -1 -> use default value */
TEE_Result tee_acipher_rsassa_verify(
	uint32_t algo, rsa_key *ltc_key, int salt_len,
	const uint8_t *msg, size_t msg_len, const uint8_t *sig, size_t sig_len);

TEE_Result tee_acipher_dsa_sign(
	uint32_t algo, dsa_key *ltc_key,
	const uint8_t *msg, size_t msg_len, uint8_t *sig, size_t *sig_len);

TEE_Result tee_acipher_dsa_verify(
	uint32_t algo, dsa_key *ltc_key,
	const uint8_t *msg, size_t msg_len, const uint8_t *sig, size_t sig_len);



/**************************************** Auth Cipher Algorithm *****************************************/

TEE_Result tee_authenc_get_ctx_size(uint32_t algo, size_t *size);

TEE_Result tee_authenc_init(
	void *ctx, uint32_t algo, TEE_OperationMode mode, const uint8_t *key,
	size_t key_len, const uint8_t *nonce,
	size_t nonce_len, size_t tag_len, size_t aad_len, size_t payload_len);

TEE_Result tee_authenc_update_aad(
	void *ctx, uint32_t algo, TEE_OperationMode mode,
	  const uint8_t *data, size_t len);

TEE_Result tee_authenc_update_payload(
	void *ctx, uint32_t algo, TEE_OperationMode mode,
	const uint8_t *src_data, size_t src_len, uint8_t *dst_data);

TEE_Result tee_authenc_enc_final(
	void *ctx, uint32_t algo, const uint8_t *src_data,
	 size_t src_len, uint8_t *dst_data,
	 uint8_t *dst_tag, size_t *dst_tag_len);

TEE_Result tee_authenc_dec_final(
	void *ctx, uint32_t algo, const uint8_t *src_data,
	size_t src_len, uint8_t *dst_data, const uint8_t *tag, size_t tag_len);

void tee_authenc_final(void *ctx, uint32_t algo);





#endif /* __TEE_LTC_WRAPPER_H_ */
