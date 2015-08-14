#ifndef CRYPT_AUTH_H
#define CRYPT_AUTH_H

#include <tee_api_types.h>
#include <utee_mem.h>
#include <utee_defines.h>

#include "crypt_ctx.h"
#include "crypt_state.h"
#include "crypt_obj.h"
#include "crypt_key.h"
#include "crypt_engine.h"


TEE_Result utee_authenc_init(uint32_t state, const void *nonce,
				size_t nonce_len, size_t tag_len,
				size_t aad_len, size_t payload_len);



TEE_Result utee_authenc_update_aad(uint32_t state, const void *aad_data,
				      size_t aad_data_len);


TEE_Result utee_authenc_update_payload(uint32_t state, const void *src_data,
					  size_t src_len, void *dst_data,
					  size_t *dst_len);





TEE_Result utee_authenc_enc_final(uint32_t state, const void *src_data,
				     size_t src_len, void *dst_data,
				     size_t *dst_len, void *tag,
				     size_t *tag_len);

TEE_Result utee_authenc_dec_final(uint32_t state, const void *src_data,
				     size_t src_len, void *dst_data,
				     size_t *dst_len, const void *tag,
				     size_t tag_len);







#endif