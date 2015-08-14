#ifndef CRYPT_ASYMM_H
#define CRYPT_ASYMM_H


#include <tee_api_types.h>
#include <utee_mem.h>
#include <utee_defines.h>

#include "crypt_ctx.h"
#include "crypt_state.h"
#include "crypt_obj.h"
#include "crypt_key.h"

#include "crypt_engine.h"




TEE_Result utee_asymm_operate(uint32_t state, const TEE_Attribute *params,
			      uint32_t num_params, const void *src_data,
			      size_t src_len, void *dest_data,
			      size_t *dest_len);

TEE_Result utee_asymm_verify(uint32_t state,
			     const TEE_Attribute *params, uint32_t num_params,
			     const void *data, size_t data_len, const void *sig,
			     size_t sig_len);



#endif