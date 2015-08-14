#ifndef CRYPT_DERIVE_KEY_H
#define CRYPT_DERIVE_KEY_H



#include <tee_api_types.h>

#include "crypt_obj.h"
#include "crypt_key.h"
#include "crypt_engine.h"



TEE_Result utee_crypt_derive_key(uint32_t state, const TEE_Attribute *params,
				   uint32_t param_count, uint32_t derived_key);

#endif