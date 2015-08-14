#ifndef CRYPT_RANDOM_H
#define CRYPT_RANDOM_H


#include <tee_api_types.h>

TEE_Result tee_crypt_random_number_generate(void *buf, size_t blen);

TEE_Result tee_get_rng_array(void *buf, size_t blen);

#endif