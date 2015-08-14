#include "crypt_random.h"



static uint8_t tee_prng_value = 1;
static uint32_t tee_prng_ite = 0;   


static int 
clocks_of_day()
{
    int clocks = 0;
    struct timeval current;

    //#ifdef MACRO_GLIBC_FUNCS
        gettimeofday(&current, NULL);
        clocks = (current.tv_sec * 1000 + current.tv_usec/1000);
    //#else
    //  clocks = tee_rand();
    //#endif 

    return clocks;
}


uint8_t tee_get_random_byte(void)
{
    tee_prng_ite = (tee_prng_ite + clocks_of_day()) % INT32_MAX;
    tee_srand(tee_prng_ite);
    tee_prng_value = (256 * ((double)tee_rand() / TEE_RAND_MAX));
    return tee_prng_value;
}


TEE_Result tee_get_rng_array(void *buf, size_t blen) 
{
	TEE_Result res = TEE_SUCCESS;
    char *buf_char = buf;
    int i;

    if (buf_char == NULL) {
        res = TEE_ERROR_BAD_PARAMETERS;
        goto _ret_;
    }
    for (i = 0; i < blen; i++) {
        buf_char[i] = tee_get_random_byte();
    }

_ret_:
    return res;
}


TEE_Result tee_crypt_random_number_generate(void *buf, size_t blen)
{
	TEE_Result res;

	res = tee_get_rng_array(buf, blen);
	if (res != TEE_SUCCESS)
		return res;

	return res;
}

