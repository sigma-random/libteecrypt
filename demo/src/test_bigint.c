#include <tee_api.h>
#include <utee_api.h>
 

/*
	The following constraints are put on the internal representation of the TEE_BigInt:
		1)  The size of the representation must be a multiple of 4 bytes.
		2)  The extra memory within the representation to store metadata must not exceed 8 bytes. 
		3)  The representation must be stored 32-bit aligned in memory.
	Exactly how a multi-precision integer is represented internally is implementation specific but it must be stored 
	within a structure of the maximum size given by the macro TEE_BigIntSizeInU32

	TEE_BigInt values are within the interval [-2^M+1, 2^M-1] (limits included), where M  is an 
	implementation-defined number of bits. Every Implementation MUST ensure that M is at least 2048

	macro "TEE_BigIntSizeInU32" is defined by "tee_api_defines.h"	
	#define TEE_BigIntSizeInU32(n) ((((n)+31)/32)+2)

	macro "TEE_BigInt"  is defined by "tee_api_types.h"
	typedef uint32_t TEE_BigInt;

	
*/

#define BIG_INT_MIN_SIZE	2048

#define BIG_INT_RAW_DATA	true
#define BIG_INT_REAL_DATA	false


TEE_Result demo_calc_bigint_add() ;
TEE_Result demo_calc_rsa_key_pair();


int main(int argc, char **argv)
{
	if(TEE_InitCryptContext() != TEE_SUCCESS) {
	  TEE_Printf("[err] TEE_InitCryptContext\n");
	  return 0;
	}

	demo_calc_bigint_add();

	if(TEE_FiniCryptContext() != TEE_SUCCESS) {
	  TEE_Printf("[err] TEE_FiniCryptContext\n");
	}
	exit(0);
    return 0;
}


TEE_Result demo_calc_bigint_add() {

	TEE_Result res;
	/* we do allco TEE_BigInt dynamically */
	TEE_BigInt *op1 = TEE_HANDLE_NULL;
	TEE_BigInt *op2 = TEE_HANDLE_NULL;
	TEE_BigInt *op3 = TEE_HANDLE_NULL;
	int32_t sign = 1;

	TEE_Printf("TEE_BigIntSizeInU32(BIG_INT_MIN_SIZE) = %d\n",TEE_BigIntSizeInU32(BIG_INT_MIN_SIZE));

	/* init and set op1 */
	const const unsigned char op1_buf[] = "\x01\x02\x03\x04\x05\x06\x07\x08";
	op1 = TEE_Malloc(TEE_BigIntSizeInU32(BIG_INT_MIN_SIZE) * sizeof(TEE_BigInt), 0);
	if(!op1) {
		res = TEE_ERROR_BAD_STATE;
		goto _ret_;
	}
	TEE_BigIntInit(op1, TEE_BigIntSizeInU32(BIG_INT_MIN_SIZE) );
	res = TEE_BigIntConvertFromOctetString(op1, op1_buf, 8, sign);
    if(res != TEE_SUCCESS) {
        TEE_Printf("[err] TEE_BigIntConvertFromOctetString\n");
        goto _ret_;
    }else {
    	TEE_HexdumpBigInt("op1", op1, TEE_BigIntSizeInU32(BIG_INT_MIN_SIZE) * sizeof(TEE_BigInt), 16, BIG_INT_RAW_DATA);	// BIG_INT_RAW_DATA  BIG_INT_REAL_DATA
    }

	/* init and set op2 */
	const const unsigned char op2_buf[] = "\x08\x07\x06\x05\x04\x03\x02\x01";
	op2 = TEE_Malloc(TEE_BigIntSizeInU32(BIG_INT_MIN_SIZE) * sizeof(TEE_BigInt), 0);
	if(!op2) {
		goto _ret_;
	}
	TEE_BigIntInit(op2, TEE_BigIntSizeInU32(BIG_INT_MIN_SIZE) );
	res = TEE_BigIntConvertFromOctetString(op2, op2_buf, 8, sign);
    if(res != TEE_SUCCESS) {
        TEE_Printf("[err] TEE_BigIntConvertFromOctetString\n");
        goto _ret_;
    }else {
    	TEE_HexdumpBigInt("op2", op2, TEE_BigIntSizeInU32(BIG_INT_MIN_SIZE) * sizeof(TEE_BigInt), 16, BIG_INT_RAW_DATA);	// BIG_INT_RAW_DATA  BIG_INT_REAL_DATA
    }

    /* init and set op3 */
	op3 = TEE_Malloc(TEE_BigIntSizeInU32(BIG_INT_MIN_SIZE * 2) * sizeof(TEE_BigInt), 0);
	if(!op3) {
		goto _ret_;
	}
	TEE_BigIntInit(op3, TEE_BigIntSizeInU32(BIG_INT_MIN_SIZE * 2) );
	TEE_BigIntAdd(op3, op1, op2);

	/* calculate  op3  = op1 + op2 */
    TEE_HexdumpBigInt("op3", op3, TEE_BigIntSizeInU32(BIG_INT_MIN_SIZE) * sizeof(TEE_BigInt), 16, BIG_INT_RAW_DATA);	// BIG_INT_RAW_DATA  BIG_INT_REAL_DATA


_ret_:
	if(op1) {
		TEE_Free(op1);		
	}
	if(op2) {
		TEE_Free(op2);		
	}
	return res;

}


// TEE_Result demo_calc_rsa_key_pair() {

// 	TEE_Result res = TEE_SUCCESS;
// 	TEE_BigInt *E  = TEE_HANDLE_NULL;
// 	TEE_BigInt *P  = TEE_HANDLE_NULL;
// 	TEE_BigInt *Q  = TEE_HANDLE_NULL;

// 	uint32_t rsaKeyBits = 1024;



//    // if ((rsaKeyBits < (MIN_RSA_SIZE/8)) || (size > (MAX_RSA_SIZE/8))) {
//    //    return TEE_ERROR_BAD_PARAMETER;
//    // }

//    // if ((E < 3) || ((E & 1) == 0)) {
//    //    return TEE_ERROR_BAD_PARAMETER;
//    // }

// _ret_:

// 	return res;

// }


/** 
   Create an RSA key
   @param prng     An active PRNG state
   @param wprng    The index of the PRNG desired
   @param size     The size of the modulus (key size) desired (octets)
   @param e        The "e" value (public key).  e==65537 is a good choice
   @param key      [out] Destination of a newly created private key pair
   @return CRYPT_OK if successful, upon error all allocated ram is freed
*/
// int rsa_make_key(prng_state *prng, int wprng, int size, long e, rsa_key *key)
// {
//    void *p, *q, *tmp1, *tmp2, *tmp3;
//    int    err;

//    LTC_ARGCHK(ltc_mp.name != NULL);
//    LTC_ARGCHK(key         != NULL);

//    if ((size < (MIN_RSA_SIZE/8)) || (size > (MAX_RSA_SIZE/8))) {
//       return CRYPT_INVALID_KEYSIZE;
//    }

//    if ((e < 3) || ((e & 1) == 0)) {
//       return CRYPT_INVALID_ARG;
//    }

//    if ((err = prng_is_valid(wprng)) != CRYPT_OK) {
//       return err;
//    }

//    if ((err = mp_init_multi(&p, &q, &tmp1, &tmp2, &tmp3, NULL)) != CRYPT_OK) {
//       return err;
//    }

//    /* make primes p and q (optimization provided by Wayne Scott) */
//    if ((err = mp_set_int(tmp3, e)) != CRYPT_OK)                      { goto errkey; }  /* tmp3 = e */

//    /* make prime "p" */
//    do {
//        if ((err = rand_prime( p, size/2, prng, wprng)) != CRYPT_OK)  { goto errkey; }
//        if ((err = mp_sub_d( p, 1,  tmp1)) != CRYPT_OK)               { goto errkey; }  /* tmp1 = p-1 */
//        if ((err = mp_gcd( tmp1,  tmp3,  tmp2)) != CRYPT_OK)          { goto errkey; }  /* tmp2 = gcd(p-1, e) */
//    } while (mp_cmp_d( tmp2, 1) != 0);                                                  /* while e divides p-1 */

//    /* make prime "q" */
//    do {
//        if ((err = rand_prime( q, size/2, prng, wprng)) != CRYPT_OK)  { goto errkey; }
//        if ((err = mp_sub_d( q, 1,  tmp1)) != CRYPT_OK)               { goto errkey; } /* tmp1 = q-1 */
//        if ((err = mp_gcd( tmp1,  tmp3,  tmp2)) != CRYPT_OK)          { goto errkey; } /* tmp2 = gcd(q-1, e) */
//    } while (mp_cmp_d( tmp2, 1) != 0);                                           /* while e divides q-1 */

//    /* tmp1 = lcm(p-1, q-1) */
//    if ((err = mp_sub_d( p, 1,  tmp2)) != CRYPT_OK)                   { goto errkey; } /* tmp2 = p-1 */
//                                                                                       /* tmp1 = q-1 (previous do/while loop) */
//    if ((err = mp_lcm( tmp1,  tmp2,  tmp1)) != CRYPT_OK)              { goto errkey; } /* tmp1 = lcm(p-1, q-1) */

//    /* make key */
//    if ((err = mp_init_multi(&key->e, &key->d, &key->N, &key->dQ, &key->dP, &key->qP, &key->p, &key->q, NULL)) != CRYPT_OK) {
//       goto errkey;
//    }

//    if ((err = mp_set_int( key->e, e)) != CRYPT_OK)                     { goto errkey; } /* key->e =  e */
//    if ((err = mp_invmod( key->e,  tmp1,  key->d)) != CRYPT_OK)         { goto errkey; } /* key->d = 1/e mod lcm(p-1,q-1) */
//    if ((err = mp_mul( p,  q,  key->N)) != CRYPT_OK)                    { goto errkey; } /* key->N = pq */

//    /* optimize for CRT now */
//    /* find d mod q-1 and d mod p-1 */
//    if ((err = mp_sub_d( p, 1,  tmp1)) != CRYPT_OK)                     { goto errkey; } /* tmp1 = q-1 */
//    if ((err = mp_sub_d( q, 1,  tmp2)) != CRYPT_OK)                     { goto errkey; } /* tmp2 = p-1 */
//    if ((err = mp_mod( key->d,  tmp1,  key->dP)) != CRYPT_OK)           { goto errkey; } /* dP = d mod p-1 */
//    if ((err = mp_mod( key->d,  tmp2,  key->dQ)) != CRYPT_OK)           { goto errkey; } /* dQ = d mod q-1 */
//    if ((err = mp_invmod( q,  p,  key->qP)) != CRYPT_OK)                { goto errkey; } /* qP = 1/q mod p */

//    if ((err = mp_copy( p,  key->p)) != CRYPT_OK)                       { goto errkey; }
//    if ((err = mp_copy( q,  key->q)) != CRYPT_OK)                       { goto errkey; }

//    /* set key type (in this case it's CRT optimized) */
//    key->type = PK_PRIVATE;

//    /* return ok and free temps */
//    err       = CRYPT_OK;
//    goto cleanup;
// errkey:
//    mp_clear_multi(key->d, key->e, key->N, key->dQ, key->dP, key->qP, key->p, key->q, NULL);
// cleanup:
//    mp_clear_multi(tmp3, tmp2, tmp1, p, q, NULL);
//    return err;
// }
