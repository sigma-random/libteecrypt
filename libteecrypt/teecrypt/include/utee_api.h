#ifndef UTEE_API_H
#define UTEE_API_H


#include "tee_config.h"
#include "tee_api_types.h"
#include "utee_types.h"



/********************************************** Customized Export API *******************************************/

TEE_Result TEE_Hexdump(char *title, unsigned char *data, uint32_t size, uint32_t linenum, bool isUp);

TEE_Result TEE_HexdumpBigInt(char *title, TEE_BigInt *bn, uint32_t bn_size, uint32_t linenum, bool isRawData);

TEE_Result TEE_InitCryptContext();

TEE_Result TEE_FiniCryptContext();

TEE_Result TEE_NewRandomKeyObject(TEE_ObjectType keyObjectType, uint32_t maxKeyObjectSize, 
							TEE_ObjectHandle *hKeyObject);


TEE_Result TEE_DumpRSAKeyObj(TEE_ObjectHandle hKeyObject, uint32_t rsa_key_bits, 
			bool is_KeyPair, uint32_t rawdata);


TEE_Result TEE_LoadX509Cert(char *filename, X509_st **pX509);

TEE_Result TEE_FreeX509Cert(X509_st *x509);


#define TEE_Printf  utee_printf

int TEE_Printf(char *format, ...);


/*
TEE_Result TEE_SetRsaKeyObjectValue(TEE_ObjectHandle hKeyObject,  uint32_t rsaKeyBits, 
                                void *e_data, size_t e_bytes, void *n_data, size_t n_bytes, 
                                bool isRsaKeyPair);

TEE_Result TEE_NewRsaKeyObject(TEE_ObjectType keyObjectType, uint32_t rsaKeyBits, 
                            void *e_data, size_t e_bytes, void *n_data, size_t n_bytes, 
                            TEE_ObjectHandle *hKeyObject);
*/

#endif