#include <tee_api.h>
#include <utee_api.h>


TEE_Result crypt_cipher_aes_cbc(const void *message, size_t message_len,
								const void *key, size_t key_len,
								void *cipher, size_t *cipher_len, 
								const void *IV, size_t IVLen,
								uint32_t mode);



int main(int argc, char **argv)
{

	TEE_Result res;
	uint32_t crypt_mode;				// TEE_MODE_ENCRYPT or TEE_MODE_DECRYPT
	unsigned char mess[] =  			\
	"\x01\x23\x45\x67\x89\xAB\xCD\xEF"	\
	"\xFE\xDC\xBA\x98\x76\x54\x32\x10"	\
	"2222222222222222"\
	"5555555555555555"\
	"3333333333333333"\
	"0000000000000000"\
	"7777777777777777"\
	"4444444444444444"\
	"8888888888888888"\
	"6666666666666666"\
	"1111111111111111"\
	"9999999999999999";   
	
	size_t mess_len = 96;				// multiples of Aes algorithm key block_size (block_size of AES is 16 Bytes)

	unsigned char key[] = "\x01\x23\x45\x67\x89\xAB\xCD\xEF\xFE\xDC\xBA\x98\x76\x54\x32\x10"\
						  "\x01\x23\x45\x67\x89\xAB\xCD\xEF\xFE\xDC\xBA\x98\x76\x54\x32\x10"; 
	size_t key_len  = 16;				// 128bits = 16Bytes,  192bits = 24Bytes,  256bits = 32Bytes

	unsigned char IV[] = "\x01\x23\x45\x67\x89\xAB\xCD\xEF\xFE\xDC\xBA\x98\x76\x54\x32\x10"\
						 "\x01\x23\x45\x67\x89\xAB\xCD\xEF\xFE\xDC\xBA\x98\x76\x54\x32\x10"; 
	size_t IV_len = key_len;



	/* [0x01] Init crypt context */
	if(TEE_InitCryptContext() != TEE_SUCCESS) {
		TEE_Printf("[err] TEE_InitCryptContext\n");
		return 0;
	}



	TEE_Printf("\n============================TEE_MODE_ENCRYPT============================\n");
	/* [0x02] Encrypt: aes-128-cbc */
	size_t cipher_len = mess_len;
	void *cipher = TEE_Malloc(cipher_len, 0);
	if(!cipher) {		
		TEE_Printf("[err] TEE_Malloc\n");
		return 0;
	}
	crypt_mode = TEE_MODE_ENCRYPT;
	res  = crypt_cipher_aes_cbc((const void *)mess, mess_len, 
								(const void *)key, key_len, 
								cipher, &cipher_len,
								IV, IV_len,
								crypt_mode);					
	if(res != TEE_SUCCESS) {
		TEE_Printf("[err] crypt_cipher_aes_cbc::TEE_MODE_ENCRYPT\n");
		return 0;
	}	
	if( cipher_len > 0) {
		TEE_Hexdump("crypt_cipher_aes_cbc::plain", mess, mess_len, 16, true);
		TEE_Hexdump("crypt_cipher_aes_cbc::key", key, key_len, 16, true);
		TEE_Hexdump("crypt_cipher_aes_cbc::IV", IV, IV_len, 16, true);
		TEE_Hexdump("crypt_cipher_aes_cbc::cipher", cipher, cipher_len, 16, true);
	}



	TEE_Printf("\n============================TEE_MODE_DECRYPT============================\n");
	/* [0x03] Decrypt : aes-128-cbc  */
	size_t plain_len = cipher_len;
	void *plain      = TEE_Malloc(plain_len, 0);
	if(!plain) {		
		TEE_Printf("[err] TEE_Malloc\n");
		return 0;
	}
	crypt_mode = TEE_MODE_DECRYPT;
	res  = crypt_cipher_aes_cbc((const void *)cipher, cipher_len, 
								(const void *)key, key_len, 
								plain, &plain_len,
								IV, IV_len,
								crypt_mode);					
	if(res != TEE_SUCCESS) {
		TEE_Printf("[err] crypt_cipher_aes_cbc::TEE_MODE_DECRYPT\n");
		return 0;
	}	
	if( plain_len > 0) {
		TEE_Hexdump("crypt_cipher_aes_cbc::cipher", cipher, cipher_len, 16, true);
		TEE_Hexdump("crypt_cipher_aes_cbc::key", key, key_len, 16, true);
		TEE_Hexdump("crypt_cipher_aes_cbc::IV", IV, IV_len, 16, true);
		TEE_Hexdump("crypt_cipher_aes_cbc::plain", plain, plain_len, 16, true);
	}



	/* [0x04] Cleanup crypt context */
	if(TEE_FiniCryptContext() != TEE_SUCCESS) {
		TEE_Printf("[err] TEE_FiniCryptContext\n");
	}


	exit(0);

    return 0;
}
 


TEE_Result crypt_cipher_interface(TEE_OperationHandle operation, 
								const void *message, size_t message_len, 
								void *cipher, size_t *cipher_len,
								const void *IV, size_t IVLen) 
{
	TEE_Result res = TEE_ERROR_GENERIC;
	void * src = (void *)message;
	void * dst = (void *)cipher;
	size_t process_len = message_len;
	size_t block_size = operation->block_size;
	TEE_Printf("[info] operation->block_size = 0x%x\n", block_size);

	TEE_CipherInit(operation, IV, IVLen);


	if( process_len < block_size) {
		return res;
	}

	switch(0) {

		case 0:
			res = TEE_CipherDoFinal(operation, src, process_len, dst, &process_len);		// dst_len >= sum(src_len)
			if (res != TEE_SUCCESS) {
				TEE_Printf("[err] TEE_CipherDoFinal\n");
				return res;
			}
			*cipher_len =  process_len;

			break;

		case 1: // using TEE_CipherUpdate
		default: 
			process_len -= block_size;
			res = TEE_CipherUpdate(operation, src, process_len, dst, &process_len);
			if (res != TEE_SUCCESS) {
				TEE_Printf("[err] TEE_CipherDoFinal\n");
				return res;
			}
			// last block
			res = TEE_CipherDoFinal(operation, src+process_len, block_size, dst+process_len, &block_size);		// dst_len >= sum(src_len)
			if (res != TEE_SUCCESS) {
				TEE_Printf("[err] TEE_CipherDoFinal\n");
				return res;
			}
			*cipher_len =  process_len + block_size;		
	}

	return res;
}
 

TEE_Result crypt_cipher_aes_cbc(const void *message, size_t message_len,
								const void *key, size_t key_len,
								void *cipher, size_t *cipher_len, 
								const void *IV, size_t IVLen,
								uint32_t mode)
{
	TEE_Result res = TEE_ERROR_GENERIC;

	TEE_OperationHandle operation =  TEE_HANDLE_NULL;
	uint32_t algorithm            =  TEE_ALG_AES_CBC_NOPAD;
	uint32_t maxKeySize           =  256;						/* valid sizes 128, 192, 256 */

	res = TEE_AllocateOperation(&operation, algorithm, mode, maxKeySize);
	if(res != TEE_SUCCESS) {
		TEE_Printf("[err] TEE_AllocateOperation\n");
		goto _ret_;
	}

	if(!key || 0 >= key_len) {
		res = TEE_ERROR_BAD_PARAMETERS;
		goto _ret_;
	}

	// set crypt key
	TEE_Attribute attr_list[1];
	uint32_t attributeID = TEE_ATTR_SECRET_VALUE;
	TEE_MemFill(&attr_list[0], sizeof(attr_list[0]), 0);
	TEE_InitRefAttribute(&attr_list[0], attributeID /* TEE_ATTR_SECRET_VALUE */, (void *)key, key_len );
	res = TEE_PopulateTransientObject(operation->key1, &attr_list[0], sizeof(attr_list)/sizeof(attr_list[0]));
	if(res != TEE_SUCCESS) {
		TEE_Printf("[err] TEE_PopulateTransientObject\n");
		goto _ret_;
	}

	// do crypt
	res = crypt_cipher_interface(operation,  (const void *)message, message_len, 
								cipher, cipher_len,
								IV, IVLen);
	if(res != TEE_SUCCESS) {
		TEE_Printf("[err] crypt_cipher_interface\n");
		goto _ret_;
	}


_ret_:

	if (operation) {
		TEE_FreeOperation(operation);	
	}
	if(res != TEE_SUCCESS) {
		TEE_Panic(res);
	}

	return res;
}
 
