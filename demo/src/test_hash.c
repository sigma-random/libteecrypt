#include <tee_api.h>
#include <utee_api.h>


TEE_Result crypt_hash_sha256(const char *message, size_t message_len,
							void *hash, size_t *hash_len );



int main(int argc, char **argv)
{
	TEE_Result res = TEE_ERROR_GENERIC;

	if(TEE_InitCryptContext() != TEE_SUCCESS) {
		TEE_Printf("[err] TEE_InitCryptContext\n");
		goto _ret_;
	}

	unsigned char mess[100]    = "0123456789012345678901234567890123456789012345678901234567890123456789";
	
	size_t mess_len   = 1;

	size_t hash_len = 32;
	
	void *hash      = TEE_Malloc(hash_len, 0);
	
	if (!hash) {
		TEE_Printf("[err] TEE_Malloc(0x%x, 0x%x);\n",hash_len, 0);
		goto _ret_;
	}	

	res = crypt_hash_sha256((const char *)mess, mess_len, hash, &hash_len );

	if(res != TEE_SUCCESS) {
		TEE_Printf("[err] crypt_hash_sha256\n");
		goto _ret_;
	}
	if( hash_len > 0) {
		TEE_Hexdump("message", mess, mess_len, 16, true);
		TEE_Hexdump("hash_sha256", hash, hash_len, 16, true);
	}

_ret_:

	if(TEE_FiniCryptContext() != TEE_SUCCESS) {
		TEE_Printf("[err] TEE_FiniCryptContext\n");
	}

	exit(0);
    return 0;
}


TEE_Result crypt_hash_interface(TEE_OperationHandle operation,
								const void *message, size_t message_len, 
								void *hash, size_t *hash_len) 
{
	TEE_Result res = TEE_ERROR_GENERIC;
	size_t block_size = operation->block_size;
	TEE_Printf("[info] operation->block_size = 0x%x\n", block_size);
	
	size_t process_len = message_len;
	void * src = (void *)message;

	if(!operation || !message || !hash) {
		return TEE_ERROR_BAD_PARAMETERS;
	}

	switch(1) {

		case 0:
			res = TEE_DigestDoFinal(operation, src, process_len, hash, hash_len);	
			if (res != TEE_SUCCESS) {
				TEE_Printf("[err] TEE_DigestDoFinal\n");
				return res;
			}	

			break;

		case 1:		// using TEE_DigestUpdate
		default:
			while( process_len/block_size > 1 ) {
				TEE_DigestUpdate(operation, src, block_size);
				process_len -= block_size;
				src += block_size;
			}
			res = TEE_DigestDoFinal(operation, src, process_len, hash, hash_len);	
			if (res != TEE_SUCCESS) {
				TEE_Printf("[err] TEE_DigestDoFinal\n");
				return res;
			}
	}

	return res;
}


TEE_Result crypt_hash_sha256(const char *message, size_t message_len,
							void *hash, size_t *hash_len )
{
	TEE_Result res = TEE_ERROR_GENERIC;

	TEE_OperationHandle operation = TEE_HANDLE_NULL;
	uint32_t algorithm  = TEE_ALG_SHA256;
	uint32_t mode       = TEE_MODE_DIGEST;
	uint32_t maxKeySize = 0;

	res = TEE_AllocateOperation(&operation, algorithm, mode, maxKeySize);
	if(res != TEE_SUCCESS) {
		TEE_Printf("[err] TEE_AllocateOperation\n");
		goto _ret_;
	}

	res = crypt_hash_interface(operation, (const void*)message, message_len, 
								hash, hash_len );
	if (res != TEE_SUCCESS) {
		TEE_Printf("[err] crypt_hash_interface\n");
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

