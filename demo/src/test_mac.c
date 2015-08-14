#include <tee_api.h>
#include <utee_api.h>

 


TEE_Result crypt_hmac_md5(const void *message, size_t message_len,
						const void *key, size_t key_len,
						void *mac, size_t *mac_len);


int main(int argc, char **argv)
{
	TEE_Result res = TEE_ERROR_GENERIC;

	if(TEE_InitCryptContext() != TEE_SUCCESS) {
		TEE_Printf("[err] TEE_InitCryptContext\n");
		return 0;
	}

	unsigned char mess[] = "0123456789012345678901234567890123456789012345678901234567890123456789";

	size_t mess_len = 1;

	unsigned char key[] = "1234567887654321";

	size_t key_len = 5;

	size_t mac_len = 16;

	void *mac = TEE_Malloc(mac_len, 0);
	if(!mac) {
		TEE_Printf("[err] TEE_Malloc\n");
		return 0;
	}

	res = crypt_hmac_md5((const void *)mess, mess_len, 
						(const void *)key, key_len, 
						mac, &mac_len);
	
	if(res != TEE_SUCCESS) {
		TEE_Printf("[err] crypt_hmac_md5\n");
		return 0;
	}	
	if( mac_len > 0) {
		TEE_Hexdump("message", mess, mess_len, 16, true);
		TEE_Hexdump("key", key, key_len, 16, true);
		TEE_Hexdump("hmac-md5", mac, mac_len, 16, true);
	}

	if(TEE_FiniCryptContext() != TEE_SUCCESS) {
		TEE_Printf("[err] TEE_FiniCryptContext\n");
	}
	
	exit(0);
    return 0;
}


TEE_Result crypt_hmac_interface(TEE_OperationHandle operation,
								const void *message, size_t message_len, 
								void *mac, size_t *mac_len) 
{
	TEE_Result res = TEE_ERROR_GENERIC;
	size_t block_size = operation->block_size;
	TEE_Printf("[info] operation->block_size = 0x%x\n", block_size);

	size_t process_len = message_len;
	void * src = (void *)message;


	if(!operation || !message || !mac) {
		return TEE_ERROR_BAD_PARAMETERS;
	}

	switch(1) {

		case 0:
			TEE_MACInit(operation, NULL, 0);
			res = TEE_MACComputeFinal(operation, src, process_len, mac, mac_len);
			if (res != TEE_SUCCESS) {
				TEE_Printf("[err] TEE_MACComputeFinal\n");
				return res;
			}		
			break;

		case 1:	// using TEE_MACUpdate
		default:
			TEE_MACInit(operation, NULL, 0);
			while( process_len/block_size > 1 ) {
				TEE_MACUpdate(operation, src, block_size);
				process_len -= block_size;
				src += block_size;
			}
			res = TEE_MACComputeFinal(operation, src, process_len, mac, mac_len);	
			if (res != TEE_SUCCESS) {
				TEE_Printf("[err] TEE_MACComputeFinal\n");
				return res;
			}	

	}

	return res;
}
 

TEE_Result crypt_hmac_md5(const void *message, size_t message_len,
						const void *key, size_t key_len,
						void *mac, size_t *mac_len)
{
	TEE_Result res = TEE_ERROR_GENERIC;
	TEE_OperationHandle operation = TEE_HANDLE_NULL;
	uint32_t algorithm    = TEE_ALG_HMAC_MD5;
	uint32_t mode         = TEE_MODE_MAC;
	uint32_t maxKeySize   = 512;

	res = TEE_AllocateOperation(&operation, algorithm, mode, maxKeySize);
	if(res != TEE_SUCCESS) {
		TEE_Printf("[err] TEE_AllocateOperation\n");
		goto _ret_;
	}

	if(!key || 0 >= key_len) {
		res = TEE_ERROR_BAD_PARAMETERS;
		goto _ret_;
	}

	TEE_Attribute attr_list[1];
	uint32_t attributeID = TEE_ATTR_SECRET_VALUE;
	TEE_MemFill(&attr_list[0], sizeof(attr_list[0]), 0);
	TEE_InitRefAttribute(&attr_list[0], attributeID /* TEE_ATTR_SECRET_VALUE */, (void *)key, key_len );
	res = TEE_PopulateTransientObject(operation->key1, &attr_list[0], sizeof(attr_list)/sizeof(attr_list[0]));
	if(res != TEE_SUCCESS) {
		TEE_Printf("[err] TEE_PopulateTransientObject\n");
		goto _ret_;
	}

	res = crypt_hmac_interface(operation, (const void *)message, message_len, 
							mac, mac_len);
	if(res != TEE_SUCCESS) {
		TEE_Printf("[err] crypt_hmac_interface\n");
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

