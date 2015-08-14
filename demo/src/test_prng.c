#include <tee_api.h>
#include <utee_api.h>
 


int main(int argc, char **argv)
{
    size_t len = 32;
    void *randomBuffer = TEE_Malloc(len, 0);
    if (!randomBuffer) {
    	 TEE_Panic(TEE_ERROR_GENERIC);
    }
	
	if(TEE_InitCryptContext() != TEE_SUCCESS) {
	  TEE_Printf("[err] TEE_InitCryptContext\n");
	  return 0;
	}

    TEE_GenerateRandom(randomBuffer, len);

    TEE_Hexdump("demo_prng", randomBuffer, len, len, true);

	if(TEE_FiniCryptContext() != TEE_SUCCESS) {
	  TEE_Printf("[err] TEE_FiniCryptContext\n");
	}

	exit(0);
    return 0;
}
