#include "tomcrypt.h"

int SMS4_Setup(const unsigned char *key, int keylen, int num_rounds, symmetric_key *skey);
int SMS4_ECB_Encrypt(const unsigned char *pt, unsigned char *ct, symmetric_key *skey);
int SMS4_ECB_Decrypt(const unsigned char *ct, unsigned char *pt, symmetric_key *skey);
void SMS4_Done(symmetric_key *skey);
int SMS4_Keysize(int *keysize);
int SMS4_Test(void);


const struct ltc_cipher_descriptor sm_sms4_desc =
{
    "sm_sms4",
    40,
    16, 16, 16, 32,
    &SMS4_Setup,
    &SMS4_ECB_Encrypt,
    &SMS4_ECB_Decrypt,
    &SMS4_Test,
    &SMS4_Done,
    &SMS4_Keysize,
    NULL, 
    NULL, 
    NULL, 
    NULL, 
    NULL, 
    NULL, 
    NULL, 
    NULL, 
    NULL, 
    NULL, 
    NULL, 
    NULL
};


int SMS4_Setup(const unsigned char *key, int keylen, int num_rounds, symmetric_key *skey)
{
    skey->data = tomcrypt_malloc(keylen);
    if(!skey->data) {
        return CRYPT_MEM;
    }
    tomcrypt_memcpy(skey->data, key, keylen);

	return CRYPT_OK;
}


int SMS4_ECB_Encrypt(const unsigned char *pt, unsigned char *ct, symmetric_key *skey)
{
    T_U8* pKey = NULL;
    T_U8* pInData = NULL;
    T_U8* pOutData = NULL;
    T_U16 block_size;

    pKey = (T_U8*)skey->data;
    pInData = (T_U8*)pt;
    pOutData = (T_U8*)ct;
    block_size = 16;        

    if(SMS4EncryptECB(pKey, pInData, block_size, pOutData) != SMS4_NO_ERR ) {
        return CRYPT_ERROR;
    }

	return CRYPT_OK;

}


int SMS4_ECB_Decrypt(const unsigned char *ct, unsigned char *pt, symmetric_key *skey)
{
    T_U8* pKey = NULL;
    T_U8* pInData = NULL;
    T_U8* pOutData = NULL;
    T_U16 block_size;

    pKey = (T_U8*)skey->data;
    pInData = (T_U8*)ct;
    pOutData = (T_U8*)pt;
    block_size = 16;       

    if(SMS4DecryptECB(pKey, pInData, block_size, pOutData) != SMS4_NO_ERR ) {
        return CRYPT_ERROR;
    }

	return CRYPT_OK;
}

void SMS4_Done(symmetric_key *skey)
{
    if(skey->data) {
        tomcrypt_free(skey->data);
    }
}


int SMS4_Keysize(int *keysize)
{
    if(*keysize < 16) {
        return CRYPT_INVALID_KEYSIZE;
    }
    *keysize = 16;
    return CRYPT_OK;
}


int SMS4_Test(void) 
{
	return CRYPT_OK;
}


