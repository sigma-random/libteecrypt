#include <tee_api.h>
#include <utee_api.h>
 


#define SHA_DIGEST_LENGTH       0x14
#define SHA256_DIGEST_LENGTH    0x20

#define MIN_RSA_KEY_BITS        256
#define MAX_RSA_KEY_BITS        2048

#define TEE_RSA_RAW_KEY         0x01
#define TEE_RSA_REAL_KEY        0x00

#define IS_KEY_PAIR             true
#define IS_PUB_KEY              false



TEE_Result rsaSignDigestWithSha256(const void *digest, size_t digestLen, 
                    void *sign, size_t *signLen,
                    TEE_ObjectHandle hRsaKeyPairObject);

TEE_Result rsaVerifyDigestWithSha256(const void *digest, size_t digestLen, 
                    void *sign, size_t signLen, 
                    TEE_ObjectHandle hRsaPubKeyObject);

TEE_Result  rsa_verify();
TEE_Result  rsa_sign_verify();

int main(int argc, char **argv) {

    rsa_verify();
    //rsa_sign_verify();
    exit(0);
    return 0;
}


TEE_Result  rsa_verify() {

    TEE_Result res;
    uint32_t rsaKeyBits = 1024;                                   // 256 ~ 2048    
    TEE_ObjectHandle hRsaPubKeyObject   = TEE_HANDLE_NULL;
    TEE_ObjectType rsaPubKeyObjectType  = TEE_TYPE_RSA_PUBLIC_KEY;

    if(TEE_InitCryptContext() != TEE_SUCCESS) {
        TEE_Printf("[err] TEE_InitCryptContext\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }
    void *digest = \
    "1234567812345678123456781234567812345678123456781234567812345678" \
    "1234567812345678123456781234567812345678123456781234567812345678" \
    "1234567812345678123456781234567812345678123456781234567812345678";
    void *N =  "\x00"\
    "\xd6\xe1\x77\xa9\x15\xc1\x50\xf5\xea\xf5\x50\xb7\xb5\x3f\x7b\x01"\
    "\xef\xa3\xf3\xcb\x0b\x46\xf8\x0a\x92\x52\x86\x16\x9d\x7e\x4d\xa5"\
    "\xcc\x12\xd5\xb8\x95\xd2\x30\x5f\x4e\xdf\xce\x24\xb7\x34\x6c\x6a"\
    "\x0a\xf5\x89\xed\xf2\x30\x32\x5b\xaf\xd7\x68\xcb\x82\xff\xfc\x7f"\
    "\xd2\x90\x49\x5d\xea\x26\x8b\xea\xf7\x3c\xbe\x5e\xda\xb8\xc2\xba"\
    "\x8c\x82\x80\x03\x57\x8d\xf7\x5b\xd8\x69\x80\x4c\xe6\xe1\x7b\x25"\
    "\x02\x0a\xd8\xd2\xe4\xcd\xc8\x9c\xec\xbe\xa7\x46\x88\x1b\xcd\x07"\
    "\xba\x49\x37\x18\x1f\xc9\xc6\xe0\x38\xae\xa3\xf5\x2a\xbc\x58\x37";
    /* E = 0x00010001 */
    void *E = "\x01\x00\x01";
    void *signature =  \
    "\x51\x14\xd3\x8a\x1e\x1d\xe8\xa7\xac\x80\x34\x7b\xdb\x38\xff\x98"\
    "\xb8\x6c\x02\x28\xed\xad\x05\x90\xe3\x4f\xc2\xcc\x14\xfa\x4b\x32"\
    "\x44\x4d\x52\x12\x32\x1d\xa9\x5f\x47\x0d\x72\x28\xd8\xfa\x31\x52"\
    "\xf6\x4d\x8f\x3a\xc8\xa4\x19\x50\xc2\x39\x7d\x4f\x35\xe3\xde\xdf"\
    "\x76\xc6\x67\x1d\x72\x3f\x05\x01\x46\x50\xbd\xe9\x91\x4d\x4e\xcd"\
    "\x6b\x52\x63\x24\x89\x9e\x92\xf9\x77\xc6\xd4\x77\xcc\x81\xa5\xb9"\
    "\x22\x67\xd0\xe9\x82\xee\xb2\x21\x53\x76\x7e\xee\x7b\x47\x1e\xca"\
    "\x18\xa1\x21\xd5\x6f\x87\x80\xbd\x75\x1f\xd4\x04\x40\x2f\xba\x4e";

    res = TEE_AllocateTransientObject( rsaPubKeyObjectType, MAX_RSA_KEY_BITS, &hRsaPubKeyObject);
    if(res != TEE_SUCCESS) {
        TEE_Printf("[err] TEE_AllocateTransientObject\n");
        goto _ret_;
    }
    
    TEE_Attribute attr_list[2];
    uint32_t attributeID;
    attributeID = TEE_ATTR_RSA_MODULUS;
    TEE_MemFill(&attr_list[0], sizeof(attr_list[0]), 0);
    TEE_InitRefAttribute(&attr_list[0], attributeID /* TEE_ATTR_SECRET_VALUE */, N, 0x81 );
    attributeID = TEE_ATTR_RSA_PUBLIC_EXPONENT;
    TEE_MemFill(&attr_list[1], sizeof(attr_list[1]), 0);
    TEE_InitRefAttribute(&attr_list[1], attributeID /* TEE_ATTR_SECRET_VALUE */, E, 0x03 );

    res = TEE_PopulateTransientObject(hRsaPubKeyObject, &attr_list[0], sizeof(attr_list)/sizeof(attr_list[0]));
    if(res != TEE_SUCCESS) {
        TEE_Printf("[err] TEE_PopulateTransientObject\n");
        goto _ret_;
    }else {
        TEE_DumpRSAKeyObj(hRsaPubKeyObject, rsaKeyBits, IS_PUB_KEY, TEE_RSA_REAL_KEY); // TEE_RSA_RAW_KEY or TEE_RSA_REAL_KEY  
    }  

    res = rsaVerifyDigestWithSha256(digest, SHA256_DIGEST_LENGTH, signature, 128, hRsaPubKeyObject);
    if(res != TEE_SUCCESS) {
        TEE_Printf("[err] rsaVerifyDigestWithSha256\n");
        goto _ret_;
    }else {
        TEE_Printf("[info] rsaVerifyDigestWithSha256 success!\n");
    }

_ret_:
    if(hRsaPubKeyObject) {
        TEE_FreeTransientObject(hRsaPubKeyObject);
    }
    if(TEE_FiniCryptContext() != TEE_SUCCESS) {
        TEE_Printf("[err] TEE_FiniCryptContext\n");
    }

    return res;
}


TEE_Result  rsa_sign_verify() {

    TEE_Result res;
    uint32_t rsaKeyBits = 1024;                                   // 256 ~ 2048    
    TEE_ObjectHandle hRsaKeyPairObject  = TEE_HANDLE_NULL;
    TEE_ObjectHandle hRsaPubKeyObject   = TEE_HANDLE_NULL;
    TEE_ObjectType rsaKeyPairObjectType = TEE_TYPE_RSA_KEYPAIR;
    TEE_ObjectType rsaPubKeyObjectType  = TEE_TYPE_RSA_PUBLIC_KEY;

    void *digest = \
    "1234567812345678123456781234567812345678123456781234567812345678" \
    "1234567812345678123456781234567812345678123456781234567812345678" \
    "1234567812345678123456781234567812345678123456781234567812345678" \
    "1234567812345678123456781234567812345678123456781234567812345678" \
    "1234567812345678123456781234567812345678123456781234567812345678" \
    "1234567812345678123456781234567812345678123456781234567812345678" \
    "1234567812345678123456781234567812345678123456781234567812345678" \
    "1234567812345678123456781234567812345678123456781234567812345678";

    if(TEE_InitCryptContext() != TEE_SUCCESS) {
        TEE_Printf("[err] TEE_InitCryptContext\n");
    }
    size_t signLen = rsaKeyBits / 8;

    void *sign = TEE_Malloc( signLen, 0);
    if(!sign) {
        TEE_Printf("[err] TEE_Malloc\n");
        res = TEE_ERROR_BAD_STATE;
        goto _ret_;
    }

    /* new random rsa keypair object */
    res = TEE_NewRandomKeyObject(rsaKeyPairObjectType, rsaKeyBits, &hRsaKeyPairObject);
    if(res != TEE_SUCCESS) {
        TEE_Printf("[err] TEE_NewRandomKeyObject  RsaKeyPairObject\n");
        goto _ret_;
    }else {
        TEE_DumpRSAKeyObj(hRsaKeyPairObject, rsaKeyBits, IS_KEY_PAIR, TEE_RSA_REAL_KEY); // TEE_RSA_RAW_KEY or TEE_RSA_REAL_KEY  
    }

    res = rsaSignDigestWithSha256(digest, SHA256_DIGEST_LENGTH, sign, &signLen, hRsaKeyPairObject);
    if(res != TEE_SUCCESS ) {
        TEE_Printf("[err] rsaSignDigestWithSha256\n");
        goto _ret_;
    }else {
        TEE_Printf("[info] rsaSignDigestWithSha256 success!\n");
        TEE_Hexdump("SignDigest", sign, signLen, 16, true);
    }

    /* new rsa public key object */
    void *E = "\x01\x00\x01"; 
    void *N = \
    "\xc6\xe9\xb6\x47\xcf\x9a\x33\xf4\x18\xbf\x1f\xa4\xc5\xd2\x7d\x52" \
    "\x56\x3f\xdb\x8f\x5a\xf8\xb8\x46\xee\xcc\x26\x55\x4c\xca\x86\x6c" \
    "\x9a\x2f\xab\x49\xc0\x9a\x8a\x0f\xcb\xd5\xfa\xe7\xa2\xca\xef\x6e" \
    "\x73\xb2\xa8\xd2\x07\x2a\x6c\x0d\xd2\x9c\xdb\x33\xf3\xb4\xd5\x60" \
    "\x03\x37\x6d\x62\x0e\x23\x3d\x80\xe9\xc2\x60\xae\x0e\x9e\xd9\x80" \
    "\x1d\xb8\x72\xb4\x4f\x5f\x10\x0e\x45\x0a\x9a\x3f\xe4\xc6\xc8\x4d" \
    "\x92\xf9\xac\xa4\x40\x86\xce\xdb\x92\xcc\x16\xb7\x4b\x01\xfc\x9c" \
    "\x3c\xd4\xaf\x06\xa9\x20\xc4\xb2\x71\x3d\xea\x19\x86\x86\xa7\x53";
    
    res = TEE_AllocateTransientObject( rsaPubKeyObjectType, MAX_RSA_KEY_BITS, &hRsaPubKeyObject);
    if(res != TEE_SUCCESS) {
        TEE_Printf("[err] TEE_AllocateTransientObject\n");
        goto _ret_;
    }

    TEE_Attribute attr_list[2];
    uint32_t attributeID;
    attributeID = TEE_ATTR_RSA_MODULUS;
    TEE_MemFill(&attr_list[0], sizeof(attr_list[0]), 0);
    TEE_InitRefAttribute(&attr_list[0], attributeID /* TEE_ATTR_SECRET_VALUE */, N, 0x80 );
    attributeID = TEE_ATTR_RSA_PUBLIC_EXPONENT;
    TEE_MemFill(&attr_list[1], sizeof(attr_list[1]), 0);
    TEE_InitRefAttribute(&attr_list[1], attributeID /* TEE_ATTR_SECRET_VALUE */, E, 0x03 );

    res = TEE_PopulateTransientObject(hRsaPubKeyObject, &attr_list[0], sizeof(attr_list)/sizeof(attr_list[0]));
    if(res != TEE_SUCCESS) {
        TEE_Printf("[err] TEE_PopulateTransientObject\n");
        goto _ret_;
    }else {
        TEE_DumpRSAKeyObj(hRsaPubKeyObject, rsaKeyBits, IS_PUB_KEY, TEE_RSA_REAL_KEY); // TEE_RSA_RAW_KEY or TEE_RSA_REAL_KEY  
    }  

    res = rsaVerifyDigestWithSha256(digest, SHA256_DIGEST_LENGTH, sign, 128, hRsaPubKeyObject);
    if(res != TEE_SUCCESS) {
        TEE_Printf("[err] rsaVerifyDigestWithSha256\n");
        goto _ret_;
    }else {
        TEE_Printf("[info] rsaVerifyDigestWithSha256 success!\n");
    }

_ret_:
    
    if(sign) {
        TEE_Free(sign);
    }
    if(hRsaKeyPairObject) {
        TEE_FreeTransientObject(hRsaKeyPairObject);
    }
    if(hRsaPubKeyObject) {
        TEE_FreeTransientObject(hRsaPubKeyObject);
    }
    if(TEE_FiniCryptContext() != TEE_SUCCESS) {
        TEE_Printf("[err] TEE_FiniCryptContext\n");
    }

    return res;
}

TEE_Result rsaSignDigestWithSha256(const void *digest, size_t digestLen, 
                    void *sign, size_t *signLen,
                    TEE_ObjectHandle hRsaKeyPairObject) {

    TEE_Result res;
    TEE_OperationHandle signDigestOperation = TEE_HANDLE_NULL;
    uint32_t algorithm  = TEE_ALG_RSASSA_PKCS1_V1_5_SHA256;       // PKCS_1_V1_5
    uint32_t crypt_mode = TEE_MODE_SIGN;                          // TEE_MODE_SIGN OR TEE_MODE_VERIFY

    res = TEE_AllocateOperation(&signDigestOperation, algorithm, 
                            crypt_mode, MAX_RSA_KEY_BITS);
    if(res != TEE_SUCCESS) {
        TEE_Printf("[err] TEE_AllocateOperation\n");
        goto _ret_;
    }
    res = TEE_SetOperationKey(signDigestOperation, hRsaKeyPairObject);
    if(res != TEE_SUCCESS) {
        TEE_Printf("[err] TEE_SetOperationKey\n");
        goto _ret_;
    }
    res = TEE_AsymmetricSignDigest(signDigestOperation, NULL, 0, 
                                (const void*)digest, digestLen, 
                                sign, signLen);
    if(res != TEE_SUCCESS) {
        TEE_Printf("[err] TEE_AsymmetricSignDigest\n");
        goto _ret_;
    }
    if(*signLen <= 0){
        res = TEE_ERROR_NO_DATA;
    }

_ret_:

    if (signDigestOperation) {
        TEE_FreeOperation(signDigestOperation);   
    }

    return res;
}

TEE_Result rsaVerifyDigestWithSha256(const void *digest, size_t digestLen, 
                void *sign, size_t signLen, 
                TEE_ObjectHandle hRsaPubKeyObject) {

    TEE_Result res;
    TEE_OperationHandle verifyDigestOperation = TEE_HANDLE_NULL;
    uint32_t algorithm  = TEE_ALG_RSASSA_PKCS1_V1_5_SHA256;       // PKCS_1_V1_5
    uint32_t crypt_mode = TEE_MODE_VERIFY;                        // TEE_MODE_SIGN OR TEE_MODE_VERIFY

    res = TEE_AllocateOperation(&verifyDigestOperation, algorithm, 
                            crypt_mode, MAX_RSA_KEY_BITS);
    if(res != TEE_SUCCESS) {
        TEE_Printf("[err] TEE_AllocateOperation\n");
        goto _ret_;
    }
    res = TEE_SetOperationKey(verifyDigestOperation, hRsaPubKeyObject);
    if(res != TEE_SUCCESS) {
        TEE_Printf("[err] TEE_SetOperationKey\n");
        goto _ret_;
    }
    res = TEE_AsymmetricVerifyDigest(verifyDigestOperation, NULL, 0, 
                                (const void*)digest, digestLen, 
                                sign, signLen);
    if(res != TEE_SUCCESS) {
        TEE_Printf("[err] TEE_AsymmetricVerifyDigest\n");
        goto _ret_;
    }

_ret_:

    if (verifyDigestOperation) {
        TEE_FreeOperation(verifyDigestOperation);   
    }

    return res;
}
