#include <tee_api.h>
#include <utee_api.h>

 
 
TEE_Result set_key_value(TEE_ObjectHandle hKeyObject, const void *data, 
                            size_t data_size, uint32_t attributeID);


TEE_Result set_spec_key_method(const void *key, size_t kelen);
TEE_Result get_random_key_method1();
TEE_Result get_random_key_method2();



int main(int argc, char **argv)
{
    TEE_Result res = TEE_ERROR_GENERIC;
    unsigned char key[17] = "0000000000000000";
    size_t  keylen = 16; 

    if(TEE_InitCryptContext() != TEE_SUCCESS) {
        TEE_Printf("[err] TEE_InitCryptContext\n");
        return 0;
    }
    res = set_spec_key_method(key, keylen);
    res = get_random_key_method1();
    res = get_random_key_method2();

    if(TEE_FiniCryptContext() != TEE_SUCCESS) {
        TEE_Printf("[err] TEE_FiniCryptContext\n");
    }

    exit(0);
    return res;
}


TEE_Result set_spec_key_method(const void *key, size_t kelen)
{
    TEE_Result res;
    TEE_OperationHandle operation;
    uint32_t algorithm   = TEE_ALG_HMAC_MD5;
    uint32_t mode        = TEE_MODE_MAC;
    uint32_t maxKeySize  = 512;
    uint32_t attributeID = TEE_ATTR_SECRET_VALUE;


    res = TEE_AllocateOperation(&operation, algorithm, mode, maxKeySize);
    if(res != TEE_SUCCESS) {
        TEE_Printf("[err] TEE_AllocateOperation\n");
        goto _ret_;
    }

    res = set_key_value(operation->key1, key, kelen, attributeID);
    if(res != TEE_SUCCESS) {
        TEE_Printf("[err] set_key_value\n");
        goto _ret_;
    }

_ret_:

    if (operation) {
        TEE_FreeOperation(operation);   
    }

    return res;
}

 

TEE_Result get_random_key_method1()
{
    TEE_Result res;
    TEE_OperationHandle operation = TEE_HANDLE_NULL;
    uint32_t algorithm            = TEE_ALG_HMAC_MD5;
    uint32_t mode                 = TEE_MODE_MAC;
    uint32_t maxKeySize           = 512;

    res = TEE_AllocateOperation(&operation, algorithm, mode, maxKeySize);
    if(res != TEE_SUCCESS) {
        TEE_Printf("[err] TEE_AllocateOperation\n");
        goto _ret_;
    }

    uint32_t maxKeyObjectSize = maxKeySize; 

    //TEE_Attribute params;
    //uint32_t paramCount = 0;

    res = TEE_GenerateKey(operation->key1, maxKeyObjectSize, NULL, 0);
    if(res != TEE_SUCCESS) {
        TEE_Printf("[err] TEE_GenerateKey\n");
        return 0;
    }   

_ret_:

    if (operation) {
        TEE_FreeOperation(operation);   
    }

    return res;
}
 
TEE_Result get_random_key_method2()
{
    TEE_Result res;
    TEE_OperationHandle operation = TEE_HANDLE_NULL;
    uint32_t algorithm            = TEE_ALG_HMAC_MD5;
    uint32_t mode                 = TEE_MODE_MAC;
    uint32_t maxKeySize           = 512;

    res = TEE_AllocateOperation(&operation, algorithm, mode, maxKeySize);
    if(res != TEE_SUCCESS) {
        TEE_Printf("[err] TEE_AllocateOperation\n");
        goto _ret_;
    }

    TEE_ObjectHandle hKeyObject  = TEE_HANDLE_NULL;
    TEE_ObjectType keyObjectType = TEE_TYPE_HMAC_MD5;
    uint32_t maxKeyObjectSize    = maxKeySize; 

    res = TEE_NewRandomKeyObject(keyObjectType, maxKeyObjectSize, &hKeyObject);
    if(res != TEE_SUCCESS) {
        TEE_Printf("[err] TEE_AllocateTransientObject\n");
        return 0;
    }   
    
    res = TEE_SetOperationKey(operation, hKeyObject);
    if(res != TEE_SUCCESS) {
        TEE_Printf("[err] TEE_SetOperationKey\n");
        goto _ret_;
    }

_ret_:
    if (operation) {
        TEE_FreeOperation(operation);   
    }
    if(hKeyObject) {
        TEE_FreeTransientObject(hKeyObject);
    }

    return res;
}


TEE_Result set_key_value(TEE_ObjectHandle hKeyObject, const void *data, 
                                size_t data_size, uint32_t attributeID)
{
    TEE_Result res = TEE_ERROR_GENERIC;
    TEE_Attribute attr;

    if(!hKeyObject) {
        res = TEE_ERROR_BAD_STATE;
        goto _ret_;
    }
    if(!data || 0 >= data_size) {
        res = TEE_ERROR_BAD_PARAMETERS;
        goto _ret_;
    }

    TEE_MemFill(&attr, sizeof(attr), 0);
    TEE_InitRefAttribute(&attr, attributeID /* TEE_ATTR_SECRET_VALUE */, (void *)data, data_size );
    res = TEE_PopulateTransientObject(hKeyObject, &attr, 1);
    if(res != TEE_SUCCESS) {
        TEE_Printf("[err] TEE_PopulateTransientObject\n");
        goto _ret_;
    }

_ret_:

    if(res != TEE_SUCCESS) {
        TEE_Panic(res);
    }

    return res;
}
 