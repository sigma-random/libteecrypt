#include <tee_api.h>
#include <utee_api.h>


int main() {

	TEE_Result res;
	X509_st *x509 = NULL;

	if(TEE_InitCryptContext() != TEE_SUCCESS) {
	  TEE_Printf("[err] TEE_InitCryptContext\n");
	  return 0;
	}
	
	res = TEE_LoadX509Cert("ca.der", &x509);
	if(res != TEE_SUCCESS || x509 == NULL ) {
		goto _out_;
	}

    TEE_Hexdump("version",(void*)&x509->version, sizeof(x509->version), 16, 1);
    TEE_Hexdump("serialNumber",(void*)x509->serialNumber, x509->serialNumber_len, 16, 1);
    TEE_Hexdump("algorithm",(void*)x509->algorithm, x509->algorithm_len, 16, 1);
    TEE_Hexdump("subject user",(void*)x509->subject.user, x509->subject.user_len, 16, 1);

    if(x509->public_key.type == IS_RSA_PUBKEY) {
        TEE_Hexdump("rsa publickey->N",(void*)x509->public_key.pubkey.rsa_pubkey.N, x509->public_key.pubkey.rsa_pubkey.N_len, 16, 1);
        TEE_Hexdump("rsa publickey->E",(void*)x509->public_key.pubkey.rsa_pubkey.E, x509->public_key.pubkey.rsa_pubkey.E_len, 16, 1);
    }
    
    TEE_Hexdump("signature",(void*)x509->signature, x509->signature_len, 16, 1);

    TEE_FreeX509Cert(x509);

	if(TEE_FiniCryptContext() != TEE_SUCCESS) {
	  TEE_Printf("[err] TEE_FiniCryptContext\n");
	}

_out_:

	exit(0);
    return 0;
}
