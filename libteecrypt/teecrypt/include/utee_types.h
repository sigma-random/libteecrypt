#ifndef UTEE_TYPES_H
#define UTEE_TYPES_H


/********************* TEE_OperationHandle ******************************/

struct __TEE_OperationHandle {
    TEE_OperationInfo info;
    TEE_ObjectHandle key1;
    TEE_ObjectHandle key2;
    uint8_t *buffer;        /* buffer to collect complete blocks */
    bool buffer_two_blocks; /* True if two blocks need to be buffered */
    size_t block_size;      /* Block size of cipher */
    size_t buffer_offs;     /* Offset in buffer */
    uint32_t state;         /* Handle state  */
    uint32_t ae_tag_len;    /* tag_len in bytes for AE signDigestOperation else unused */
};
//typedef struct __TEE_OperationHandle*  TEE_OperationHandle;


/********************* X509 Cert ******************************/


#define IS_RSA_PUBKEY   0x01010101
#define IS_DSA_PUBKEY   0x01010102
#define IS_OTHER_PUBKEY 0x01010103

struct DSA_PublicKey {
    // todo
};

struct RSA_PublicKey {
    int N_len;
    unsigned char *N;
    int E_len;
    unsigned char *E;
};

struct PublicKey {

    int type;
    union {
        struct RSA_PublicKey rsa_pubkey;
        struct DSA_PublicKey dsa_pubkey;
        struct {
            int len;
            unsigned char *data; 
        }o;
    }pubkey;

};

struct X509_NAME {
    int email_len;
    unsigned char *email;
    int country_len;
    unsigned char *country;
    int province_len;
    unsigned char *province;
    int orgnization_len;
    unsigned char *orgnization;
    int city_len;
    unsigned char *city;
    int user_len;
    unsigned char *user;
    int department_len;
    unsigned char *department;
};

struct X509_EXTENSION {
    int issuerUID_len;
    unsigned char *issuerUID;       /* [ 1 ] optional in v2 or v3*/
    int subjectUID_len;
    unsigned char *subjectUID;      /* [ 2 ] optional in v2 or v3*/
    int authKID_len;
    unsigned char *authKID;
    int subKID_len;
    unsigned char *subKID;
    int keyUSG_len;
    unsigned char *keyUSG;
    int subAltName_len;
    unsigned char *subAltName;
    int basicConstraints_len;
    unsigned char *basicConstraints;
    int extKUSG_len;
    unsigned char *extKUSG;
    int CRLDP_len;
    unsigned char *CRLDP;
    int alg_len;
    unsigned char *alg;
    int extk_len;
    unsigned char *extk;
};


struct X509_CINF {
    int version;                        /*  default of v1 (0), v2(1), v3(2)*/
    int serialNumber_len;
    unsigned char *serialNumber;
    int algorithm_len;
    unsigned char *algorithm;
    struct X509_NAME issuer;
    int notBefore_len;
    unsigned char *notBefore;
    int notAfter_len;
    unsigned char *notAfter;
    struct X509_NAME subject;
    int algor_len;
    unsigned char *algor;
    //int public_key_len;
    //unsigned char *public_key;
    struct PublicKey public_key;
    struct X509_EXTENSION extensions;   /* [ 3 ] optional in v3 */
    int signature_len;
    unsigned char *signature;   
}x509_cinf_st;


typedef struct X509_CINF X509_st;




#endif