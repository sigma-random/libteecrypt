#ifndef CRYPT_X509_H
#define CRYPT_X509_H




/* ASN types */

#define ASN_INT 0x02
#define ASN_BITSTRING 0x03
#define ASN_NULL 0x05
#define ASN_OID 0x06
#define ASN_UTCTIME 0x17
#define ASN_GENTIME 0x18
#define ASN_SEQUENCE 0x30
#define ASN_SET 0x31
#define ASN_VERSON 0xa0
#define ASN_EXTENSIONS 0xa3

/* define OIDs */
#define IS_OID_email 0x01
#define IS_OID_orgnization 0x02
#define IS_OID_country 0x03
#define IS_OID_province 0x04
#define IS_OID_department 0x05
#define IS_OID_city 0x06
#define IS_OID_user 0x07
#define IS_OID_authKID 0x08
#define IS_OID_subKID 0x09
#define IS_OID_subaltname 0x10
#define IS_OID_keyUsage 0x11
#define IS_OID_basicCon 0x12
#define IS_OID_extKeyUsage 0x13
#define IS_OID_CRLDP 0x14

#define IS_OID_md5withRSAEnc 0x15
#define IS_OID_sha256withRSAEnc 0x16
#define IS_OID_sha512withRSAEnc 0x17

#define IS_OID_rsaEnc 0x20

/* OID values */
static unsigned int OID_user[]         = {2, 5, 4, 3};
static unsigned int OID_country[]      = {2, 5, 4, 6};
static unsigned int OID_city[]         = {2, 5, 4, 7};
static unsigned int OID_province[]     = {2, 5, 4, 8};
static unsigned int OID_orgnization[]  = {2, 5, 4, 10};
static unsigned int OID_department[]   = {2, 5, 4, 11};

static unsigned int OID_subKID[]       = {2, 5, 29, 14}; 
static unsigned int OID_keyUsage[]     = {2, 5, 29, 15};
static unsigned int OID_subaltname[]   = {2, 5, 29, 17};
static unsigned int OID_basicCon[]     = {2, 5, 29, 19};
static unsigned int OID_CRLDP[]        = {2, 5, 29, 31};
static unsigned int OID_authKID[]      = {2, 5, 29, 35};
static unsigned int OID_extKeyUsage[]  = {2, 5, 29, 37};

/* signature algorithm */
static unsigned int OID_md5withRSAEncryption[]     = {1, 2, 840, 113549, 1, 1, 4};
static unsigned int OID_sha256withRSAEncryption[]  = {1, 2, 840, 113549, 1, 1, 11};
static unsigned int OID_sha512withRSAEncryption[]  = {1, 2, 840, 113549, 1, 1, 12};

/* public key */
static unsigned int OID_rsaEncryption[]            = {1, 2, 840, 113549, 1, 1, 1}; 
static unsigned int OID_email[]                    = {1, 2, 840, 113549, 1, 9, 1};


X509_st* loadX509Cert(char *filename);
void freeX509Cert(X509_st* x509);


#endif




















