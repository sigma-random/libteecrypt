#include <utee_api.h>
#include <utee_mem.h>
#include "crypt_x509.h"


static int unsure = 0;
static int isRsaPubKey = 0;

static int isStruct(unsigned int rv);
static int chkItemLen(unsigned long *len,int *mark,int i);
static int setCount(unsigned char rv,unsigned char *expect,int *expectnumber,int *steps,int isoid,int count,int *bak);
static unsigned char *copyData(unsigned char *buf, int len);
static unsigned int readData(unsigned char **buf,unsigned char *temp,unsigned int fsize,int *cont);
static void errMsg(char *err);
static unsigned long getItemLen(unsigned char* temp,int *cont);
static int getOID(unsigned char *temp,int len);
static int oid2hex(unsigned int *oid, int oid_bytes, unsigned char **hex_buf);
static int fillX509(X509_st* x509, unsigned char *buf,int fsize,int count);
X509_st* loadX509Cert(char *filename);
void freeX509Cert(X509_st* x509);

int _main(int argc,char *argv[])
{
    X509_st* x509;

    if(argc != 2){
        TEE_Printf("Usage: %s  <derfilename>\n",argv[0]);
        exit(-1);
    }

    x509 = loadX509Cert( argv[1] );

    TEE_Hexdump("version",(void*)&x509->version, sizeof(x509->version), 16, 1);
    TEE_Hexdump("serialNumber",(void*)x509->serialNumber, x509->serialNumber_len, 16, 1);
    TEE_Hexdump("algorithm",(void*)x509->algorithm, x509->algorithm_len, 16, 1);
    TEE_Hexdump("subject user",(void*)x509->subject.user, x509->subject.user_len, 16, 1);
    if(x509->public_key.type == IS_RSA_PUBKEY) {
        TEE_Hexdump("rsa publickey->N",(void*)x509->public_key.pubkey.rsa_pubkey.N, x509->public_key.pubkey.rsa_pubkey.N_len, 16, 1);
        TEE_Hexdump("rsa publickey->E",(void*)x509->public_key.pubkey.rsa_pubkey.E, x509->public_key.pubkey.rsa_pubkey.E_len, 16, 1);
    }
    TEE_Hexdump("signature",(void*)x509->signature, x509->signature_len, 16, 1);

    freeX509Cert(x509);

    exit(0);
    return 0;
}




X509_st* loadX509Cert(char *filename)
{
    unsigned char aimtag[] = {0x02,0x02,0x06,0x7f,0x17,0x17,0x7f,0x06,0x03,0x7f,0x06,0x03};
    unsigned int i = 0, j = 0;
    size_t fsize, ftmpsize;
    int steps = 0, restore = 0;
    unsigned char *buf = NULL, *temp = NULL;
    unsigned len[512];
    int fd;
    int mark[512];
    int expnum = 0;
    int isoid,count = 0;
    int bak = 0;
    int cont=0;
    X509_st* x509_tmp = NULL;

    if(NULL == filename) {
        return 0;
    }

    if((fd = open((char *)filename, O_RDONLY)) < 0 ) {
        errMsg("can't open cert file!");
    }
    
    fsize = lseek(fd, 0L, SEEK_END);    
    if(fsize <= 0) {
        goto out;
    }

    if((temp = (unsigned char *)utee_mem_alloc(fsize)) == NULL) {
        errMsg("malloc error!");
    }
    utee_mem_fill(temp, 0, fsize);

    lseek(fd,0L,SEEK_SET);
    read(fd, (void*)temp, fsize) ;

    x509_tmp =  (X509_st*)utee_mem_alloc(sizeof(X509_st));
    if(x509_tmp == NULL) {
        goto out;
    }
    utee_mem_fill(x509_tmp, 0, sizeof(X509_st));
    
    i = 0;
    cont = 0;
    while(cont < fsize) {
        if(isStruct(temp[cont])) {
            cont++;
            len[i] = getItemLen(temp,&cont);
            if(!len[i]) {
                if(!i) {
                    len[i] = fsize;
                }
                ftmpsize = 1;
            }
            else {
                mark[i]=1;
                ftmpsize = unsure;
            }
            if(!i) {
                if((buf = (unsigned char *)utee_mem_alloc(len[i] + 1)) == NULL) {       
                    errMsg("utee_mem_alloc error!");
                }
            }
            for(j=0;j<i;j++) {
                if(mark[j] == 0) {
                    continue;
                }
                len[j] = len[j] - ftmpsize - 1;
                if(len[j] == 0) {
                    mark[j] = 0;
                }
            }
            i++;
        }
        else{
            isoid = (temp[cont] == 0x06)? 1 : 0;
            restore = temp[cont];
            cont++;
            ftmpsize = getItemLen(temp,&cont);
            ftmpsize = readData(&buf,temp,ftmpsize,&cont);
            if(isoid) {
                isoid = getOID(buf,ftmpsize);
            }
            if(restore != 0x05) {   // NULL
                count = setCount(restore,aimtag,&expnum,&steps,isoid,count,&bak);
                isoid = 0;
                if(count) {
                    int ret = fillX509(x509_tmp, buf, ftmpsize, count);
                    if(!ret) {
                        utee_mem_free(buf);
                        errMsg("fillX509 error!");
                    }
                }
                utee_mem_fill(buf,0,ftmpsize);
            }
            for(j=0;j<i;j++){
                if(mark[j] == 0) {
                    continue;
                }
                len[j] = len[j] - ftmpsize - unsure - 1;
                if(len[j] == 0) {
                    mark[j] = 0;
                }
            }
        }
        cont++;
        if(!chkItemLen((unsigned long *)len,mark,i)) {
            break;
        }
    }


out:
    if(fd) {
        close(fd);
    }
    if(temp) {
        utee_mem_free(temp);
    }
    if(buf) {
        utee_mem_free(buf);
    }
    //TEE_Printf("x509_tmp = 0x%08x\n",x509_tmp);
    return x509_tmp;
}
 

void freeX509Cert(X509_st* x509) {

    if(x509 != NULL) {
        if(x509->serialNumber) {
            utee_mem_free(x509->serialNumber); 
        }
        if(x509->algorithm) {
            utee_mem_free(x509->algorithm); 
        }
        if(x509->issuer.email) {
            utee_mem_free(x509->issuer.email); 
        }
        if(x509->issuer.country) {
            utee_mem_free(x509->issuer.country); 
        }
        if(x509->issuer.province) {
            utee_mem_free(x509->issuer.province); 
        }
        if(x509->issuer.orgnization) {
            utee_mem_free(x509->issuer.orgnization); 
        }
        if(x509->issuer.city) {
            utee_mem_free(x509->issuer.city); 
        }
        if(x509->issuer.user) {
            utee_mem_free(x509->issuer.user); 
        }
        if(x509->issuer.department) {
            utee_mem_free(x509->issuer.department); 
        }
        if(x509->notBefore) {
            utee_mem_free(x509->notBefore); 
        }
        if(x509->notAfter) {
            utee_mem_free(x509->notAfter); 
        }
        if(x509->subject.email) {
            utee_mem_free(x509->subject.email); 
        }
        if(x509->subject.country) {
            utee_mem_free(x509->subject.country); 
        }
        if(x509->subject.province) {
            utee_mem_free(x509->subject.province); 
        }
        if(x509->subject.orgnization) {
            utee_mem_free(x509->subject.orgnization); 
        }
        if(x509->subject.city) {
            utee_mem_free(x509->subject.city); 
        }
        if(x509->subject.user) {
            utee_mem_free(x509->subject.user); 
        }
        if(x509->subject.department) {
            utee_mem_free(x509->subject.department); 
        }
        if(x509->algor) {
            utee_mem_free(x509->algor); 
        }
        if(x509->public_key.type == IS_RSA_PUBKEY) {
            if(x509->public_key.pubkey.rsa_pubkey.E) {
                utee_mem_free(x509->public_key.pubkey.rsa_pubkey.E); 
            }
            if(x509->public_key.pubkey.rsa_pubkey.N) {
                utee_mem_free(x509->public_key.pubkey.rsa_pubkey.N); 
            }
        }
        if(x509->extensions.issuerUID) {
            utee_mem_free(x509->extensions.issuerUID); 
        }
        if(x509->extensions.subjectUID) {
            utee_mem_free(x509->extensions.subjectUID); 
        }
        if(x509->extensions.authKID) {
            utee_mem_free(x509->extensions.authKID); 
        }
        if(x509->extensions.subKID) {
            utee_mem_free(x509->extensions.subKID); 
        }
        if(x509->extensions.keyUSG) {
            utee_mem_free(x509->extensions.keyUSG); 
        }
        if(x509->extensions.subAltName) {
            utee_mem_free(x509->extensions.subAltName); 
        }
        if(x509->extensions.basicConstraints) {
            utee_mem_free(x509->extensions.basicConstraints); 
        }
        if(x509->extensions.extKUSG) {
            utee_mem_free(x509->extensions.extKUSG); 
        }
        if(x509->extensions.CRLDP) {
            utee_mem_free(x509->extensions.CRLDP); 
        }
        if(x509->extensions.alg) {
            utee_mem_free(x509->extensions.alg); 
        }
        if(x509->extensions.extk) {
            utee_mem_free(x509->extensions.extk); 
        }
        utee_mem_free(x509);
    }
}

static int chkItemLen(unsigned long *len,int *mark,int i)
{
    int j;
    for(j=0;j<i;j++) {
        if(mark[j]) {
            if(len[j] !=0) {
                return -1;
            }
        }
    }
    return 0;
}



static unsigned int readData(unsigned char **buf,unsigned char *temp,unsigned int fsize,int *cont)
{
    unsigned  int i = 1,rv = 0;
    if((unsure == 0xff) && fsize == 1) {
        while(1) {
            fsize++;
            (*cont)++;
            ((*buf)[rv]) = temp[*cont];
            rv++;
            if(temp[*cont]) {
                continue;
            }
            if(temp[*cont] == i) {
                fsize -= 2;
                break;
            }
            i = temp[*cont];
        }
        return fsize;
    }
    while(rv<fsize) {
        (*cont)++;
        ((*buf)[rv]) = temp[*cont];
        rv++;
    }
    return fsize;
}


static int isStruct(unsigned int rv)
{
    if(rv & 0x20) {
        return 1;
    }
    return 0;
}


static unsigned long getItemLen(unsigned char *temp,int *cont)
{
    unsigned long len = 0,tmp = 0;
    if(temp[*cont] == 0x80) {
        unsure = 0xff;
        return 0;
    }
    else if(temp[*cont] < 0x80) {
        unsure = 1;
        return temp[*cont];
    }
    else {
        temp[*cont] -=0x81;
        unsure = 2 + temp[*cont];
        if(temp[*cont]>0) {
            tmp=temp[*cont];
            for(;tmp>0;tmp--) {
                (*cont)++;
                len = len + temp[*cont];
                len = len * 256;
            }
        }
        (*cont)++;
        len = len + temp[*cont];
    }
    return len;
}


static int fillX509(X509_st* x509, unsigned char *buf,int fsize,int count)
{
    int tmp = 0;
    //TEE_Printf("fillX509:: count = %d\n",count);
    switch(count) {
        case 1:
            x509->version = buf[0];
            break;
        case 2:
            x509->serialNumber_len = fsize;
            x509->serialNumber = copyData(buf,fsize);
            break;
        case 3:
            x509->algorithm_len = fsize;
            x509->algorithm = copyData(buf,fsize);
            break;
        case 4:
            x509->issuer.email_len = fsize;
            x509->issuer.email = copyData(buf,fsize);
            break;
        case 5:
            x509->issuer.country_len = fsize;
            x509->issuer.country = copyData(buf,fsize);
            break;
        case 6:
            x509->issuer.province_len = fsize;
            x509->issuer.province = copyData(buf,fsize);
            break;
        case 7:
            x509->issuer.orgnization_len = fsize;
            x509->issuer.orgnization = copyData(buf,fsize);
            break;
        case 8:
            x509->issuer.city_len = fsize;
            x509->issuer.city = copyData(buf,fsize);
            break;
        case 9:
            x509->issuer.user_len = fsize;
            x509->issuer.user = copyData(buf,fsize);
            break;
        case 10:
            x509->issuer.department_len = fsize;
            x509->issuer.department = copyData(buf,fsize);
            break;
        case 11:
            x509->notBefore_len = fsize;
            x509->notBefore = copyData(buf,fsize);
            break;
        case 12:
            x509->notAfter_len = fsize;
            x509->notAfter = copyData(buf,fsize);
            break;
        case 13:
            x509->subject.email_len = fsize;
            x509->subject.email = copyData(buf,fsize);
            break;
        case 14:
            x509->subject.country_len = fsize;
            x509->subject.country = copyData(buf,fsize);
            break;
        case 15:
            x509->subject.province_len = fsize;
            x509->subject.province = copyData(buf,fsize);
            break;
        case 16:
            x509->subject.orgnization_len = fsize;
            x509->subject.orgnization = copyData(buf,fsize);
            break;
        case 17:
            x509->subject.city_len = fsize;
            x509->subject.city = copyData(buf,fsize);
            break;
        case 18:
            x509->subject.user_len = fsize;
            x509->subject.user = copyData(buf,fsize);
            break;
        case 19:
            x509->subject.department_len = fsize;
            x509->subject.department = copyData(buf,fsize);
            break;
        case 20:
            x509->algor_len = fsize;
            x509->algor = copyData(buf,fsize);
            break;
        case 21:
            // first bit indicates how many bits(0-7) unused in BIT STRING
            if(*(unsigned char*)buf == 0) {
                fsize = fsize - 1;
                buf += 1;
            }else {
                TEE_Printf("public-key's first byte indicates how many bits(0-7) unused in bits!");
            }
            if(*(unsigned char*)buf != 0x30) {
                errMsg("parse publick key error!");
            }
            // then buf point to the Sequence Struct contains public key 
            if(isRsaPubKey == 1) {
                buf++;
                x509->public_key.type = IS_RSA_PUBKEY;
                // parse and fill the RSA public key
                if(*(unsigned char*)buf <= 0x80) {
                    buf++;
                }else {
                    buf += (*(unsigned char*)buf - 0x80) + 1;
                }
                // parse rsa public key "N"
                if(*(unsigned char*)buf != 0x02) {
                    errMsg("parse rsa publickey \"N\" error!");
                }
                buf++;
                if(*(unsigned char*)buf <= 0x80) {
                    fsize = *(unsigned char*)buf;
                    buf++;
                }else {
                    tmp = *(unsigned char*)buf - 0x80;
                    buf++;
                    fsize = 0;
                    do{
                        tmp--;
                        fsize += *(unsigned char*)buf *(1 << ( 8 * tmp) );
                        buf++;
                    }while(tmp > 0);
                }
                x509->public_key.pubkey.rsa_pubkey.N_len = fsize;
                x509->public_key.pubkey.rsa_pubkey.N = copyData(buf, fsize);
                buf += fsize;

                // parse rsa public key "E"
                if(*(unsigned char*)buf != 0x02) {
                    errMsg("parse rsa publickey \"E\" error!");
                }
                buf++;
                if(*(unsigned char*)buf <= 0x80) {
                    fsize = *(unsigned char*)buf;
                    buf++;
                }else {
                    tmp = *(unsigned char*)buf - 0x80;
                    buf++;
                    fsize = 0;
                    do{
                        tmp--;
                        fsize += *(unsigned char*)buf *(1 << ( 8 * tmp) );
                        buf++;
                    }while(tmp > 0);
                }
                x509->public_key.pubkey.rsa_pubkey.E_len = fsize;
                x509->public_key.pubkey.rsa_pubkey.E = copyData(buf, fsize);
                buf += fsize;
            }else {
                x509->public_key.pubkey.o.len  = fsize;
                x509->public_key.pubkey.o.data = copyData(buf, fsize);
            }
            break;
        // extensions
        case 22:
            x509->extensions.issuerUID_len = fsize;
            x509->extensions.issuerUID = copyData(buf,fsize);
            break;
        case 23:
            x509->extensions.subjectUID_len = fsize;
            x509->extensions.subjectUID = copyData(buf,fsize);
            break;
        case 24:
            x509->extensions.authKID_len = fsize;
            x509->extensions.authKID = copyData(buf,fsize);
            break;
        case 25:
            x509->extensions.subKID_len = fsize;
            x509->extensions.subKID = copyData(buf,fsize);
            break;
        case 26:
            x509->extensions.keyUSG_len = fsize;
            x509->extensions.keyUSG = copyData(buf,fsize);
            break;
        case 27:
            x509->extensions.subAltName_len = fsize;
            x509->extensions.subAltName = copyData(buf,fsize);
            break;
        case 28:
            x509->extensions.basicConstraints_len = fsize;
            x509->extensions.basicConstraints = copyData(buf,fsize);
            break;
        case 29:
            x509->extensions.extKUSG_len = fsize;
            x509->extensions.extKUSG = copyData(buf,fsize);
            break;
        case 30:
            x509->extensions.CRLDP_len = fsize;
            x509->extensions.CRLDP = copyData(buf,fsize);
            break;
        case 31:
            x509->extensions.alg_len = fsize;
            x509->extensions.alg = copyData(buf,fsize);
            break;
        case 32:
            x509->extensions.extk_len = fsize;
            x509->extensions.extk = copyData(buf,fsize);
            break;
        case 33:
            // first bit indicates how many bits(0-7) unused in BIT STRING
            if(*(unsigned char*)buf == 0) {
                fsize = fsize - 1;
                buf += 1;
            }else {
                TEE_Printf("signature's first byte indicates how many bits(0-7) unused in bits!");
            }
            x509->signature_len = fsize;
            x509->signature = copyData(buf,fsize);
            break;
        case 0:
            break;
        default:
            errMsg("fillX509 error!");
            return 0;
    }
    return 1;
}


static void errMsg(char *err)
{
    TEE_Printf("[err] %s \n",err);
    exit(-1);
}

static int getOID(unsigned char *buf,int len)
{
    unsigned char *hex_buf = NULL;
    int hex_size = 0 ;
    int OID = 0;

    //TEE_Hexdump(">>>>>>>>>>>>>>>>>getOID::buf<<<<<<<<<<<<<",(void*)buf, len, 16, 1);

    // public key
    hex_size = oid2hex(OID_rsaEncryption, sizeof(OID_rsaEncryption)/ sizeof(OID_rsaEncryption[0]), &hex_buf);
    if(hex_size > 0) {
        if(!utee_mem_cmp(buf, hex_buf,hex_size)) {
            OID =  IS_OID_rsaEnc;
            isRsaPubKey = 1;
            goto out;
        }
    }
    // signature algorithm
    hex_size = oid2hex(OID_md5withRSAEncryption, sizeof(OID_md5withRSAEncryption)/ sizeof(OID_md5withRSAEncryption[0]), &hex_buf);
    if(hex_size > 0) {
        if(!utee_mem_cmp(buf, hex_buf,hex_size)) {
            OID =  IS_OID_md5withRSAEnc;
            goto out;
        }
    }
    hex_size = oid2hex(OID_sha256withRSAEncryption, sizeof(OID_sha256withRSAEncryption)/ sizeof(OID_sha256withRSAEncryption[0]), &hex_buf);
    if(hex_size > 0) {
        if(!utee_mem_cmp(buf, hex_buf,hex_size)) {
            OID =  IS_OID_sha256withRSAEnc;
            goto out;
        }
    }
    hex_size = oid2hex(OID_sha512withRSAEncryption, sizeof(OID_sha512withRSAEncryption)/ sizeof(OID_sha512withRSAEncryption[0]), &hex_buf);
    if(hex_size > 0) {
        if(!utee_mem_cmp(buf, hex_buf,hex_size)) {
            OID =  IS_OID_sha512withRSAEnc;
            goto out;
        }
    }
    hex_size = oid2hex(OID_extKeyUsage, sizeof(OID_extKeyUsage)/ sizeof(OID_extKeyUsage[0]), &hex_buf);
    if(hex_size > 0) {
        if(!utee_mem_cmp(buf, hex_buf,hex_size)) {
            OID =  IS_OID_extKeyUsage;
            goto out;
        }
    }
    hex_size = oid2hex(OID_CRLDP, sizeof(OID_CRLDP)/ sizeof(OID_CRLDP[0]), &hex_buf);
    if(hex_size > 0) {
        if(!utee_mem_cmp(buf, hex_buf,hex_size)) {
            OID =  IS_OID_CRLDP;
            goto out;
        }
    }
    hex_size = oid2hex(OID_basicCon, sizeof(OID_basicCon)/ sizeof(OID_basicCon[0]), &hex_buf);
    if(hex_size > 0) {
        if(!utee_mem_cmp(buf, hex_buf,hex_size)) {
            OID =  IS_OID_basicCon;
            goto out;
        }
    }
    hex_size = oid2hex(OID_subaltname, sizeof(OID_subaltname)/ sizeof(OID_subaltname[0]), &hex_buf);
    if(hex_size > 0) {
        if(!utee_mem_cmp(buf, hex_buf,hex_size)) {
            OID =  IS_OID_subaltname;
            goto out;
        }
    }
    hex_size = oid2hex(OID_authKID, sizeof(OID_authKID)/ sizeof(OID_authKID[0]), &hex_buf);
    if(hex_size > 0) {
        if(!utee_mem_cmp(buf, hex_buf,hex_size)) {
            OID =  IS_OID_authKID;
            goto out;
        }
    }
    hex_size = oid2hex(OID_keyUsage, sizeof(OID_keyUsage)/ sizeof(OID_keyUsage[0]), &hex_buf);
    if(hex_size > 0) {
        if(!utee_mem_cmp(buf, hex_buf,hex_size)) {
            OID =  IS_OID_keyUsage;
            goto out;
        }
    }
    hex_size = oid2hex(OID_subKID, sizeof(OID_subKID)/ sizeof(OID_subKID[0]), &hex_buf);
    if(hex_size > 0) {
        if(!utee_mem_cmp(buf, hex_buf,hex_size)) {
            OID =  IS_OID_subKID;
            goto out;
        }
    }
    hex_size = oid2hex(OID_email, sizeof(OID_email)/ sizeof(OID_email[0]), &hex_buf);
    if(hex_size > 0) {
        if(!utee_mem_cmp(buf, hex_buf,hex_size)) {
            OID =  IS_OID_email;
            goto out;
        }
    }
    hex_size = oid2hex(OID_city, sizeof(OID_city)/ sizeof(OID_city[0]), &hex_buf);
    if(hex_size > 0) {
        if(!utee_mem_cmp(buf, hex_buf,hex_size)) {
            OID =  IS_OID_city;
            goto out;
        }
    }
    hex_size = oid2hex(OID_orgnization, sizeof(OID_orgnization)/ sizeof(OID_orgnization[0]), &hex_buf);
    if(hex_size > 0) {
        if(!utee_mem_cmp(buf, hex_buf,hex_size)) {
            OID =  IS_OID_orgnization;
            goto out;
        }
    }
    hex_size = oid2hex(OID_country, sizeof(OID_country)/ sizeof(OID_country[0]), &hex_buf);
    if(hex_size > 0) {
        if(!utee_mem_cmp(buf, hex_buf,hex_size)) {
            OID =  IS_OID_country;
            goto out;
        }
    }
    hex_size = oid2hex(OID_province, sizeof(OID_province)/ sizeof(OID_province[0]), &hex_buf);
    if(hex_size > 0) {
        if(!utee_mem_cmp(buf, hex_buf,hex_size)) {
            OID =  IS_OID_province;
            goto out;
        }
    }
    hex_size = oid2hex(OID_department, sizeof(OID_department)/ sizeof(OID_department[0]), &hex_buf);
    if(hex_size > 0) {
        if(!utee_mem_cmp(buf, hex_buf,hex_size)) {
            OID =  IS_OID_department;
            goto out;
        }
    }
    hex_size = oid2hex(OID_user, sizeof(OID_user)/ sizeof(OID_user[0]), &hex_buf);
    if(hex_size > 0) {
        if(!utee_mem_cmp(buf, hex_buf,hex_size)) {
            OID =  IS_OID_user;
            goto out;
        }
    }
    TEE_Printf("unknown OID: %x\n",*buf);
    OID = 0;

out:
    if(hex_buf) {
        utee_mem_free(hex_buf);
        hex_buf = NULL;
    }

    return OID;
}


static int setCount(unsigned char rv, unsigned char *expect, int *expnum, int *steps, int isoid, int count, int *bak)
{
    if(expect[*expnum] == rv) {
        (*expnum)++;
        count++;
        return count;
    }
    if((rv == 0x17)&&((*steps)==0)) {
        (*steps)++;
        (*expnum)+=2;
        return 11;
    }
    if((rv == 0x06) && (isoid == 0) && ((*steps) == 1)) {
        (*steps)++;
        (*expnum)+=2;
        return 20;
    }
    if((rv == 0x06) && (isoid == 0) && ((*steps) == 2)) {
        (*steps)++;
        //(*expnum)++;
        return 31;
    }

    if(expect[*expnum] == 0x7f) {
        switch(isoid) {
            case IS_OID_email:
                count = (*steps)?13:4;
                break;
            case IS_OID_country:
                count = (*steps)?14:5;
                break;
            case IS_OID_province:
                count = (*steps)?15:6;
                break;
            case IS_OID_orgnization:
                count = (*steps)?16:7;
                break;
            case IS_OID_city:
                count = (*steps)?17:8;
                break;
            case IS_OID_user:
                count = (*steps)?18:9;
                break;
            case IS_OID_department:
                count = (*steps)?19:10;
                break;
            case IS_OID_rsaEnc:
                count = 21;
                break;
            case IS_OID_authKID:
                count = 24;
                break;
            case IS_OID_subKID:
                count = 25;
                break;
            case IS_OID_subaltname:
                count = 27;
                break;
            case IS_OID_keyUsage:
                count = 26;
                break;
            case IS_OID_basicCon:
                count = 28;
                break;
            case IS_OID_extKeyUsage:
                count = 29;
                break;
            case IS_OID_CRLDP:
                count = 30;
                break;
            case IS_OID_md5withRSAEnc:
            case IS_OID_sha256withRSAEnc:
            case IS_OID_sha512withRSAEnc:
                count = 33;
                break;
            case 0:
                return (*bak);
            default:
                TEE_Printf("!!!!!!!!!!!!error!!!!!!!!!!!!\n");
                break;
        }
        (*bak) = count;
        return 0;
    }

    TEE_Printf("error in %d line!!! count is :%d  expect[%d] = %x rv = %x\n",__LINE__,count,*expnum,expect[*expnum],rv);
    return 0;
}


static unsigned char *copyData(unsigned char *buf, int len)
{
    unsigned char *temp;
    if((temp=(unsigned char*)utee_mem_alloc(len)) == NULL) {
        errMsg("copyData error!");        
    }
    utee_mem_copy(temp,buf,len);
    return temp;
}


static int oid2hex(unsigned int *oid, int oid_bytes, unsigned char **hex_buf) {

    int i, j;
    int buf_size = 0;
    unsigned int tmp;
    unsigned int r;
    int round;
    unsigned char *p = NULL;
    int * round_arry = NULL;

    if(!oid ) {
        goto out;
    }

    if(oid_bytes < 2 || oid[oid_bytes-1] == 0) {
        goto out;
    }

    round_arry = (int*)utee_mem_alloc(oid_bytes * sizeof(int));
    if(!round_arry) {
        goto out;
    }
    utee_mem_fill(round_arry, oid_bytes * sizeof(int), 0);

    buf_size = 1;

    for(i = 2; i < oid_bytes; i++) {
        round = 0;
        tmp = oid[i];
        do{
            r = tmp%128;
            tmp = tmp/128;
            round += 1;
        }while( tmp != 0);
        buf_size += round;
        round_arry[i] = round;
    }

    p = (unsigned char *)utee_mem_alloc(buf_size);
    if(!p) {
        goto out;
    }
    utee_mem_fill(p, 0, buf_size);

    p[0] = 40 * oid[0] + oid[1];
    j = 1;
    for(i = 2; i < oid_bytes; i++) {
        tmp = oid[i];
        round = 0;
        do{
            r = tmp%128;
            tmp = tmp/128;
            r = round == 0 ? r : (r|0x80) ;
            p[ j + (round_arry[i] - round) - 1 ] = r;
            round += 1;
        }while( tmp != 0);
        j += round;
    }

    *hex_buf = p;
    p = NULL;

 out:
    if(round_arry) {
        utee_mem_free(round_arry);
    }

    return buf_size;
}

