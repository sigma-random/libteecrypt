#include <tee_api.h>
#include <utee_api.h>
#include <utee_mem.h>
 
#include "teecrypt_api.h"
 
/* #######################  Customized API  ######################*/


extern int isprintable(int c);


TEE_Result TEE_Hexdump(char *title, unsigned char *data, uint32_t size, uint32_t linenum, bool isUp)
{
	TEE_Result res;
    res = utee_mem_hexdump(title, data, size, linenum, isUp);
	if(res != TEE_SUCCESS) {
		_PANIC_LOG_(res);
		TEE_Panic(res);
	}
    return res;
}



/*
typedef struct mpa_numbase_struct {
	mpa_asize_t alloc;
	mpa_usize_t size;
	mpa_word_t d[];
} mpa_num_base;
*/
TEE_Result TEE_HexdumpBigInt(char *title, TEE_BigInt *bn, uint32_t bn_size, uint32_t linenum, bool isRawData)
{
	TEE_Result res;
	
	if(!title || !bn) {
		return TEE_ERROR_BAD_PARAMETERS;
	}

	mpanum mpa_bn = (mpa_num_base *)bn;
	int32_t meta_data_size = sizeof(mpa_bn->alloc) + sizeof(mpa_bn->size);

	bool isUp;

	if(isRawData) {
		isUp = true;
	    res = utee_mem_hexdump(title, (void*)mpa_bn, (mpa_bn->size * sizeof(mpa_bn->d[0])) + meta_data_size, linenum, isUp);
	}else {
		isUp = false;
	    res = utee_mem_hexdump(title, (void*)mpa_bn + meta_data_size, (mpa_bn->size * sizeof(mpa_bn->d[0])), linenum, isUp);		
	}
	if(res != TEE_SUCCESS) {
		_PANIC_LOG_(res);
		TEE_Panic(res);
	}
    return res;
}



/* Cryption Context Operation Funcs */
TEE_Result TEE_InitCryptContext()
{
	TEE_Result res;
    res = tee_init_crypt_ctx();
	if(res != TEE_SUCCESS) {
		_PANIC_LOG_(res);
		TEE_Panic(res);
	}
    return res;
}


TEE_Result TEE_FiniCryptContext()
{
	TEE_Result res;
    res = tee_fini_crypt_ctx();
	if(res != TEE_SUCCESS) {
		_PANIC_LOG_(res);
		TEE_Panic(res);
	}
    return res;
}




TEE_Result TEE_NewRandomKeyObject(TEE_ObjectType keyObjectType, uint32_t maxKeyObjectSize, 
							TEE_ObjectHandle *hKeyObject)
{
	TEE_Result res = TEE_ERROR_GENERIC;
	uint32_t attributeID;
	TEE_Attribute attr;

	res = TEE_AllocateTransientObject( keyObjectType, maxKeyObjectSize, hKeyObject);
	if(res != TEE_SUCCESS) {
		utee_printf("[err] TEE_AllocateTransientObject\n");
		goto _ret_;
	}
	/*
	TEE_MemFill(&attr, sizeof(attr), 0);
	TEE_InitRefAttribute(&attr, attributeID, NULL, 0 );
	*/
	res = TEE_GenerateKey(*hKeyObject, maxKeyObjectSize, NULL, 0);
	if(res != TEE_SUCCESS) {
		utee_printf("[err] TEE_GenerateKey\n");
		_PANIC_LOG_(res);
		goto _ret_;
	}

_ret_:

	if(res != TEE_SUCCESS) {
		if(*hKeyObject) {
			TEE_FreeTransientObject(*hKeyObject);
		}

	}

	return res;
}


TEE_Result TEE_DumpRSAKeyObj(TEE_ObjectHandle hKeyObject, uint32_t rsaKeyBits, 
				bool isRsaKeyPair, uint32_t rawdata)
{

	return utee_dump_ltc_rsa_key_obj((uint32_t)hKeyObject, rsaKeyBits, isRsaKeyPair, rawdata);

}


TEE_Result TEE_LoadX509Cert(char *filename, X509_st **pX509)
{
	TEE_Result res;

	*pX509 = loadX509Cert(filename);
	if(*pX509 == NULL) {
		res = TEE_ERROR_GENERIC;
	}else {
		res = TEE_SUCCESS;
	}
    return res;
}

TEE_Result TEE_FreeX509Cert(X509_st *x509)
{
	TEE_Result res;
	if(x509) {
		freeX509Cert(x509);
	}
    return TEE_SUCCESS;
}



/*
TEE_Result TEE_SetRsaKeyObjectValue(TEE_ObjectHandle hKeyObject,  uint32_t rsaKeyBits, 
								void *e_data, size_t e_bytes, void *n_data, size_t n_bytes, 
								bool isRsaKeyPair)
{

	return	utee_obj_set_key_rsa((uint32_t)hKeyObject, rsaKeyBits, 
								e_data, e_bytes, n_data, n_bytes, isRsaKeyPair);

}


TEE_Result TEE_NewRsaKeyObject(TEE_ObjectType keyObjectType, uint32_t rsaKeyBits, 
							void *e_data, size_t e_bytes, void *n_data, size_t n_bytes, 
							TEE_ObjectHandle *hKeyObject)
{
	TEE_Result res = TEE_ERROR_GENERIC;
	uint32_t maxRsaKeyObjectSize = 2048;
	uint32_t attributeID;
	TEE_Attribute attr;

	if( keyObjectType != TEE_TYPE_RSA_KEYPAIR && keyObjectType != TEE_TYPE_RSA_PUBLIC_KEY) {
		res = TEE_ERROR_BAD_PARAMETERS;
		_PANIC_LOG_(res);
		goto _ret_;
	}
	res = TEE_AllocateTransientObject( keyObjectType, maxRsaKeyObjectSize, hKeyObject);
	if(res != TEE_SUCCESS) {
		utee_printf("[err] TEE_AllocateTransientObject\n");
		goto _ret_;
	}

	res = utee_obj_set_key_rsa((uint32_t)*hKeyObject, rsaKeyBits, 
								e_data, e_bytes, n_data, n_bytes, 
								keyObjectType == TEE_TYPE_RSA_KEYPAIR ? true:false);
	if(res != TEE_SUCCESS) {
		utee_printf("[err] utee_obj_set_key_rsa\n");
		_PANIC_LOG_(res);
		TEE_Panic(res);
		goto _ret_;
	}

_ret_:

	if(res != TEE_SUCCESS) {
		if(*hKeyObject) {
			TEE_FreeTransientObject(*hKeyObject);
		}

	}

	return res;
}

*/


/*****************************************************************************************************/


void *utee_mem_alloc(size_t len)
{
	uint8_t *p = NULL;
	p = tee_malloc(len);
	if (p == NULL)
		return NULL;
	tee_memset(p, 0, len);
	return p;
}

	
void *utee_mem_calloc(size_t nmemb, size_t size)
{
	uint8_t *p = NULL;
	p = tee_malloc(nmemb * size);
	if (p == NULL)
		return NULL;
	tee_memset(p, 0, nmemb * size);
	return p;
}


void *utee_mem_realloc(void *buffer, size_t len)
{
	return tee_realloc(buffer, len);
}


void utee_mem_free(void *buffer)
{
	if( buffer != NULL ) {
		tee_free(buffer);		
	}
}


void *utee_mem_move(void *dest, const void *src, uint32_t size)
{
	return tee_memmove(dest, src, size);
}

void *utee_mem_copy(void *dest, const void *src, uint32_t size)
{
	return tee_memcpy(dest, src, size);	
}


int32_t utee_mem_cmp(const void *buffer1, const void *buffer2, uint32_t size)
{
	return tee_memcmp(buffer1, buffer2, size);
}

void *utee_mem_fill(void *buff, uint32_t x, uint32_t size)
{
	return tee_memset(buff, x, size);
}


/* copy data from client space to ta space */
TEE_Result utee_copy_to_user(void *sess, void *uaddr, const void *kaddr, size_t len)
{
	TEE_Result res;
	/* memory checking */
	// TODO...
    tee_memcpy(uaddr, kaddr, len);
    return TEE_SUCCESS;
}

/* copy data from ta space to client space */
TEE_Result utee_copy_from_user(void *sess, void *kaddr, const void *uaddr, size_t len)
{
	TEE_Result res;
	/* memory checking */
	// TODO...
	//
	tee_memcpy(kaddr, uaddr, len);
	return TEE_SUCCESS;
}

 

TEE_Result utee_mem_hexdump(char *title, unsigned char *data, uint32_t size, uint32_t linenum, bool isUp)
{
    uint32_t line;
    uint32_t i, j, count;

    if( size <= 0 ) {
    	return TEE_SUCCESS;
    }

    if (NULL == title || NULL == data) {
        return TEE_ERROR_BAD_PARAMETERS;        
    }

    if( linenum <= 0 || linenum > 16) {
        linenum = 16;
    }
    if(0 == size) {
        utee_printf("[info] no data to dump!\n");
        return TEE_SUCCESS;
    }
    line = 0;
    count = 0;
    i = 0;
    if(isUp) {
        i = 0;
    }else {
        i = size - 1;
    }
    while(true) {
        while(0 == count % linenum) {
            if(0 == count) {
                utee_printf("\n<%s>\n", title);
                utee_printf("%08x\t",line);
                break;   
            }
            line += linenum;
            utee_printf("\t|");
            for(j=linenum; j>0; j--){
            	utee_printf("%c",isprintable(data[count-j])?data[count-j]:'.');
            }
            utee_printf("|");
            utee_printf("\n%08x\t",line);  
            break;    
        } 
        utee_printf("%02x ", *(data+i));
        count++;
        if( isUp && ((++i) == size) ) {
            break;
        }
        if( !isUp && ((i--) == 0) ){
            break;
        }                    
    }

    if( 1 ) {
    	i = size % linenum == 0 ? linenum : size % linenum;
    	for(j = linenum - i; j>0; j--){
    		utee_printf("   ");    		
    	}
    	utee_printf("\t|");
        for(j=i; j>0; j--){
        	utee_printf("%c",isprintable(data[count-j])?data[count-j]:'.');
        }
    	for(j = linenum - i; j>0; j--){
    		utee_printf(" "); 		
    	}
        utee_printf("|");      	
    } 
    utee_printf("\n%08x\n",line + linenum); 

    return TEE_SUCCESS;
}



static const char base64_table[] =
	"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

bool base64_enc(const void *data, size_t dlen, char *buf, size_t *blen)
{
	size_t n;
	size_t boffs = 0;
	const char *d = data;

	n = 4 * ((dlen + 2) / 3) + sizeof('\0');
	if (*blen < n) {
		*blen = n;
		return false;
	}

	for (n = 0; n < dlen; n += 3) {
		uint32_t igrp;

		igrp = d[n];
		igrp <<= 8;

		if ((n + 1) < dlen)
			igrp |= d[n + 1];
		igrp <<= 8;

		if ((n + 2) < dlen)
			igrp |= d[n + 2];

		buf[boffs] = base64_table[(igrp >> 18) & 0x3f];
		buf[boffs + 1] = base64_table[(igrp >> 12) & 0x3f];
		if ((n + 1) < dlen)
			buf[boffs + 2] = base64_table[(igrp >> 6) & 0x3f];
		else
			buf[boffs + 2] = '=';
		if ((n + 2) < dlen)
			buf[boffs + 3] = base64_table[igrp & 0x3f];
		else
			buf[boffs + 3] = '=';

		boffs += 4;
	}
	buf[boffs++] = '\0';

	*blen = boffs;
	return true;
}

static bool get_idx(char ch, uint8_t *idx)
{
	size_t n;

	for (n = 0; base64_table[n] != '\0'; n++) {
		if (ch == base64_table[n]) {
			*idx = n;
			return true;
		}
	}
	return false;
}

bool base64_dec(const char *data, size_t size, void *buf, size_t *blen)
{
	size_t n;
	uint8_t idx;
	uint8_t *b = buf;
	size_t m = 0;
	size_t s = 0;

	for (n = 0; n < size && data[n] != '\0'; n++) {
		if (data[n] == '=')
			break;	/* Reached pad characters, we're done */

		if (!get_idx(data[n], &idx))
			continue;

		if (m > *blen)
			b = NULL;

		switch (s) {
		case 0:
			if (b)
				b[m] = idx << 2;
			s++;
			break;
		case 1:
			if (b)
				b[m] |= idx >> 4;
			m++;
			if (m > *blen)
				b = NULL;
			if (b)
				b[m] = (idx & 0xf) << 4;
			s++;
			break;
		case 2:
			if (b)
				b[m] |= idx >> 2;
			m++;
			if (m > *blen)
				b = NULL;
			if (b)
				b[m] = (idx & 0x3) << 6;
			s++;
			break;
		case 3:
			if (b)
				b[m] |= idx;
			m++;
			s = 0;
			break;
		default:
			return false;	/* "Can't happen" */
		}
	}
	/* We don't detect if input was bad, but that's OK with the spec. */
	*blen = m;
	if (b)
		return true;
	else
		return false;
}

