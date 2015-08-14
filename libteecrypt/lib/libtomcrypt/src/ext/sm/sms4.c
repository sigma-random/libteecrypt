#include "tomcrypt_sm.h"


#define ROL(x,y)		((x)<<(y) | (x)>>(32-(y)))								// Ñ­»·ÒÆÎ»
//#define SMS4_8TO32(x) 	(((*x)<<24) | ((*(x+1))<<16) | ((*(x+2))<<8) | *(x+3))	// 8Î»µ½32Î»×ª»»

// transform 4 Bytes into INT32 (Big-Endian)
static T_U32 SMS4_8TO32(T_U8 *data) 
{
	return	(T_U32)(((*data)<<24) | ((*(data+1))<<16) | ((*(data+2))<<8) | *(data+3));

}
static T_U32 _SMS4_8TO32(T_U8 *data) 
{
	T_U32 word;
	T_U32 tmp = 0x11223344;

	if( *((T_U8*)&tmp) == (tmp>>24) ) { // Big-Endian
		printf(">>>>>>>>>>>>>>>>>> Big-Endian <<<<<<<<<<<<<<<<\n");
		word = (T_U32)(((*data)<<24) | ((*(data+1))<<16) | ((*(data+2))<<8) | *(data+3));

	}else { // Little-Endian
		printf(">>>>>>>>>>>>>>>>>> Little-Endian <<<<<<<<<<<<<<<<\n");
		word = (T_U32)(((*data+3)<<24) | ((*(data+2))<<16) | ((*(data+1))<<8) | *(data));
	}

	return word;
}

// transform INT32 into 4 Bytes (Big-Endian) 
static T_U32 SMS4_32TO8(T_U32 *data) 
{
	// transforming INT32 into Big-Endian, if target arch only support Little-Endian!
	if( SMS4_8TO32((T_U8*)data) != (*data) ) {
		*((T_U8*)data+0) ^= *((T_U8*)data+3);
		*((T_U8*)data+3) ^= *((T_U8*)data+0);
		*((T_U8*)data+0) ^= *((T_U8*)data+3);

		*((T_U8*)data+1) ^= *((T_U8*)data+2);
		*((T_U8*)data+2) ^= *((T_U8*)data+1);
		*((T_U8*)data+1) ^= *((T_U8*)data+2);	
	}
	return *data;
}



static T_U32 FK[4]={
    0xA3B1BAC6,0x56AA3350,0x677D9197,0xB27022DC
};

static T_U32 CK[SMS4_ROUND]={
    0x00070e15, 0x1c232a31, 0x383f464d, 0x545b6269,
    0x70777e85, 0x8c939aa1, 0xa8afb6bd, 0xc4cbd2d9,
    0xe0e7eef5, 0xfc030a11, 0x181f262d, 0x343b4249,
    0x50575e65, 0x6c737a81, 0x888f969d, 0xa4abb2b9,
    0xc0c7ced5, 0xdce3eaf1, 0xf8ff060d, 0x141b2229,
    0x30373e45, 0x4c535a61, 0x686f767d, 0x848b9299,
    0xa0a7aeb5, 0xbcc3cad1, 0xd8dfe6ed, 0xf4fb0209,
    0x10171e25, 0x2c333a41, 0x484f565d, 0x646b7279
};

static T_U8 Sbox[256]={
    0xd6,0x90,0xe9,0xfe,0xcc,0xe1,0x3d,0xb7,0x16,0xb6,0x14,0xc2,0x28,0xfb,0x2c,0x05,
    0x2b,0x67,0x9a,0x76,0x2a,0xbe,0x04,0xc3,0xaa,0x44,0x13,0x26,0x49,0x86,0x06,0x99,
    0x9c,0x42,0x50,0xf4,0x91,0xef,0x98,0x7a,0x33,0x54,0x0b,0x43,0xed,0xcf,0xac,0x62,
    0xe4,0xb3,0x1c,0xa9,0xc9,0x08,0xe8,0x95,0x80,0xdf,0x94,0xfa,0x75,0x8f,0x3f,0xa6,
    0x47,0x07,0xa7,0xfc,0xf3,0x73,0x17,0xba,0x83,0x59,0x3c,0x19,0xe6,0x85,0x4f,0xa8,
    0x68,0x6b,0x81,0xb2,0x71,0x64,0xda,0x8b,0xf8,0xeb,0x0f,0x4b,0x70,0x56,0x9d,0x35,
    0x1e,0x24,0x0e,0x5e,0x63,0x58,0xd1,0xa2,0x25,0x22,0x7c,0x3b,0x01,0x21,0x78,0x87,
    0xd4,0x00,0x46,0x57,0x9f,0xd3,0x27,0x52,0x4c,0x36,0x02,0xe7,0xa0,0xc4,0xc8,0x9e,
    0xea,0xbf,0x8a,0xd2,0x40,0xc7,0x38,0xb5,0xa3,0xf7,0xf2,0xce,0xf9,0x61,0x15,0xa1,
    0xe0,0xae,0x5d,0xa4,0x9b,0x34,0x1a,0x55,0xad,0x93,0x32,0x30,0xf5,0x8c,0xb1,0xe3,
    0x1d,0xf6,0xe2,0x2e,0x82,0x66,0xca,0x60,0xc0,0x29,0x23,0xab,0x0d,0x53,0x4e,0x6f,
    0xd5,0xdb,0x37,0x45,0xde,0xfd,0x8e,0x2f,0x03,0xff,0x6a,0x72,0x6d,0x6c,0x5b,0x51,
    0x8d,0x1b,0xaf,0x92,0xbb,0xdd,0xbc,0x7f,0x11,0xd9,0x5c,0x41,0x1f,0x10,0x5a,0xd8,
    0x0a,0xc1,0x31,0x88,0xa5,0xcd,0x7b,0xbd,0x2d,0x74,0xd0,0x12,0xb8,0xe5,0xb4,0xb0,
    0x89,0x69,0x97,0x4a,0x0c,0x96,0x77,0x7e,0x65,0xb9,0xf1,0x09,0xc5,0x6e,0xc6,0x84,
    0x18,0xf0,0x7d,0xec,0x3a,0xdc,0x4d,0x20,0x79,0xee,0x5f,0x3e,0xd7,0xcb,0x39,0x48
};


// ¼Ó½âÃÜÖÐµÄT±ä»»
T_U32 T1(T_U32 ulA)
{
    T_U32 ulB, ulC;	// ulB±£´æ·ÇÏßÐÔ½á¹û£¬ulC±£´æºÏ³É½á¹û
	
	ulB = Sbox[(T_U8)ulA] | 
		(Sbox[(T_U8)(ulA >> 8)] << 8) | 
		(Sbox[(T_U8)(ulA >> 16)] << 16) | 
		(Sbox[(T_U8)(ulA >> 24)] << 24);
		
    ulC = ulB ^ ROL(ulB,2) ^ ROL(ulB,10) ^ ROL(ulB,18) ^ ROL(ulB,24);

	return ulC;
}

// ÃÜÔ¿À©Õ¹ÖÐµÄT¡®±ä»»
T_U32 T2(T_U32 ulA)
{
    T_U32 ulB, ulC;

	ulB = Sbox[(T_U8)ulA] | 
		(Sbox[(T_U8)(ulA >> 8)] << 8) | 
		(Sbox[(T_U8)(ulA >> 16)] << 16) | 
		(Sbox[(T_U8)(ulA >> 24)] << 24);
	
    ulC = ulB ^ ROL(ulB,13) ^ ROL(ulB,23);

	return ulC;
}

// ÃÜÔ¿À©Õ¹º¯Êý
T_U16 SMS4KeyExpansion(T_U8* pKey, T_U32* pRK)
{
    T_U32 ulMK[4], ulK[36];
    T_U8 bCycleCount = 0;

    for (bCycleCount = 0; bCycleCount < 4; bCycleCount++)
    {
		ulMK[bCycleCount] = SMS4_8TO32(&pKey[bCycleCount*4]);
        ulK[bCycleCount] = ulMK[bCycleCount] ^ FK[bCycleCount];
    }

    for (bCycleCount = 0; bCycleCount < SMS4_ROUND; bCycleCount++)
    {
		ulK[bCycleCount+4] = ulK[bCycleCount] ^ 
						T2(ulK[bCycleCount+1] ^ ulK[bCycleCount+2] ^ ulK[bCycleCount+3] ^ CK[bCycleCount]);
        pRK[bCycleCount] = ulK[bCycleCount+4];
    }
    
    return SMS4_NO_ERR;
}

// ¼ÓÃÜº¯Êý
T_U16 SMS4EncryptECB(T_U8* pKey, T_U8* pInData, T_U16 wInDataLen, T_U8* pOutData)
{
	T_U32 ulRK[SMS4_ROUND], ulTemp[36], ulTempOutData[4];
	T_U16 wBlockNum = 0, wCycleI = 0, wCycleJ = 0;
	
	if(!pKey || !pInData || !pOutData)
	{
		return SMS4_PARAM_ERROR;
	}
	
	if(0 != wInDataLen % SMS4_BLOCK_LEN)
	{
		return SMS4_DATA_LEN_ERROR;
	}
	
	// ÃÜÔ¿À©Õ¹
    SMS4KeyExpansion(pKey, ulRK);

	wBlockNum = wInDataLen / SMS4_BLOCK_LEN;
	for(wCycleI = 0; wCycleI < wBlockNum; wCycleI++)
	{
		for(wCycleJ = 0; wCycleJ < 4; wCycleJ++)
		{
			ulTemp[wCycleJ] = SMS4_8TO32(&pInData[wCycleI*SMS4_BLOCK_LEN + wCycleJ*4]);
		}
		
		for(wCycleJ = 0; wCycleJ < SMS4_ROUND; wCycleJ++)
		{
			ulTemp[wCycleJ+4] = ulTemp[wCycleJ] ^ 
							T1(ulTemp[wCycleJ+1] ^ ulTemp[wCycleJ+2] ^ ulTemp[wCycleJ+3] ^ ulRK[wCycleJ]);
		}
		
		for (wCycleJ = 0; wCycleJ < 4; wCycleJ++)
		{
			ulTempOutData[wCycleJ] = ulTemp[35-wCycleJ];
			ulTempOutData[wCycleJ] = SMS4_32TO8( &ulTemp[35-wCycleJ] );
		}
		
		tomcrypt_memcpy(pOutData + (wCycleI * SMS4_BLOCK_LEN), ulTempOutData, SMS4_BLOCK_LEN);
	}
	return SMS4_NO_ERR;
}

// ½âÃÜº¯Êý
T_U16 SMS4DecryptECB(T_U8* pKey, T_U8* pInData, T_U16 wInDataLen, T_U8* pOutData)
{
	T_U32 ulRK[SMS4_ROUND], ulTemp[36], ulTempOutData[4];
	T_U32 ulBlockNum = 0, ulCycleI = 0, ulCycleJ = 0;
	
	if(!pKey || !pInData || !pOutData)
	{
		return SMS4_PARAM_ERROR;
	}
	
	if(wInDataLen % SMS4_BLOCK_LEN)
	{
		return SMS4_DATA_LEN_ERROR;
	}
	
	// ÃÜÔ¿À©Õ¹
    SMS4KeyExpansion(pKey, ulRK);
	
	ulBlockNum = wInDataLen / SMS4_BLOCK_LEN;

	for(ulCycleI = 0; ulCycleI < ulBlockNum; ulCycleI++)
	{
		for(ulCycleJ = 0; ulCycleJ < 4; ulCycleJ++)
			ulTemp[ulCycleJ] = SMS4_8TO32(&pInData[ulCycleI*SMS4_BLOCK_LEN + ulCycleJ*4]);
		
		for(ulCycleJ = 0; ulCycleJ < SMS4_ROUND; ulCycleJ++)
		{
			ulTemp[ulCycleJ+4] = ulTemp[ulCycleJ] ^ 
							T1(ulTemp[ulCycleJ+1] ^ ulTemp[ulCycleJ+2] ^ ulTemp[ulCycleJ+3] ^ ulRK[31-ulCycleJ]);
		}

		for (ulCycleJ = 0; ulCycleJ < 4; ulCycleJ++)
		{
			ulTempOutData[ulCycleJ] = ulTemp[35-ulCycleJ];
			ulTempOutData[ulCycleJ] = SMS4_32TO8( &ulTemp[35-ulCycleJ] );
		}

		tomcrypt_memcpy(pOutData + ulCycleI*SMS4_BLOCK_LEN, ulTempOutData, SMS4_BLOCK_LEN);
	}
	return SMS4_NO_ERR;
}

T_U16 SMS4EncryptCBC(T_U8* pKey, T_U8* pIVInit, T_U8* pInData, T_U16 wInDataLen, T_U8* pOutData)
{
	T_U16 wRet = SMS4_NO_ERR;
	T_U16 wOffset = 0, wCycleI = 0;
	T_U8 pIV[SMS4_BLOCK_LEN];
	T_U8 pInDataTmp[SMS4_BLOCK_LEN];
	
	if(!pKey || !pInData || !pOutData || !pIV)
	{
		return SMS4_PARAM_ERROR;
	}
	
	if(wInDataLen % SMS4_BLOCK_LEN)
	{
		return SMS4_DATA_LEN_ERROR;
	}
	
	// ³õÊ¼»¯IV
	tomcrypt_memcpy(pIV, pIVInit, SMS4_BLOCK_LEN);
	// Çå¿ÕÁÙÊ±ÊäÈëÊý¾Ý
	tomcrypt_memset(pInDataTmp, 0x00, SMS4_BLOCK_LEN);
	
	while(wOffset*SMS4_BLOCK_LEN < wInDataLen)
	{
		// ½«´ý¼ÓÃÜÊý¾Ý×ª´æÔÚÁÙÊ±±äÁ¿ÖÐ
		tomcrypt_memcpy(pInDataTmp, &pInData[wOffset*SMS4_BLOCK_LEN], SMS4_BLOCK_LEN);
		
		// CBCÒì»ò
		for(wCycleI = 0; wCycleI < SMS4_BLOCK_LEN; wCycleI++)
		{
			pInDataTmp[wCycleI] = pInDataTmp[wCycleI] ^ pIV[wCycleI];
		}
	
		wRet = SMS4EncryptECB(pKey, pInDataTmp, SMS4_BLOCK_LEN, &pOutData[wOffset*SMS4_BLOCK_LEN]);
		if(SMS4_NO_ERR != wRet)
		{
			goto err;
		}
		
		// µÃµ½ÐÂµÄIVÖµ
		tomcrypt_memcpy(pIV, &pOutData[wOffset*SMS4_BLOCK_LEN], SMS4_BLOCK_LEN);
	
		wOffset++;
	}

err:
	return wRet;
}

T_U16 SMS4DecryptCBC(T_U8* pKey, T_U8* pIVInit, T_U8* pInData, T_U16 wInDataLen, T_U8* pOutData)
{
	T_U16 wRet = SMS4_NO_ERR;
	T_U16 wOffset = 0, wCycleI = 0;
	T_U8 pTempIV[SMS4_BLOCK_LEN];
	T_U8 pIV[SMS4_BLOCK_LEN];
	
	if(!pKey || !pInData || !pOutData || !pIV)
	{
		return SMS4_PARAM_ERROR;
	}
	
	if(wInDataLen % SMS4_BLOCK_LEN)
	{
		return SMS4_DATA_LEN_ERROR;
	}
	
	// ³õÊ¼»¯IV
	tomcrypt_memcpy(pIV, pIVInit, SMS4_BLOCK_LEN);
	
	while(wOffset*SMS4_BLOCK_LEN < wInDataLen)
	{
		// ±£´æIVÖµ
		tomcrypt_memcpy(pTempIV, &pInData[wOffset*SMS4_BLOCK_LEN], SMS4_BLOCK_LEN);
		
		wRet = SMS4DecryptECB(pKey, &pInData[wOffset*SMS4_BLOCK_LEN], SMS4_BLOCK_LEN, &pOutData[wOffset*SMS4_BLOCK_LEN]);
		if(SMS4_NO_ERR != wRet)
		{
			goto err;
		}
		
		// CBCÒì»ò
		for(wCycleI = 0; wCycleI < SMS4_BLOCK_LEN; wCycleI++)
		{
			pOutData[wOffset*SMS4_BLOCK_LEN + wCycleI] = pOutData[wOffset*SMS4_BLOCK_LEN + wCycleI] ^ pIV[wCycleI];
		}
		
		// µÃµ½ÐÂµÄIVÖµ
		tomcrypt_memcpy(pIV, pTempIV, SMS4_BLOCK_LEN);
	
		wOffset++;
	}

err:
	return wRet;
}
