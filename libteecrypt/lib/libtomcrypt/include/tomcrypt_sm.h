#ifndef __TOMCRYPT_SM_H__
#define __TOMCRYPT_SM_H__

#include "tomcrypt_config.h"



/*
 * Copyright (C) Win-Trust, 2012
 * This file includes SMS4 functions.
 * All functions are implemented in software level.
 */

typedef void				T_VOID;
typedef unsigned char		T_U8;
typedef char				T_S8;
typedef unsigned short		T_U16;
typedef short				T_S16;
typedef unsigned int		T_U32,u32;
typedef long				T_S32;
typedef unsigned char		T_BOOL;
typedef long				T_RESULT;


#ifndef true
#define true				((T_BOOL)1)
#endif
#ifndef false
#define false				((T_BOOL)0)
#endif


#ifndef NULL
#define NULL				0
#endif


#define RADIX_BITS			32
#define S16_MIN				(-32768)
#define S16_MAX             32767
#define U16_MAX             0xffff
#define S32_MIN             (-2147483647 - 1)
#define S32_MAX             2147483647
#define U32_MAX             0xffffffff


/*********** SM2 Algorithmn ***********/


/*********** SM3 Algorithmn ***********/


/*********** SMS4 Algorithmn ***********/
#define SMS4_KEY_LEN		16
#define SMS4_BLOCK_LEN		16

#define SMS4_ROUND			32

#define SMS4_NO_ERR			(T_U16)0x0000
#define SMS4_PARAM_ERROR	(T_U16)0x0001
#define SMS4_DATA_LEN_ERROR	(T_U16)0x0002

T_U16 SMS4EncryptECB(T_U8* pKey, T_U8* pInData, T_U16 wInDataLen, T_U8* pOutData);
T_U16 SMS4DecryptECB(T_U8* pKey, T_U8* pInData, T_U16 wInDataLen, T_U8* pOutData);
T_U16 SMS4EncryptCBC(T_U8* pKey, T_U8* pIVInit, T_U8* pInData, T_U16 wInDataLen, T_U8* pOutData);
T_U16 SMS4DecryptCBC(T_U8* pKey, T_U8* pIVInit, T_U8* pInData, T_U16 wInDataLen, T_U8* pOutData);


extern const struct ltc_cipher_descriptor sm_sms4_desc;



#endif
