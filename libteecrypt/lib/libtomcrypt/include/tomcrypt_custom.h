/*
 * Copyright (c) 2001-2007, Tom St Denis
 * Copyright (c) 2014, STMicroelectronics International N.V.
 *
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#ifndef TOMCRYPT_CUSTOM_H_
#define TOMCRYPT_CUSTOM_H_


#define LTC_NO_PROTOTYPES
#define LTC_SOURCE
#define LTC_NO_TABLES
// #define LTC_VERBOSE

/* macros for various libc functions you can change for embedded targets */
#ifndef XMALLOC
   #ifdef tomcrypt_malloc 
   #define LTC_NO_PROTOTYPES
   #endif
#define XMALLOC  tomcrypt_malloc
#endif
#ifndef XREALLOC
   #ifdef tomcrypt_realloc 
   #define LTC_NO_PROTOTYPES
   #endif
#define XREALLOC tomcrypt_realloc
#endif
#ifndef XCALLOC
   #ifdef tomcrypt_calloc 
   #define LTC_NO_PROTOTYPES
   #endif
#define XCALLOC  tomcrypt_calloc
#endif
#ifndef XFREE
   #ifdef tomcrypt_free
   #define LTC_NO_PROTOTYPES
   #endif
#define XFREE    tomcrypt_free
#endif

#ifndef XMEMSET
   #ifdef tomcrypt_memset
   #define LTC_NO_PROTOTYPES
   #endif
#define XMEMSET  tomcrypt_memset
#endif
#ifndef XMEMCPY
   #ifdef tomcrypt_memcpy
   #define LTC_NO_PROTOTYPES
   #endif
#define XMEMCPY  tomcrypt_memcpy
#endif
#ifndef XMEMCMP
   #ifdef tomcrypt_memcmp 
   #define LTC_NO_PROTOTYPES
   #endif
#define XMEMCMP  tomcrypt_memcmp
#endif
#ifndef XSTRCMP
   #ifdef tomcrypt_strcmp
   #define LTC_NO_PROTOTYPES
   #endif
#define XSTRCMP tomcrypt_strcmp
#endif

#ifndef XCLOCK
#define XCLOCK   tomcrypt_clock
#endif

#ifndef XCLOCKS_PER_SEC
#define XCLOCKS_PER_SEC CLOCKS_PER_SEC
#endif

#ifndef XQSORT
   #ifdef tomcrypt_qsort
   #define LTC_NO_PROTOTYPES
   #endif
#define XQSORT tomcrypt_qsort
#endif

#if defined(_WIN32) || defined(_MSC_VER)
#define LTC_CALL __cdecl
#else
#ifndef LTC_CALL
   #define LTC_CALL
#endif
#endif

#ifndef LTC_EXPORT
#define LTC_EXPORT
#endif

/* certain platforms use macros for these, making the prototypes broken */
#ifndef LTC_NO_PROTOTYPES

   /* you can change how memory allocation works ... */
   LTC_EXPORT void * LTC_CALL XMALLOC(size_t n);
   LTC_EXPORT void * LTC_CALL XREALLOC(void *p, size_t n);
   LTC_EXPORT void * LTC_CALL XCALLOC(size_t n, size_t s);
   LTC_EXPORT void LTC_CALL XFREE(void *p);

   LTC_EXPORT void LTC_CALL XQSORT(void *base, size_t nmemb, size_t size, int(*compar)(const void *, const void *));


   /* change the clock function too */
   LTC_EXPORT clock_t LTC_CALL XCLOCK(void);

   /* various other functions */
   LTC_EXPORT void * LTC_CALL XMEMCPY(void *dest, const void *src, size_t n);
   LTC_EXPORT int   LTC_CALL XMEMCMP(const void *s1, const void *s2, size_t n);
   LTC_EXPORT void * LTC_CALL XMEMSET(void *s, int c, size_t n);

   LTC_EXPORT int   LTC_CALL XSTRCMP(const char *s1, const char *s2);

#endif



/* Easy button? */
#ifdef LTC_EASY
   #define LTC_NO_CIPHERS
   #define LTC_RIJNDAEL
   #define LTC_BLOWFISH
   #define LTC_DES
   #define LTC_CAST5
   
   #define LTC_NO_MODES
   #define LTC_ECB_MODE
   #define LTC_CBC_MODE
   #define LTC_CTR_MODE
   
   #define LTC_NO_HASHES
   #define LTC_SHA1
   #define LTC_SHA512
   #define LTC_SHA384
   #define LTC_SHA256
   #define LTC_SHA224
   
   #define LTC_NO_MACS
   #define LTC_HMAC
   #define LTC_OMAC
   #define LTC_CCM_MODE

   #define LTC_NO_PRNGS
   #define LTC_SPRNG
   #define LTC_YARROW
   #define LTC_DEVRANDOM
   #define TRY_URANDOM_FIRST
      
   #define LTC_NO_PK
   #define LTC_MRSA
   #define LTC_MECC
#endif   

/* Use small code where possible */
/* #define LTC_SMALL_CODE */

/* Enable self-test test vector checking */
#ifndef LTC_NO_TEST
   #define LTC_TEST
#endif

/* we want do not want any predefined PRNG */
#define LTC_NO_PRNGS

/* clean the stack of functions which put private information on stack */
/* #define LTC_CLEAN_STACK */

/* disable all file related functions */
#define LTC_NO_FILEz

/* disable all forms of ASM */
#define LTC_NO_ASM 

/* disable FAST mode */
/* #define LTC_NO_FAST */

/* disable BSWAP on x86 */
/* #define LTC_NO_BSWAP */

/* ---> Symmetric Block Ciphers <--- */

#define LTC_RIJNDAEL

/* LTC_DES includes EDE triple-LTC_DES */
#define LTC_DES

/* Chinese SM algorithmns */
#define LTC_SM_SM2
#define LTC_SM_SM3
#define LTC_SM_SMS4



/* ---> Block Cipher Modes of Operation <--- */
#ifndef LTC_NO_MODES

#define LTC_CFB_MODE
#define LTC_OFB_MODE
#define LTC_ECB_MODE
#define LTC_CBC_MODE
#define LTC_CTR_MODE

/* F8 chaining mode */
#define LTC_F8_MODE

/* LRW mode */
#define LTC_LRW_MODE
#ifndef LTC_NO_TABLES
   /* like GCM mode this will enable 16 8x128 tables [64KB] that make
    * seeking very fast.  
    */
   #define LRW_TABLES
#endif

/* XTS mode */
#define LTC_XTS_MODE

#endif /* LTC_NO_MODES */

/* ---> One-Way Hash Functions <--- */
#ifndef LTC_NO_HASHES 

#define LTC_SHA512
#define LTC_SHA384
#define LTC_SHA256
#define LTC_SHA224
#define LTC_SHA1
#define LTC_MD5

#endif /* LTC_NO_HASHES */

/* ---> MAC functions <--- */
#ifndef LTC_NO_MACS

#define LTC_HMAC
#define LTC_OMAC
#define LTC_PMAC
#define LTC_XCBC


/* ---> Encrypt + Authenticate Modes <--- */

#define LTC_EAX_MODE
#if defined(LTC_EAX_MODE) && !(defined(LTC_CTR_MODE) && defined(LTC_OMAC))
   #error LTC_EAX_MODE requires CTR and LTC_OMAC mode
#endif

#define LTC_OCB_MODE
#define LTC_CCM_MODE
#define LTC_GCM_MODE

/* Use 64KiB tables */
#ifndef LTC_NO_TABLES
   #define LTC_GCM_TABLES 
#endif

/* USE SSE2? requires GCC works on x86_32 and x86_64*/
#ifdef LTC_GCM_TABLES
/* #define LTC_GCM_TABLES_SSE2 */
#endif

#endif /* LTC_NO_MACS */

/* Various tidbits of modern neatoness */
#define LTC_BASE64

/* --> Pseudo Random Number Generators <--- */
#ifndef LTC_NO_PRNGS

/* Yarrow */
#define LTC_YARROW
/* which descriptor of AES to use?  */
/* 0 = rijndael_enc 1 = aes_enc, 2 = rijndael [full], 3 = aes [full] */
#define LTC_YARROW_AES 3

#if defined(LTC_YARROW) && !defined(LTC_CTR_MODE)
   #error LTC_YARROW requires LTC_CTR_MODE chaining mode to be defined!
#endif

/* a PRNG that simply reads from an available system source */
#define LTC_SPRNG

/* the *nix style /dev/random device */
#define LTC_DEVRANDOM
/* try /dev/urandom before trying /dev/random */
#define TRY_URANDOM_FIRST

#endif /* LTC_NO_PRNGS */

/* ---> Public Key Crypto <--- */
#ifndef LTC_NO_PK

/* Include RSA support */
#define LTC_MRSA

/* Include Diffie-Hellman support */
/*
 * From libtomcrypt.org:
 *     DH vanished because nobody used it and it was a pain to support
 *     DH support rewritten by ST
 */
#define LTC_MDH

/* Include Katja (a Rabin variant like RSA) */
/* #define MKAT */ 

/* Digital Signature Algorithm */
#define LTC_MDSA

/* ECC */
#define LTC_MECC

/* use Shamir's trick for point mul (speeds up signature verification) */
#define LTC_ECC_SHAMIR

#if defined(TFM_LTC_DESC) && defined(LTC_MECC)
   #define LTC_MECC_ACCEL
#endif   

/* do we want fixed point ECC */
/* #define LTC_MECC_FP */

/* Timing Resistant? */
/* #define LTC_ECC_TIMING_RESISTANT */

#endif /* LTC_NO_PK */

/* LTC_PKCS #1 (RSA) and #5 (Password Handling) stuff */
#ifndef LTC_NO_PKCS

#define LTC_PKCS_1
#define LTC_PKCS_5

/* Include ASN.1 DER (required by DSA/RSA) */
#define LTC_DER

#endif /* LTC_NO_PKCS */

/* cleanup */

#ifdef LTC_MECC
/* Supported ECC Key Sizes */
#ifndef LTC_NO_CURVES
   #define ECC192
   #define ECC224
   #define ECC256
   #define ECC384
   #define ECC521
#endif
#endif

#if defined(LTC_MECC) || defined(LTC_MRSA) || defined(LTC_MDSA) || defined(MKATJA)
   /* Include the MPI functionality?  (required by the PK algorithms) */
   #define MPI
#endif

#ifdef LTC_MRSA
   #define LTC_PKCS_1
#endif   

#if defined(LTC_DER) && !defined(MPI) 
   #error ASN.1 DER requires MPI functionality
#endif

#if (defined(LTC_MDSA) || defined(LTC_MRSA) || defined(LTC_MECC) || defined(MKATJA)) && !defined(LTC_DER)
   #error PK requires ASN.1 DER functionality, make sure LTC_DER is enabled
#endif



/* THREAD management */


#ifdef LTC_PTHREAD

#include <pthread.h>

#define LTC_MUTEX_GLOBAL(x)   pthread_mutex_t x = PTHREAD_MUTEX_INITIALIZER;
#define LTC_MUTEX_PROTO(x)    extern pthread_mutex_t x;
#define LTC_MUTEX_TYPE(x)     pthread_mutex_t x;
#define LTC_MUTEX_INIT(x)     pthread_mutex_init(x, NULL);
#define LTC_MUTEX_LOCK(x)     pthread_mutex_lock(x);
#define LTC_MUTEX_UNLOCK(x)   pthread_mutex_unlock(x);

#else

/* default no functions */
#define LTC_MUTEX_GLOBAL(x)
#define LTC_MUTEX_PROTO(x)
#define LTC_MUTEX_TYPE(x)
#define LTC_MUTEX_INIT(x)
#define LTC_MUTEX_LOCK(x)
#define LTC_MUTEX_UNLOCK(x)

#endif

/*
 * Here are a list of fixes required in libtomcrypt
 */

#define LTC_LINARO_FIX_RSAWITHOUTCRT

/*
 * From libtomcrypt.org:
 *     DH vanished because nobody used it and it was a pain to support
 * DH support was adapted from the master branch of libtomcrypt that can be
 * found at
 *     http://dev.openaos.org/browser/trunk/buildroot/gen7/buildroot/package/libtomcrypt/libtomcrypt-dh.patch
 * The original version was not taken as it makes use of static const array
 * containing base and prime, and did not include subprime and x-bits
 * constraints
 */
#define LTC_LINARO_FIX_DH

/* Debuggers */

/* define this if you use Valgrind, note: it CHANGES the way SOBER-128 and LTC_RC4 work (see the code) */
/* #define LTC_VALGRIND */

#endif



/* $Source: /cvs/libtom/libtomcrypt/src/headers/tomcrypt_custom.h,v $ */
/* $Revision: 1.73 $ */
/* $Date: 2007/05/12 14:37:41 $ */
