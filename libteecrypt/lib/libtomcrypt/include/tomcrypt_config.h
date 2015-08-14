/* This is the build config file.
 *
 * With this you can setup what to inlcude/exclude automatically during any build.  Just comment
 * out the line that #define's the word for the thing you want to remove.  phew!
 */

#ifndef TOMCRYPT_CFG_H
#define TOMCRYPT_CFG_H



#ifndef MACRO_GLIBC_FUNCS
#ifndef MACRO_NEWLIBC_FUNCS
#define MACRO_GLIBC_FUNCS
#endif
#endif

 
// glibc
#if defined(MACRO_GLIBC_FUNCS)

    #include <assert.h>
    #include <stdio.h>
    #include <string.h>
    #include <stdlib.h>
    #include <stdint.h>
    #include <time.h>
    #include <ctype.h>
    #include <limits.h>
    #include <stdarg.h>

    #define tomcrypt_malloc       malloc
    #define tomcrypt_realloc      realloc
    #define tomcrypt_free         free
    #define tomcrypt_memset       memset
    #define tomcrypt_memcpy       memcpy
    #define tomcrypt_memmove      memmove
    #define tomcrypt_memcmp       memcmp
    #define tomcrypt_calloc(a,b)  calloc(a,b)

    #define tomcrypt_strcpy       strcpy
    #define tomcrypt_strchr       strchr
    #define tomcrypt_strcmp       strcmp
    #define tomcrypt_qsort        qsort

    #define tomcrypt_printf       printf
    #define tomcrypt_fprintf      fprintf
    #define tomcrypt_fflush       fflush
    #define tomcrypt_clock        clock 

    #define TOMCRYPT_RAND_MAX     RAND_MAX
    #define tomcrypt_rand         rand
    #define tomcrypt_srand        srand

// newlibc
#elif 1 //defined(MACRO_NEWLIBC_FUNCS)

    #include <types.h>
    #include <user.h>

    #define tomcrypt_malloc       malloc
    #define tomcrypt_realloc      realloc
    #define tomcrypt_free         free
    #define tomcrypt_memset       memset
    #define tomcrypt_memcpy       memcpy
    #define tomcrypt_memmove      memmove
    #define tomcrypt_memcmp       memcmp
    #define tomcrypt_calloc(a,b)  malloc((a)*(b))

    #define tomcrypt_strcpy       strcpy
    #define tomcrypt_strchr       strchr
    #define tomcrypt_strcmp       strcmp
    #define tomcrypt_qsort        qsort

    #define tomcrypt_printf       printf
    #define tomcrypt_fprintf      uprintf
    #define tomcrypt_fflush       flush
    #define tomcrypt_clock        clock 

    #define TOMCRYPT_RAND_MAX     RAND_MAX
    #define tomcrypt_rand        rand
    #define tomcrypt_srand       srand

#endif



/*
 * with ARGTYPE==4, LTC_ARGCHK() returns an error when an argument is not correct
 */
#define ARGTYPE  4

/* type of argument checking, 0=default, 1=fatal and 2=error+continue, 3=nothing */
#ifndef ARGTYPE
    #define ARGTYPE  3
#endif

/* disable pthread */
#ifdef LTC_PTHREAD
#undef LTC_PTHREAD
#endif


/* Controls endianess and size of registers.  Leave uncommented to get platform neutral [slower] code 
 * 
 * Note: in order to use the optimized macros your platform must support unaligned 32 and 64 bit read/writes.
 * The x86 platforms allow this but some others [ARM for instance] do not.  On those platforms you **MUST**
 * use the portable [slower] macros.
 */

/* detect x86-32 machines somewhat */
#if !defined(__STRICT_ANSI__) && (defined(INTEL_CC) || (defined(_MSC_VER) && defined(WIN32)) || (defined(__GNUC__) && (defined(__DJGPP__) || defined(__CYGWIN__) || defined(__MINGW32__) || defined(__i386__))))
    #define ENDIAN_LITTLE
    #define ENDIAN_32BITWORD
    #define LTC_FAST
    #define LTC_FAST_TYPE    unsigned long
#endif

/* detects MIPS R5900 processors (PS2) */
#if (defined(__R5900) || defined(R5900) || defined(__R5900__)) && (defined(_mips) || defined(__mips__) || defined(mips))
    #define ENDIAN_LITTLE
    #define ENDIAN_64BITWORD
#endif

/* detect amd64 */
#if !defined(__STRICT_ANSI__) && defined(__x86_64__)
    #define ENDIAN_LITTLE
    #define ENDIAN_64BITWORD
    #define LTC_FAST
    #define LTC_FAST_TYPE    unsigned long
#endif

/* detect PPC32 */
#if !defined(__STRICT_ANSI__) && defined(LTC_PPC32)
    #define ENDIAN_BIG
    #define ENDIAN_32BITWORD
    #define LTC_FAST
    #define LTC_FAST_TYPE    unsigned long
#endif   

/* detect sparc and sparc64 */
#if defined(__sparc__)
    #define ENDIAN_BIG
    #if defined(__arch64__)
        #define ENDIAN_64BITWORD
    #else
        #define ENDIAN_32BITWORD
    #endif
#endif


#ifdef LTC_NO_FAST
    #ifdef LTC_FAST
      #undef LTC_FAST
    #endif
#endif

/* No asm is a quick way to disable anything "not portable" */
#ifdef LTC_NO_ASM
    #undef ENDIAN_LITTLE
    #undef ENDIAN_BIG
    #undef ENDIAN_32BITWORD
    #undef ENDIAN_64BITWORD
    #undef LTC_FAST
    #undef LTC_FAST_TYPE
    #define LTC_NO_ROLC
    #define LTC_NO_BSWAP
#endif

/* #define ENDIAN_LITTLE */
/* #define ENDIAN_BIG */

/* #define ENDIAN_32BITWORD */
/* #define ENDIAN_64BITWORD */

#if (defined(ENDIAN_BIG) || defined(ENDIAN_LITTLE)) && !(defined(ENDIAN_32BITWORD) || defined(ENDIAN_64BITWORD))
    #error You must specify a word size as well as endianess in tomcrypt_cfg.h
#endif

#if !(defined(ENDIAN_BIG) || defined(ENDIAN_LITTLE))
    #define ENDIAN_NEUTRAL
#endif


#endif

/* $Source: /cvs/libtom/libtomcrypt/src/headers/tomcrypt_cfg.h,v $ */
/* $Revision: 1.19 $ */
/* $Date: 2006/12/04 02:19:48 $ */
