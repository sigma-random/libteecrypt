/* This is the build config file.
 *
 * With this you can setup what to inlcude/exclude automatically during any build.  Just comment
 * out the line that #define's the word for the thing you want to remove.  phew!
 */

#ifndef GUARD_MPA_CONFIG_H
#define GUARD_MPA_CONFIG_H

#ifndef MACRO_GLIBC_FUNCS
#ifndef MACRO_NEWLIBC_FUNCS
#define MACRO_GLIBC_FUNCS
#endif
#endif

// glibc
#if defined(MACRO_GLIBC_FUNCS)

    #include <stdlib.h>
    #include <string.h>
    #include <inttypes.h>
    #include <stdbool.h>
 
    #define mpa_malloc          malloc
    #define mpa_realloc         realloc
    #define mpa_free            free
    #define mpa_memset          memset
    #define mpa_memcpy          memcpy
    #define mpa_memmove         memmove
    #define mpa_calloc(a,b)     calloc(a,b)

    #define mpa_strcpy          strcpy
    #define mpa_strchr          strchr
    #define mpa_strcmp          strcmp
 
    #define mpa_printf          printf
    #define mpa_fprintf         fprintf
    #define mpa_fflush          fflush
    #define MPA_RAND_MAX        RAND_MAX
    #define mpa_rand            rand
    #define mpa_srand           srand

// newlibc
#elif 1 //defined(MACRO_NEWLIBC_FUNCS)

    #include <types.h>
    #include <user.h>

    #define mpa_malloc          malloc
    #define mpa_realloc         realloc
    #define mpa_free            free
    #define mpa_memset          memset
    #define mpa_memcpy          memcpy
    #define mpa_memmove         memmove
    #define mpa_calloc(a,b)     malloc((a)*(b))

    #define mpa_strcpy          strcpy
    #define mpa_strchr          strchr
    #define mpa_strcmp          strcmp

    #define mpa_printf          printf
    #define mpa_fprintf         uprintf
    #define mpa_fflush          flush
    #define MPA_RAND_MAX        RAND_MAX
    #define mpa_rand            rand
    #define mpa_srand           srand

#endif


/************************************************************************\
 *  Common definitions
 *  You should go through these carefully and adjust to your environment
 \************************************************************************/

/*
 * Definitions of different sized integers and unsigned
 *
 * mpa_word_t:  should be an unsigned int of size equal to the most
 *              efficient add/sub/mul/div word size of the machine.
 *
 * mpa_int_t    should be a signed int of the same size as the mpa_word_t
 *
 * mpa_halfw_t: half size of mpa_word_t
 *
 * mpa_asize_t: an unsigned int of suitable size to hold the number of
 *              allocated bytes for the representation. We cannot use size_t
 *              since that is 64 bit long on 64 bit machines, and that is
 *              ridiciously large.
 *
 * mpa_usize_t: a signed int suitable to hold the number of used mpa_word_t to
 *              represent the integer.
 *
 * mpa_byte_t:  the native unsigned byte type.
 */


typedef uint32_t mpa_word_t;
typedef int32_t mpa_int_t;
typedef uint16_t mpa_halfw_t;
typedef uint32_t mpa_asize_t;
typedef int32_t mpa_usize_t;
typedef uint8_t mpa_byte_t;



/* Number of bits in mpa_word_t */
#define MPA_WORD_SIZE                  32

/* Largest representable number in a mpa_int_t */
#define MPA_INT_MAX                    INT32_MAX

/* Smallest representable number in a mpa_int_t */
#define MPA_INT_MIN                    INT32_MIN

/* The Log2(MPA_WORD_SIZE) */
#define MPA_LOG_OF_WORD_SIZE           5

/* The Log2 of number of bytes in a mpa_word_t */
#define MPA_LOG_OF_BYTES_PER_WORD      2

/* The largest power of 10 representable in a mpa_word_t */
#define LARGEST_DECIMAL_BASE_IN_WORD    1000000000

/* the number of decimal digits minus 1 in LARGEST_DECIMAL_BASE_IN_WORD */
#define LARGEST_DECIMAL_BASE_DIGITS     9

/* The largest string size to represent a big number as a string */
#define MPA_STR_MAX_SIZE (4096 + 2)

/* define MPA_BIG_ENDIAN or MPA_LITTLE_ENDIAN */
#define MPA_LITTLE_ENDIAN
/*#define MPA_BIG_ENDIAN */

/*
 * comment out the line below if your system does not support "unsigned
 * long long"
 */
#define MPA_SUPPORT_DWORD_T

/*
 * define if you want to use ARM assembler code for certain cruicial
 * functions
 */
/* #define     USE_ARM_ASM */

/*
 * Include functionality for converting to and from strings; mpa_set_string
 * and mpa_get_string.
 */
#define MPA_INCLUDE_STRING_CONVERSION


//#define DEBUG


#endif /* include guard */
