/* This is the build config file.
 *
 * With this you can setup what to inlcude/exclude automatically during any build.  Just comment
 * out the line that #define's the word for the thing you want to remove.  phew!
 */

#ifndef TEE_CONFIG_H
#define TEE_CONFIG_H


#ifndef MACRO_GLIBC_FUNCS
#ifndef MACRO_NEWLIBC_FUNCS
#define MACRO_GLIBC_FUNCS
#endif
#endif

 
// glibc
#if defined(MACRO_GLIBC_FUNCS)
 	#include <unistd.h>
	#include <stdlib.h>
	#include <string.h>
	#include <stdint.h>
	#include <stdbool.h>
	#include <stdio.h>
	#include <stddef.h>
 	#include <memory.h>
	#include <sys/time.h>
  	#include <fcntl.h>

	#define tee_malloc			malloc
	#define tee_realloc			realloc
	#define tee_free			free
	#define tee_memset			memset
	#define tee_memcpy			memcpy
	#define tee_memmove			memmove
	#define tee_memcmp			memcmp
	#define tee_calloc			calloc

	#define tee_printf			printf
 	#define tee_fprintf			fprintf

	#define TEE_RAND_MAX		RAND_MAX
	#define tee_rand			rand
	#define tee_srand			srand

// newlibc
#elif 1 //defined(MACRO_NEWLIBC_FUNCS)

	#include <types.h>
	#include <user.h>
 	#include <stat.h>
	#include <fcntl.h>

	#define tee_malloc			malloc
	#define tee_realloc			realloc
	#define tee_free			free
	#define tee_memset			memset
	#define tee_memcpy			memcpy
	#define tee_memmove			memmove
	#define tee_memcmp			memcmp
	//#define tee_calloc(a,b)		malloc((a)*(b))
	#define tee_calloc			utee_mem_calloc
	#define tee_printf			utee_printf
 	#define tee_fprintf			uprintf

	#define TEE_RAND_MAX		RAND_MAX
	#define tee_rand			rand
	#define tee_srand			srand


#endif


extern int utee_printf(char *format, ...);

#define _PANIC_LOG_(panicCode)   \
        tee_printf("raising exception[0x%x]: [file:%s  line:%d]\n", panicCode, __FILE__, __LINE__);



#endif