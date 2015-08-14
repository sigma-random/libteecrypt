#ifndef MY_TYPES_H
#define MY_TYPES_H


#ifndef  RAND_MAX	
#define RAND_MAX       0x7FFF
#endif

typedef	__SIZE_TYPE__	size_t;
typedef struct _IO_FILE FILE;

#ifdef offsetof
#undef offsetof
#endif

#ifdef __compiler_offsetof
	#define offsetof(TYPE,MEMBER) __compiler_offsetof(TYPE,MEMBER)
#else
	#define offsetof(TYPE, MEMBER) ((size_t) &((TYPE *)0)->MEMBER)
#endif


#define ptrdiff_t int


/**************************** bool type *****************************/

	#ifndef __cplusplus
		#define bool	_Bool 			// C99 Boolean Type:  _Bool
		#ifndef true
		#define true	1
		#endif
		#ifndef false
		#define false	0
		#endif
	#else /* __cplusplus */
		#define _Bool	bool
		#define bool	bool
		#ifndef false
		#define false	false
		#endif
		#ifndef true
		#define true	true
		#endif
	#endif

	#define __bool_true_false_are_defined 1


/**************************** int type *****************************/

	/* Signed */
	#ifndef __int8_t_defined
		#define __int8_t_defined
		typedef signed char			int8_t;
		typedef short int			int16_t;
		typedef int					int32_t;
		#if __WORDSIZE == 64
			typedef long int		int64_t;
		#else
			typedef long long int	int64_t;
		#endif
	#endif

	/* Unsigned */
	typedef unsigned char			uint8_t;
	typedef unsigned short int		uint16_t;
	#ifndef __uint32_t_defined
		typedef unsigned int		uint32_t;
		#define __uint32_t_defined
	#endif
	#if __WORDSIZE == 64
		typedef unsigned long int	uint64_t;
	#else
		typedef unsigned long long int	uint64_t;
	#endif

	/* Largest integral types */
	#if __WORDSIZE == 64
		typedef long int			intmax_t;
		typedef unsigned long int	uintmax_t;
	#else
		typedef long long int		intmax_t;
		typedef unsigned long long int	uintmax_t;
	#endif


	/* The ISO C99 standard specifies that in C++ implementations these
	   macros should only be defined if explicitly requested.  */
	#if !defined __cplusplus || defined __STDC_LIMIT_MACROS
		#if __WORDSIZE == 64
			#define __INT64_C(c)	c ## L
			#define __UINT64_C(c)	c ## UL
		#else
			#define __INT64_C(c)	c ## LL
			#define __UINT64_C(c)	c ## ULL
		#endif

		/* Minimum of signed integral types */
		#define INT8_MIN		(-128)
		#define INT16_MIN		(-32767-1)
		#define INT32_MIN		(-2147483647-1)
		#define INT64_MIN		(-__INT64_C(9223372036854775807)-1)
		#define INT_MIN 		INT32_MIN
		/* Maximum of signed integral types */
		#define INT8_MAX		(127)
		#define INT16_MAX		(32767)
		#define INT32_MAX		(2147483647)
		#define INT64_MAX		(__INT64_C(9223372036854775807))
		#define INT_MAX			INT32_MAX
		/* Maximum of unsigned integral types */
		#define UINT8_MAX		(255)
		#define UINT16_MAX		(65535)
		#define UINT32_MAX		(4294967295U)
		#define UINT64_MAX		(__UINT64_C(18446744073709551615))
	# endif	

/**************************** `void *' pointers type *****************************/

	#if __WORDSIZE == 64
		#ifndef __intptr_t_defined
			typedef long int        intptr_t;
			#define __intptr_t_defined
		#endif
		typedef unsigned long int   uintptr_t;
	#else
		#ifndef __intptr_t_defined
			typedef int         intptr_t;
			#define __intptr_t_defined
			#endif
		typedef unsigned int        uintptr_t;
	#endif

/**************************** time type *****************************/

typedef unsigned int    time_t;
typedef unsigned int 	suseconds_t;

struct timezone {
	int tz_minuteswest;	/* minutes west of Greenwich */
	int tz_dsttime;	/* type of DST correction */
};

struct timeval {
	time_t	tv_sec;	/* seconds */
	suseconds_t tv_usec;	/* microseconds */
};


/**************************** valist type *****************************/


#ifndef VALIST 
#define VALIST 
typedef char *va_list; 
 

#define ALIGNbnd      ( sizeof (signed int) - 1 )
#define bnd(X, bnd)         (((sizeof (X)) + (bnd)) & (~(bnd)))
#define va_arg(ap,T)   ( *(T *)(((ap) += (bnd(T, ALIGNbnd))) - (bnd(T,ALIGNbnd))) )
#define va_end(ap)     ( (void)0 )
#define va_start(ap,A) ( (void) ((ap) = (((char *) &(A)) + (bnd(A,ALIGNbnd)))) )

#endif




#endif