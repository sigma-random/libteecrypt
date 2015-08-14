################################################
# Don't touch anything below this comment
################################################

ifeq ($(WHICH_ARCH),$(CONST_ARCH_ARM))

	ifeq ($(WHICH_LIBC),$(CONST_NEWLIBC))

		ifeq ($(USE_ARM_EABI), true)

	    	CROSS_COMPILE = $(ARM_EABI_COMPILE)
	    	CROSS_COMPILE_LIB_PATH = $(ARM_EABI_COMPILE_LIB_PATH)
	    
	    else

	    	CROSS_COMPILE = $(ARM_GNUEABI_COMPILE)
	    	CROSS_COMPILE_LIB_PATH = $(ARM_GNUEABI_COMPILE_LIB_PATH)
	    	
	    endif

	else

	    CROSS_COMPILE = $(ARM_GNUEABI_COMPILE)
	    CROSS_COMPILE_LIB_PATH = $(ARM_GNUEABI_COMPILE_LIB_PATH)
	    
	endif

else	

    CROSS_COMPILE =

endif

ifeq ($(WHICH_ARCH),$(CONST_ARCH_X86))

	ifeq ($(WHICH_LIBC),$(CONST_NEWLIBC))

		WHICH_LIBC = $(CONST_GLIBC)

	endif
	
endif

ifeq ($(WHICH_LIBC),$(CONST_GLIBC))

    DEF_MACROS = MACRO_GLIBC_FUNCS
    define USE_GLIBC
    endef

else

    DEF_MACROS = MACRO_NEWLIBC_FUNCS
    define USE_NEWLIBC
    endef

endif



################################################

#CROSS_COMPILE = arm-none-linux-gnueabi-
CC  =	$(CROSS_COMPILE)gcc
LD  =	$(CROSS_COMPILE)ld
AR	=	$(CROSS_COMPILE)ar
NM	=	$(CROSS_COMPILE)nm
RL 	=	$(CROSS_COMPILE)ranlib

################################################

CFLAGS	=	#-Wall  -std=c99  -g  #-O3  -std=gnu99  -Werror   
AFLAGS	=	crsv 
LDFLAGS	=	

CFLAGS_EXT	+=	$(cflags_ext)
LDFLAGS_EXT	+=	$(ldflag_ext)

################################################
#			compile rules
################################################
.c.o:
	$(CC) $< -o $* $(CFLAGS) $(CFLAGS_EXT) $(LDFLAGS) $(LDFLAGS_EXT)

.C.o:
	$(CC) $< -o $* $(CFLAGS) $(CFLAGS_EXT) $(LDFLAGS) $(LDFLAGS_EXT)
	
.s.o:
	$(CC) $< -o $* $(CFLAGS) $(CFLAGS_EXT) $(LDFLAGS) $(LDFLAGS_EXT)

.S.o:
	$(CC) $< -o $* $(CFLAGS) $(CFLAGS_EXT) $(LDFLAGS) $(LDFLAGS_EXT)
