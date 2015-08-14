################################################
#       Target Arch Configuration
################################################
include mk/config.mk

WHICH_ARCH = $(CONST_ARCH_ARM)
WHICH_ARCH = $(CONST_ARCH_X86)

WHICH_LIBC = $(CONST_NEWLIBC)
WHICH_LIBC = $(CONST_GLIBC)


################################################
# Don't touch anything below this comment
################################################


include mk/compile.mk


################################################
#    lib dir configuration
################################################
LIB_TEECRYPT_PATH	= ../libteecrypt
LIB_TEECRYPT_NAME	= teecrypt         # libteecrypt.a

NEWLIBC_DIR			= ../libteecrypt/lib/newlibc
NEWLIBC_HDR_DIR		= $(NEWLIBC_DIR)

#libtomcrypt
TOMCRYPT_DIR		= ../libteecrypt/lib/libtomcrypt
TOMCRYPT_HDR_DIR	= $(TOMCRYPT_DIR)/include

object_files :=
clean_files  :=


################################################
#		build flags
################################################

cflags_ext	+= 	-Wall -std=c99  -O3  --static \
				-D$(DEF_MACROS) -I./include  -I$(TOMCRYPT_HDR_DIR)
				 
ldflag_ext	+=  -L$(LIB_TEECRYPT_PATH) -l$(LIB_TEECRYPT_NAME) 

ifeq ($(WHICH_LIBC),$(CONST_NEWLIBC))
cflags_ext	+= -nostdlib -I$(NEWLIBC_DIR)  -fno-builtin 
# should link libgcc.a that can supports softfloat
ldflag_ext	+= -L$(CROSS_COMPILE_LIB_PATH) -lgcc \
				-nostartfiles -e main 
endif				

################################################

subdirs = ./src
include mk/subdir.mk          # mk/subdir.mk  gen srcs and objs
object_files+=	$(objs) 
clean_files +=	$(object_files)
bin_files    =	$(object_files:%.o=%)
cp_bin_files =	$(object_files:$(subdirs)/%.o=%)
clean_files +=	$(bin_files)
clean_files +=	$(cp_bin_files)
################################################
.PHONY: all
all: demo

demo: $(objs) 
	@cp $(bin_files) ./
	@echo done!


################################################
#            cleanup files
################################################
clean:
	rm -f $(clean_files)
