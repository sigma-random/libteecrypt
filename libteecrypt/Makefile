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
PROJECT_DIR			=	.
LIB_DIR				=	$(PROJECT_DIR)/lib
CORE_LIB_DIR		=	$(LIB_DIR)/

#newlibc
NEWLIBC_DIR			=	$(LIB_DIR)/newlibc
NEWLIBC_HDR_DIR		=	$(NEWLIBC_DIR)

#libmap
MPA_DIR				=   $(LIB_DIR)/libmpa
MPA_HDR_DIR			=   $(MPA_DIR)/include

#libtomcrypt
TOMCRYPT_DIR		=	$(LIB_DIR)/libtomcrypt
TOMCRYPT_HDR_DIR	=	$(TOMCRYPT_DIR)/include

#teecrypt
TEECRYPT_DIR		=	$(PROJECT_DIR)/teecrypt
TEECRYPT_HDR_DIR	=	$(TEECRYPT_DIR)/include



object_files :=
clean_files  :=


################################################
#		build flags
################################################

cflags_ext	+= 	-Werror -std=c99  -O3  --static -D$(DEF_MACROS)
ldflag_ext	+=


################################################
# Don't touch anything below this comment
################################################


################################################
#        generate libteecrypt.a
################################################
TEECRYPT_LIBFILE = libteecrypt.a
clean_files += $(TEECRYPT_LIBFILE)
.PHONY: all
all:  newlibc    mpa    tomcrypt  teecrypt_api
	$(AR)  $(AFLAGS) $(TEECRYPT_LIBFILE)  $(object_files) 
	@echo gen teecrypt libfile: $(TEECRYPT_LIBFILE)




################################################
#              build newlibc
################################################
ifeq ($(WHICH_LIBC),$(CONST_NEWLIBC))
NEWLIBC_FILE = libnewlibc.a
subdirs = $(NEWLIBC_DIR)
include mk/subdir.mk          # mk/subdir.mk  gen srcs and objs
object_files += $(objs)
clean_files	 += $(NEWLIBC_FILE)
cflags_ext	 +=  -nostdlib -I$(NEWLIBC_DIR) -fno-builtin  -L$(CROSS_COMPILE_LIB_PATH) -lgcc
ldflag_ext	 +=  newlibc: $(objs)
newlibc: $(objs)
	#$(AR)  $(AFLAGS) $(NEWLIBC_FILE)  $^
	@echo --------------------- build module: $(NEWLIBC_FILE) ---------------------
else
newlibc:
endif

################################################
#             build libmpa
################################################
MPA_LIBFILE = libmpa.a
subdirs = $(MPA_DIR)
include mk/subdir.mk          # mk/subdir.mk  gen srcs and objs
object_files += $(objs)
clean_files  += $(MPA_LIBFILE)
cflags_ext	 += -I$(MPA_HDR_DIR)
ldflag_ext	 +=

mpa: $(objs)
	#$(AR)  $(AFLAGS) $(MPA_LIBFILE)  $^
	@echo --------------------- build module: $(MPA_LIBFILE) ---------------------


################################################
#             build libtomcrypt
################################################
TOMCRYPT_LIBFILE = libtomcrypt.a
subdirs  = $(TOMCRYPT_DIR)
include  mk/subdir.mk          # mk/subdir.mk  gen srcs and objs
object_files += $(objs)
clean_files  += $(TOMCRYPT_LIBFILE)
cflags_ext	 += -I$(TOMCRYPT_HDR_DIR)
ldflag_ext	 +=
tomcrypt: $(objs)
	#$(AR)  $(AFLAGS) $(TOMCRYPT_LIBFILE)  $^
	@echo --------------------- build module: $(TOMCRYPT_LIBFILE) ---------------------



################################################
#             build teecrypt_api  
################################################
TEECRYPT_API_LIBFILE = teecrypt_api.a
subdirs  = $(TEECRYPT_DIR)
include  mk/subdir.mk          # mk/subdir.mk  gen srcs and objs
object_files += $(objs)
clean_files  += $(TEECRYPT_API_LIBFILE)
cflags_ext	 += -I$(TEECRYPT_HDR_DIR)
ldflag_ext	 +=
teecrypt_api: $(objs)
	#$(AR)  $(AFLAGS) $(TEECRYPT_API_LIBFILE)  $^
	@echo --------------------- build module: $(TEECRYPT_API_LIBFILE) ---------------------


################################################
#            cleanup files
################################################
clean_files += $(object_files)
clean:
	rm -f $(clean_files)




