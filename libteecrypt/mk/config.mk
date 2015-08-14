################################################
#			compiler configuration
################################################

USE_ARM_EABI = true

#**********************************************#
#			arm gnueabi compiler
#**********************************************#

ARM_GNUEABI_PATH = /opt/arm-none-linux-gnueabi-2009q3

ARM_GNUEABI_VER  = 4.4.1

ARM_GNUEABI_COMPILE_PRE = arm-none-linux-gnueabi-

ARM_GNUEABI_COMPILE = $(ARM_GNUEABI_PATH)/bin/$(ARM_GNUEABI_COMPILE_PRE)

ARM_GNUEABI_COMPILE_LIB_PATH = $(ARM_GNUEABI_PATH)/lib/gcc/arm-none-linux-gnueabi/$(ARM_GNUEABI_VER)

#**********************************************#
#			arm eabi compiler
#**********************************************#

ARM_EABI_PATH = /opt/arm-none-eabi-2011

ARM_EABI_VER  = 4.5.2

ARM_EABI_COMPILE_PRE = arm-none-eabi-

ARM_EABI_COMPILE = $(ARM_EABI_PATH)/bin/$(ARM_EABI_COMPILE_PRE)

ARM_EABI_COMPILE_LIB_PATH = $(ARM_EABI_PATH)/lib/gcc/arm-none-eabi/$(ARM_EABI_VER)


################################################
# Don't touch anything below this comment
################################################


################################################
#			target arch name
################################################
CONST_ARCH_X86 = "x86"
CONST_ARCH_ARM = "arm"


################################################
#			libc name
################################################
CONST_GLIBC = "glibc"
CONST_NEWLIBC = "newlibc"

