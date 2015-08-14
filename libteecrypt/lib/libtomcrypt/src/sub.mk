srcs-y += mpa_desc.c
cflags-mpa_desc.c-y += -Wno-declaration-after-statement
cflags-mpa_desc.c-y += -Wno-unused-parameter


subdirs-y += ciphers
subdirs-y += encauth
subdirs-y += hashes
subdirs-y += mac
subdirs-y += math
subdirs-y += misc
subdirs-y += modes
subdirs-y += pk
subdirs-y += prngs

subdirs-y += ext