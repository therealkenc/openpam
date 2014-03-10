# $Id$

AM_CPPFLAGS = -I$(top_srcdir)/include -I$(top_srcdir)/lib/libpam

lib_LTLIBRARIES = liboath.la

noinst_HEADERS = oath_impl.h

liboath_la_SOURCES = \
	oath_base32.c \
	oath_base64.c \
	oath_hotp.c \
	oath_totp.c \
	oath_key_alloc.c \
	oath_key_create.c \
	oath_key_dummy.c \
	oath_key_from_uri.c \
	oath_key_free.c \
	oath_key.c \
	oath_uri_decode.c

liboath_la_LDFLAGS = -no-undefined -version-info @LIB_MAJ@
liboath_la_LIBADD = $(top_builddir)/lib/libpam/libpam.la @CRYPTO_LIBS@
