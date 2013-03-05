# $Id$

AM_CPPFLAGS = -I$(top_srcdir)/include -I$(top_srcdir)/lib/libpam

lib_LTLIBRARIES = liboath.la

liboath_la_SOURCES = \
	oath_base32.c \
	oath_base64.c \
	oath_hotp.c \
	oath_totp.c \
	oath_key.c

liboath_la_LDFLAGS = -no-undefined -version-info @LIB_MAJ@
liboath_la_LIBADD = $(top_builddir)/lib/libpam/libpam.la @CRYPTO_LIBS@
