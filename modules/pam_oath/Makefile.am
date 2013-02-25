# $Id: Makefile.am 429 2010-03-09 17:51:29Z des $

pkglibdir = @OPENPAM_MODULES_DIR@
AM_CPPFLAGS = -I$(top_srcdir)/include

if WITH_PAM_OATH
pkglib_LTLIBRARIES = pam_oath.la

noinst_HEADERS = oath.h
pam_oath_la_SOURCES = pam_oath.c oath_hotp.c oath_totp.c
pam_oath_la_LDFLAGS = -no-undefined -module -version-info @LIB_MAJ@ \
	-export-symbols-regex '^pam_sm_'
pam_oath_la_LIBADD = $(top_builddir)/lib/libpam.la @CRYPTO_LIBS@
endif
