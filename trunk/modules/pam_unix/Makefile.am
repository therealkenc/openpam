# $Id$

pkglibdir = @OPENPAM_MODULES_DIR@
AM_CPPFLAGS = -I$(top_srcdir)/include

pkglib_LTLIBRARIES = pam_unix.la

pam_unix_la_SOURCES = pam_unix.c
pam_unix_la_LDFLAGS = -no-undefined -module -version-info @LIB_MAJ@ \
	-export-symbols-regex '^pam_sm_'
pam_unix_la_LIBADD = $(top_builddir)/lib/libpam.la @CRYPT_LIBS@
