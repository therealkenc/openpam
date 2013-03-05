# $Id$

pkglibdir = @OPENPAM_MODULES_DIR@
AM_CPPFLAGS = -I$(top_srcdir)/include

pkglib_LTLIBRARIES = pam_deny.la

pam_deny_la_SOURCES = pam_deny.c
pam_deny_la_LDFLAGS = -no-undefined -module -version-info @LIB_MAJ@ \
	-export-symbols-regex '^pam_sm_'
pam_deny_la_LIBADD = $(top_builddir)/lib/libpam/libpam.la
