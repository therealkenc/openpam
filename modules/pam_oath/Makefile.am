# $Id$

pkglibdir = @OPENPAM_MODULES_DIR@
AM_CPPFLAGS = -I$(top_srcdir)/include

pkglib_LTLIBRARIES = pam_oath.la
pam_oath_la_LDFLAGS = -no-undefined -module -version-info @LIB_MAJ@ \
	-export-symbols-regex '^pam_sm_'
pam_oath_la_LIBADD = \
	$(top_builddir)/lib/libpam/libpam.la \
	$(top_builddir)/lib/liboath/liboath.la
