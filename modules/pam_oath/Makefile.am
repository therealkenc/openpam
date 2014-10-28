# $Id$

if CUSTOM_MODULES_DIR
moduledir = $(OPENPAM_MODULES_DIR)
else
moduledir = $(libdir)
endif
AM_CPPFLAGS = -I$(top_srcdir)/include

module_LTLIBRARIES = pam_oath.la

pam_oath_la_SOURCES = pam_oath.c
pam_oath_la_LDFLAGS = -no-undefined -module -version-info $(LIB_MAJ) \
	-export-symbols-regex '^pam_sm_'
pam_oath_la_LIBADD =
if WITH_SYSTEM_LIBOATH
pam_oath_la_LIBADD += $(SYSTEM_LIBOATH)
else
pam_oath_la_LIBADD += $(top_builddir)/lib/liboath/liboath.la
endif
if WITH_SYSTEM_LIBPAM
pam_oath_la_LIBADD += $(SYSTEM_LIBPAM)
else
pam_oath_la_LIBADD += $(top_builddir)/lib/libpam/libpam.la
endif
