# $Id$

AM_CPPFLAGS = -I$(top_srcdir)/include -I$(top_srcdir)/lib/libpam

bin_PROGRAMS = oathkey
oathkey_SOURCES = oathkey.c
oathkey_LDADD =
if WITH_SYSTEM_LIBOATH
oathkey_LDADD += $(SYSTEM_LIBOATH)
else
oathkey_LDADD += $(top_builddir)/lib/liboath/liboath.la
endif
if WITH_SYSTEM_LIBPAM
oathkey_LDADD += $(SYSTEM_LIBPAM)
else
oathkey_LDADD += $(top_builddir)/lib/libpam/libpam.la
endif

dist_man1_MANS = oathkey.1

install-exec-hook:
	chmod u+s $(DESTDIR)$(bindir)/oathkey
