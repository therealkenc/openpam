# $Id$

AM_CPPFLAGS = -I$(top_srcdir)/include -I$(top_srcdir)/lib/libpam

bin_PROGRAMS = oathkey
oathkey_SOURCES = oathkey.c
oathkey_LDADD = $(top_builddir)/lib/liboath/liboath.la $(top_builddir)/lib/libpam/libpam.la

dist_man1_MANS = oathkey.1

install-exec-hook:
	chmod u+s $(DESTDIR)$(bindir)/oathkey
