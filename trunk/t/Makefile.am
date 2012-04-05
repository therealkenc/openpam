# $Id$

INCLUDES = -I$(top_srcdir)/include -I$(top_srcdir)/lib

noinst_HEADERS = t.h

# tests
TESTS = t_openpam_readword t_openpam_readlinev
check_PROGRAMS = $(TESTS)

# libt - common support code
check_LIBRARIES = libt.a
libt_a_SOURCES = t_main.c

# link with libpam and libt
LDADD = libt.a $(top_builddir)/lib/libpam.la
