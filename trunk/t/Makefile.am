# $Id$

INCLUDES = -I$(top_srcdir)/include -I$(top_srcdir)/lib

# tests
TESTS = t_openpam_readword
check_PROGRAMS = $(TESTS)

# libt - common support code
check_LIBRARIES = libt.a
libt_a_SOURCES = t_main.c

# link with libpam and libt
LDADD = $(top_builddir)/lib/libpam.la $(srcdir)/libt.a
