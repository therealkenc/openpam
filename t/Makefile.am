# $Id$

AM_CPPFLAGS = -I$(top_srcdir)/include -I$(top_srcdir)/lib/libpam

AM_TESTS_ENVIRONMENT = \
	PAM_RETURN_SO=$(abs_top_builddir)/modules/pam_return/.libs/pam_return.so

noinst_HEADERS = t.h t_pam_conv.h

# tests
TESTS =
TESTS += t_openpam_ctype
TESTS += t_openpam_dispatch
TESTS += t_openpam_readword
TESTS += t_openpam_readlinev
check_PROGRAMS = $(TESTS)

# libt - common support code
check_LIBRARIES = libt.a
libt_a_SOURCES = t_main.c t_file.c t_pam_conv.c

# link with libpam and libt
LDADD = libt.a
if WITH_SYSTEM_LIBPAM
LDADD += $(SYSTEM_LIBPAM)
else
LDADD += $(top_builddir)/lib/libpam/libpam.la
endif
