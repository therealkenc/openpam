#!/bin/sh
#
# $Id$
#

libtoolize --copy --force
aclocal -I m4
autoheader
automake --add-missing --copy --foreign
autoconf
