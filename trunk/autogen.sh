#!/bin/sh
#
# $Id$
#

aclocal -I m4
libtoolize --copy --force
autoheader
automake -a -c --foreign
autoconf
