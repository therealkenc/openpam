#!/bin/sh
#
# $Id$
#

aclocal
libtoolize --copy --force
autoheader
automake -a -c --foreign
autoconf
