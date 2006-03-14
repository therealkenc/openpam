#!/bin/sh
#
# $Id$
#

if [ -d /usr/local/gnu-autotools/bin ] ; then
	export PATH=${PATH}:/usr/local/gnu-autotools/bin
fi

aclocal
libtoolize --copy --force
autoheader
automake -a -c --foreign
autoconf
