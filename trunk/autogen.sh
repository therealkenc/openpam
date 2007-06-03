#!/bin/sh
#
# $Id$
#

if [ -d /usr/local/gnu-autotools/bin ] ; then
	export PATH=${PATH}:/usr/local/gnu-autotools/bin
	FIX_BROKEN_FREEBSD_PORTS="-I /usr/local/share/aclocal"
fi

aclocal ${FIX_BROKEN_FREEBSD_PORTS}
libtoolize --copy --force
autoheader
automake -a -c --foreign
autoconf
