#!/bin/sh -ex
#
# $Id$
#

libtoolize --copy --force
aclocal
autoheader
automake -a -c --foreign
autoconf
