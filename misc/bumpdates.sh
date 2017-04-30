#!/bin/sh
#-
# Copyright (c) 2012 Dag-Erling Smørgrav
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
# 1. Redistributions of source code must retain the above copyright
#    notice, this list of conditions and the following disclaimer.
# 2. Redistributions in binary form must reproduce the above copyright
#    notice, this list of conditions and the following disclaimer in the
#    documentation and/or other materials provided with the distribution.
# 3. The name of the author may not be used to endorse or promote
#    products derived from this software without specific prior written
#    permission.
#
# THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
# ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
# ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
# FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
# DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
# OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
# HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
# LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
# OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
# SUCH DAMAGE.
#
# $OpenPAM$
#

error() {
	echo "$@" >&2
	exit 1
}

if [ ! -f configure.ac -o ! -f include/security/openpam_version.h ] ; then
	error "script invoked from incorrect directory"
fi

if [ $# -ne 1 ] ; then
	error "missing release name"
fi

release="$1"
isodate=$(date +"%Y%m%d")
mdocdate=$(date +"%B %e, %Y" | tr -s ' ')

echo "openpam_version.h"
perl -p -i -e '
m/OPENPAM_RELEASE/ && s/\"\w+\"/\"'"${release}"'\"/;
m/OPENPAM_VERSION/ && s/\d{8}/'"${isodate}"'/;
' include/security/openpam_version.h

echo "configure.ac"
perl -p -i -e '
m/AC_INIT/ && s/trunk|\d{8}/'"${isodate}"'/
' configure.ac

echo "man pages"
perl -p -i -e '
s/^\.Dd .*?$/.Dd '"${mdocdate}"'/;
' $(find . -type f -name \*.[0-9])

echo "check before commit!"
