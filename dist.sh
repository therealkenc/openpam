#!/bin/sh
#
# $P4: //depot/projects/openpam/dist.sh#6 $
#

set -e

release=$(date '+%Y%m%d')
distname="openpam-${release}"
tarball="${distname}.tar.gz"

make cleandir
make cleandir
make depend && make
install -d -m 0755 "${distname}"
grep -v '^#' MANIFEST | while read file; do
    install -d -m 0755 "${distname}/$(dirname ${file})" || exit 1
    install -c -m 0644 "${file}" "${distname}/${file}" || exit 1
done
tar zcf "${tarball}" "${distname}"
rm -rf "${distname}"
make cleandir
make cleandir

echo
md5 "${tarball}"
