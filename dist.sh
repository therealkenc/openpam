#!/bin/sh
#
# $P4: //depot/projects/openpam/dist.sh#11 $
#

set -e

srcdir=$(dirname $(realpath $0))
release=$(perl -ne '/^#define\s+_OPENPAM_VERSION\s+(\d+)/ && print $1' \
    $srcdir/include/security/openpam_version.h)
distname="openpam-${release}"
tarball="${distname}.tar.gz"

install -d -m 0755 "${distname}"
grep '^[A-Za-z].*/$' MANIFEST | while read dir; do
    echo "Creating ${dir}"
    install -d -m 0755 "${distname}/${dir}" || exit 1
done
grep '^[A-Za-z].*[^/]$' MANIFEST | while read file; do
    echo "Adding ${file}"
    install -c -m 0644 "${file}" "${distname}/${file}" || exit 1
done
for file in autogen.sh configure depcomp install-sh ltmain.sh ; do
    echo "Adjusting permissions for ${file}"
    chmod a+x "${distname}/${file}"
done
find "${distname}" | sort -r | xargs touch -t "${release}0000"
tar zcf "${tarball}" "${distname}"
dd if=/dev/zero of="${tarball}" conv=notrunc bs=4 oseek=1 count=1
rm -rf "${distname}"

echo
md5 "${tarball}"
