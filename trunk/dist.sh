#!/bin/sh
#
# $P4: //depot/projects/openpam/dist.sh#10 $
#

set -e

release=$(date '+%Y%m%d')
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
for file in autogen.sh configure depcomp install-sh ltconfig ltmain.sh ; do
    echo "Adjusting permissions for ${file}"
    chmod a+x "${distname}/${file}"
done
(cd "${distname}" && grep -rl YYYYMMDD *) | while read file ; do
    echo "Datestamping ${file}"
    perl -p -i -e "s/YYYYMMDD/${release}/g" "${distname}/${file}"
done
find "${distname}" | sort -r | xargs touch -t "${release}0000"
tar zcf "${tarball}" "${distname}"
dd if=/dev/zero of="${tarball}" conv=notrunc bs=4 oseek=1 count=1
rm -rf "${distname}"

echo
md5 "${tarball}"
