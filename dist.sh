#!/bin/sh
#
# $P4: //depot/projects/openpam/dist.sh#2 $
#

set -e

release=$(date '+%Y%m%d')
distname="openpam-${release}"

install -d -m 0755 "${distname}"
grep -v '^#' MANIFEST | while read file; do
    install -d -m 0755 "${distname}/$(dirname ${file})"
    install -c -m 0644 "${file}" "${distname}/${file}"
done
tar zcf "${distname}.tar.gz" "${distname}"
rm -rf "${distname}"
