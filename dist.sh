#!/bin/sh
#
# $P4: //depot/projects/openpam/dist.sh#8 $
#

set -e

release=$(date '+%Y%m%d')
distname="openpam-${release}"
tarball="${distname}.tar.gz"

gmake clean || true
gmake distclean || true
sh -e autogen.sh
sh configure --with-pam-su --with-pam-unix
gmake
install -d -m 0755 "${distname}"
grep -v '^#' MANIFEST | while read file; do
    install -d -m 0755 "${distname}/$(dirname ${file})" || exit 1
    install -c -m 0644 "${file}" "${distname}/${file}" || exit 1
done
for f in autogen.sh configure depcomp install-sh ltconfig ltmain.sh ; do
    chmod a+x "${distname}/${f}"
done
for f in configure configure.in include/security/openpam_version.h ; do
    perl -p -i -e "s/YYYYMMDD/${release}/g" "${distname}/${f}"
done
find "${distname}" | xargs touch -t "${release}0000"
tar zcf "${tarball}" "${distname}"
rm -rf "${distname}"
gmake clean || true
gmake distclean || true

echo
md5 "${tarball}"
