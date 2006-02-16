#!/bin/sh
#
# $Id$

tmpfile="/tmp/openpam-clean.$$"
p4 files ... | grep -v 'delete change' |
    sed 's|^.*/openpam/||; s|#.*$||' > "${tmpfile}"
find . -not -type d | cut -c 3- | while read file ; do
    grep "^${file}\$" "${tmpfile}" >/dev/null || rm -v "${file}"
done
find . -type d -empty -print -delete
rm "${tmpfile}"

