#!/bin/sh
#
# $P4: //depot/projects/openpam/clean.sh#1 $

tmpfile="/tmp/openpam-clean.$$"
p4 files ... | grep -v 'delete change' |
    sed 's|^.*/openpam/||; s|#.*$||' > "${tmpfile}"
find . -type f | cut -c 3- | while read file ; do
    grep "^${file}\$" "${tmpfile}" >/dev/null || rm -v "${file}"
done
find . -type d -empty -print -delete
rm "${tmpfile}"

