#!/bin/sh
#set -x

if [ x"${srcdir}" = x ]; then
    srcdir=.
fi
. ${srcdir}/lib.sh

get()
{
	tftp 127.0.0.1:69 -c get "$1"
	sleep 1
}

netstat -atnup

get testfile.txt
ls -la
[ -s testfile.txt ] && OK
FAIL

