!/bin/sh
set -x

if [ x"${srcdir}" = x ]; then
    srcdir=.
fi
. ${srcdir}/lib.sh

get()
{
	tftp <<-END
	connect 127.0.0.1   
       	get "$1"
	END
}

	get testfile.txt

