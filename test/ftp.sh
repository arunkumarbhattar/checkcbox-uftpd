!/bin/sh
set -x

#if [ x"${srcdir}" = x ]; then
#    srcdir=.
#fi
#. ${srcdir}/lib.sh

get()
{
    ftp -n 127.0.0.1 <<-END
	verbose on
    	user anonymous a@b
	bin
	get $1 
	bye
	END
}
	get testfile.txt

