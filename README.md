## CheckCBOX -->
### The configure goes as -->
```
./configure 
CC=<Checkcbox-clang> 
CFLAGS="-fw2c_sbx" 
LDFLAGS=-L<Checkcbox_LIBS> 
LIBS="-ldl -lstdc++ -lSBX_CON_LIB -lisc_lib_final -lTLIBDefs"
```

####  All about WASM Libs 
--> checkcbox-uftpd/Checkcbox_LIBS --> that holds all of the WASM dependencies needed for uftpd to function 
##### Below is the directory tree

libisc_lib_final.a --> WASM Dependencies along with symbol definitions for WASM Sandboxed functions  

libisc_lib_final.so  

libSBX_CON_LIB.a --> Tainted STD Library support --> Does nothing WASM specific --> Just a wrapper to call std functions

#### Example --> 
t_strncpy is defined as a symbol in the above library that just does this --> t_strncpy(args...) { strcpy(args...)}

libTLIBDefs.a --> uftpd specific library symbol definitions -->
Like I said, if you have your own library functions(that do not add/remove/modify memory, ex strncpy) which you want to call with tainted pointers 
--> You gotta define a wrapper function and define the symbol definition (indirected call to original function) in a seperate file and compile and link it as a static library 
--> example, if you want to call myCustomStrncpy(args..) with tainted args --> (targs..) --> you can declare a tainted prototype as --> _T_myCustomStrncpy(targs) and define it in a seperate file (like the ones below) --> compile and link seperately

TaintedLibWrappers.c --> wrappers to calls to custom library functions 
TaintedLibWrappers.h 

Compile the above with --> 
```
clang -c -I/usr/include/x86_64-linux-gnu/  -I/usr/include/ -I/usr/local/include/libite TaintedLibWrappers.c -o TaintedLibWrappers.o
ar rcs libTLIBDefs.a TaintedLibWrappers.o
```

No Nonsense FTP/TFTP Server
===========================
[![License Badge][]][License] [![GitHub Status][]][GitHub] [![Coverity Status][]][Coverity Scan]

uftpd is a UNIX daemon with sane built-in defaults.  It just works.


Features
--------

* FTP and/or TFTP
* No complex configuration file
* Runs from standard UNIX inetd, or standalone
* Uses `ftp` user's `$HOME`, from `/etc/passwd`, or custom path
* Uses `ftp/tcp` and `tftp/udp` from `/etc/services`, or custom ports
* Privilege separation, drops root privileges having bound to ports
* Possible to use symlinks outside of the FTP home directory
* Possible to have group writable FTP home directory


Usage
-----

```
uftpd [-hnsv] [-l LEVEL] [-o OPTS] [PATH]

  -h         Show this help text
  -l LEVEL   Set log level: none, err, notice (default), info, debug
  -n         Run in foreground, do not detach from controlling terminal
  -o OPT     Options:
                      ftp=PORT
                      tftp=PORT
                      pasv_addr=ADDR
                      writable
  -s         Use syslog, even if running in foreground, default w/o -n
  -v         Show program version

The optional 'PATH' defaults to the $HOME of the /etc/passwd user 'ftp'
Bug report address: https://github.com/troglobit/uftpd/issues
```

To start uftpd in the background as an FTP/TFTP server:

    uftpd

If the `ftp` user does not exist on your system, `uftpd` defaults to
serve files from the `/srv/ftp` directory.  To serve another directory,
simply append that directory to the argument list.

Use `sudo`, or set `CAP_NET_BIND_SERVICE` capabilities, on `uftpd` to
allow regular users to start `uftpd` on privileged (standard) ports,
i.e. `< 1024`:

    sudo setcap cap_net_bind_service+ep uftpd

To change port on either FTP or TFTP, use:

    uftpd -o ftp=PORT,tftp=PORT

Set `PORT` to zero (0) to disable either service.

New sessions are droppbed by default if uftpd detects the FTP root is
writable.  To allow writable FTP root:

    uftpd -o writable PATH

> **Note:** since v2.11 uftpd logs a lot more events by default.  Set up
> your syslogd to redirect `LOG_FTP` to a separate log file, or reduce
> the log level of uftpd using `-l error` to only log errors and higher.


Running from inetd
------------------

Rarely used services like FTP/TFTP are good candidates to run from the
Internet super server, inetd.  On Debian and Ubuntu based distributions
we recommend `openbsd-inetd`.

Use the following two lines in `/etc/inetd.conf`, notice how `in.ftpd`
and `in.tftpd` are symlinks to the `uftpd` binary:

    ftp     stream  tcp nowait  root    /usr/sbin/in.ftpd
    tftp    dgram   udp wait    root    /usr/sbin/in.tftpd

Remember to activate your changes to inetd by reloading the service or
sending `SIGHUP` to it.  Another inetd server may use different syntax.
Like the inetd that comes built-in to [Finit][], in `/etc/finit.conf`:

    inetd ftp/tcp   nowait /usr/sbin/in.ftpd  -- The uftpd FTP server
    inetd tftp/udp    wait /usr/sbin/in.tfptd -- The uftpd TFTP server


Caveat
------

uftpd is primarily not targeted at secure installations, it is targeted
at users in need of a *simple* FTP/TFTP server.

uftpd allows symlinks outside the FTP root, as well as a group writable
FTP home directory &mdash; user-friendly features that potentially can
cause security breaches, but also very useful for people who just want
their FTP server to work.  A lot of care has been taken, however, to
lock down and secure uftpd by default.


Build & Install
---------------

### Debian/Ubuntu

    curl -sS https://deb.troglobit.com/pubkey.gpg | sudo apt-key add -
    echo "deb [arch=amd64] https://deb.troglobit.com/debian stable main" | sudo tee /etc/apt/sources.list.d/troglobit.list
    sudo apt-get update && sudo apt-get install uftpd

### Building from Source

`uftpd` depends on two other projects to build from source, [libuEv][]
and [lite][].  See their respective README for details, there should be
no real surprises, both use the familiar configure, make, make install.

To find the two libraries uftpd depends on `pkg-config`.  The package
name for your Linux distribution varies, on Debian/Ubuntu systems:

```shell
user@example:~/> sudo apt install pkg-config
```

uftpd, as well as its dependencies, can be built as `.deb` packages on
Debian or Ubuntu based distributions.  Download and install each of the
dependencies, and then run

    ./autogen.sh      <--- Only needed if using GIT sources
    ./configure
    make package

The `.deb` package takes care of setting up `/etc/inetd.conf`, create an
`ftp` user and an `/srv/ftp` home directory with write permissions for
all members of the `users` group.

If you are using a different Linux or UNIX distribution, check the
output from `./configure --help`, followed by `make all install`.
For instance, building on [Alpine Linux](https://alpinelinux.org/):

    PKG_CONFIG_LIBDIR=/usr/local/lib/pkgconfig ./configure \
	    --prefix=/usr --localstatedir=/var --sysconfdir=/etc

Provided the library dependencies were installed in `/usr/local/`.  This
`PKG_CONFIG_LIBDIR` trick may be needed on other GNU/Linux, or UNIX,
distributions as well.


Origin & References
-------------------

uftpd was originally based on [FtpServer][] by [Xu Wang][], but is now a
complete rewrite with TFTP support by [Joachim Wiberg][], maintained at
[GitHub][home].


[Joachim Wiberg]: http://troglobit.com
[the FTP]:         http://ftp.troglobit.com/uftpd/
[Xu Wang]:         https://github.com/xu-wang11/
[FtpServer]:       https://github.com/xu-wang11/FtpServer
[home]:            https://github.com/troglobit/uftpd
[Finit]:           https://github.com/troglobit/finit
[lite]:            https://github.com/troglobit/libite
[libuEv]:          https://github.com/troglobit/libuev
[License]:         https://en.wikipedia.org/wiki/ISC_license
[License Badge]:   https://img.shields.io/badge/License-ISC-blue.svg
[GitHub]:          https://github.com/troglobit/uftpd/actions/workflows/build.yml/
[GitHub Status]:   https://github.com/troglobit/uftpd/actions/workflows/build.yml/badge.svg
[Coverity Scan]:   https://scan.coverity.com/projects/2947
[Coverity Status]: https://scan.coverity.com/projects/2947/badge.svg
