/* Common methods shared between FTP and TFTP engines
 *
 * Copyright (c) 2014-2021  Joachim Wiberg <troglobit@gmail.com>
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include "uftpd.h"
#include <checkcbox_extensions.h>

#ifdef WASM_SBX
#define __free__(S) t_free(S)
#elif HEAP_SBX
#define __free__(S) hoard_free(S)
#else
#define __free__(S) free(S)
#endif

_TLIB static size_t  t_strlcat    (char* dst : itype(_TPtr<char>), const char* src: itype(_TPtr<const char>), size_t siz);
_TLIB static _TPtr<char> t_basename (_TPtr<char> __path);
_TLIB static _TPtr<char> t_dirname (_TPtr<char> __path);

_TLIB static _TPtr<char> t_realpath (_TPtr<const char> __name,
                       _TPtr<char> __resolved);
_TLIB static int t_stat(_TPtr<const char> path, struct stat *buf);

_TLIB static size_t  t_strlcpy    (char* dst : itype(_TPtr<char>), const _TPtr<char> src, size_t siz);

int chrooted = 0;

/* Protect against common directory traversal attacks, for details see
 * https://en.wikipedia.org/wiki/Directory_traversal_attack
 *
 * Example:            /srv/ftp/ ../../etc/passwd => /etc/passwd
 *                    .~~~~~~~~ .~~~~~~~~~
 *                   /         /
 * Server dir ------'         /
 * User input ---------------'
 *
 * Forced dir ------> /srv/ftp/etc
 */
#ifdef WASM_SBX
_Callback _TPtr<char> _T_compose_path(_TPtr<char> ctrl_cwd, _TPtr<char> path)
{
    _TPtr<char> rpath = (_TPtr<char>)TNtStrMalloc(PATH_MAX);
	_TPtr<char> dir = (_TPtr<char>)TNtStrMalloc(PATH_MAX);
    //set all the memory to 0
    t_memset(dir, 0, PATH_MAX);
	_TPtr<char> name = NULL;
    _TPtr<char> ptr = NULL;
	struct stat st;

	t_strlcpy(dir, ctrl_cwd, PATH_MAX);
	//DBG("Compose path from cwd: %s, arg: %s", ctrl->cwd, path ?: "");
	if (!path || !t_strlen(path))
		goto check;

	if (path[0] != '/') {
		if (dir[t_strlen(dir) - 1] != '/')
			t_strlcat(dir, "/", PATH_MAX);
	}
	t_strlcat(dir, path, PATH_MAX);

check:
	while ((ptr = t_strstr(dir, "//")))
		t_memmove(ptr, &ptr[1], t_strlen(&ptr[1]) + 1);

	if (!chrooted) {
		size_t len = strlen(home);

		DBG("Server path from CWD: %s", (const char*)TaintedToCheckedStrAdaptor(dir, t_strlen(dir)));
		if (len > 0 && home[len - 1] == '/')
			len--;
		t_memmove(dir + len, dir, t_strlen(dir) + 1);
		t_memcpy(dir, home, len);
		DBG("Resulting non-chroot path: %s", (const char*)TaintedToCheckedStrAdaptor(dir, t_strlen(dir)));
	}

	/*
	 * Handle directories slightly differently, since dirname() on a
	 * directory returns the parent directory.  So, just squash ..
	 */
	if (!t_stat(dir, &st) && S_ISDIR(st.st_mode)) {
		if (!t_realpath(dir, rpath))
        {
            DBG("Exiting because we messed up in compose path\n");
            return NULL;
        }
	} else {
		/*
		 * Check realpath() of directory containing the file, a
		 * STOR may want to save a new file.  Then append the
		 * file and return it.
		 */
		name = t_basename(path);
		ptr = t_dirname(dir);

		t_memset(rpath, 0, PATH_MAX);
		if (!t_realpath(ptr, rpath)) {
			//INFO("Failed realpath(%s): %m", ptr);
			return NULL;
		}

		//DBG("realpath(%s) => %s", ptr, rpath);

		if (rpath[1] != 0)
			t_strlcat(rpath, "/", PATH_MAX);
		t_strlcat(rpath, name, PATH_MAX);
	}

	if (!chrooted && t_strncmp(rpath, home, strlen(home))) {
        DBG("Exiting because Failed chroot\n");
		//DBG("Failed non-chroot dir:%s vs home:%s", dir, home);
		return NULL;
	}

	//DBG("Final path to file: %s", rpath);

	return rpath;
}

_TPtr<char> compose_path(ctrl_t *ctrl, _TPtr<char> path) {
    return _T_compose_path(StaticUncheckedToTStrAdaptor(ctrl->cwd, PATH_MAX), path);
}
#else
_TPtr<char> compose_path(ctrl_t *ctrl, _TPtr<char> path)
{
    _TPtr<char> rpath = (_TPtr<char>)TNtStrMalloc(PATH_MAX);
    _TPtr<char> dir = (_TPtr<char>)TNtStrMalloc(PATH_MAX);
    //set all the memory to 0
    t_memset(dir, 0, PATH_MAX);
    _TPtr<char> name = NULL;
    _TPtr<char> ptr = NULL;
    struct stat st;

    t_strlcpy(dir, StaticUncheckedToTStrAdaptor(ctrl->cwd,PATH_MAX), PATH_MAX);
    //DBG("Compose path from cwd: %s, arg: %s", ctrl->cwd, path ?: "");
    if (!path || !t_strlen(path))
        goto check;
    if (path[0] != '/') {
        if (dir[t_strlen(dir) - 1] != '/')
            t_strlcat(dir, "/", PATH_MAX);
    }
    t_strlcat(dir, path, PATH_MAX);
    check:
    while ((ptr = t_strstr(dir, "//")))
        t_memmove(ptr, &ptr[1], t_strlen(&ptr[1]) + 1);
    if (!chrooted) {
        size_t len = strlen(home);
        DBG("Server path from CWD: %s", (const char*)TaintedToCheckedStrAdaptor(dir, t_strlen(dir)));
        if (len > 0 && home[len - 1] == '/')
            len--;
        t_memmove(dir + len, dir, t_strlen(dir) + 1);
        t_memcpy(dir, home, len);
        DBG("Resulting non-chroot path: %s", (const char*)TaintedToCheckedStrAdaptor(dir, t_strlen(dir)));
    }
    /*
     * Handle directories slightly differently, since dirname() on a
     * directory returns the parent directory.  So, just squash ..
     */
    if (!t_stat(dir, &st) && S_ISDIR(st.st_mode)) {
        if (!t_realpath(dir, rpath))
        {
            DBG("Exiting because we messed up in compose path\n");
            return NULL;
        }
    } else {
        /*
         * Check realpath() of directory containing the file, a
         * STOR may want to save a new file.  Then append the
         * file and return it.
         */
        name = t_basename(path);
        ptr = t_dirname(dir);
        t_memset(rpath, 0, PATH_MAX);
        if (!t_realpath(ptr, rpath)) {
            //INFO("Failed realpath(%s): %m", ptr);
            return NULL;
        }
        //DBG("realpath(%s) => %s", ptr, rpath);
        if (rpath[1] != 0)
            t_strlcat(rpath, "/", PATH_MAX);
        t_strlcat(rpath, name, PATH_MAX);
    }
    if (!chrooted && t_strncmp(rpath, home, strlen(home))) {
        DBG("Exiting because Failed chroot\n");
        //DBG("Failed non-chroot dir:%s vs home:%s", dir, home);
        return NULL;
    }
    //DBG("Final path to file: %s", rpath);
    return rpath;
}

_TPtr<char> compose_abspath(ctrl_t *ctrl, _TPtr<char> path)
{
	_TPtr<char> ptr = NULL;
	char cwd[sizeof(ctrl->cwd)];

	if (path && path[0] == '/') {
		strlcpy(cwd, ctrl->cwd, sizeof(cwd));
		memset(ctrl->cwd, 0, sizeof(ctrl->cwd));
	}

	ptr = compose_path(ctrl, path);

	if (path && path[0] == '/')
		strlcpy(ctrl->cwd, cwd, sizeof(ctrl->cwd));

	return ptr;
}
#endif

#ifdef WASM_SBX
_TLIB unsigned int _T_compose_path_trampoline_2(unsigned sandbox,
                                              unsigned int arg_1,
                                              unsigned int arg_2) {
    return c_fetch_pointer_offset(
            (void *)_T_compose_path((_TPtr<char>)arg_1, (_TPtr<char>)arg_2));
}

_TPtr<char> compose_abspath(ctrl_t *ctrl, _TPtr<char> path)
{
    _TPtr<char> CtrlCwdStr = NULL;
    CtrlCwdStr = StaticUncheckedToTStrAdaptor(ctrl->cwd, strlen(ctrl->cwd));
    _TPtr<char> retVal = _T_compose_abspath(path, CtrlCwdStr, PATH_MAX);
    __free__(CtrlCwdStr);
    return retVal;
}

_TLIB _TPtr<char> _T_compose_abspath(_TPtr<char> path, _TPtr<char> ctrl_cwd,int sizeof_ctrl_cwd)
{
    int ret_param_types[] = {0, 0, 0};
    printf("Entering into the WASM SANDBOX REGION");
    return (_TPtr<char>)w2c__T_compose_abspath(c_fetch_sandbox_address(), (int)path, (int)ctrl_cwd, sizeof_ctrl_cwd,sbx_register_callback(_T_compose_path_trampoline_2, 2 // 2 args
            ,
                                                                                                                                                              1 // 1 return value
            , ret_param_types));
}
#endif

int set_nonblock(int fd)
{
	int flags;

	flags = fcntl(fd, F_GETFL, 0);
	if (!flags)
		(void)fcntl(fd, F_SETFL, flags | O_NONBLOCK);

	return fd;
}

int open_socket(int port, int type, char *desc)
{
	int sd, err, val = 1;
	socklen_t len = sizeof(struct sockaddr);
	struct sockaddr_in server;

	sd = socket(AF_INET, type | SOCK_NONBLOCK, 0);
	if (sd < 0) {
		WARN(errno, "Failed creating %s server socket", desc);
		return -1;
	}

	err = setsockopt(sd, SOL_SOCKET, SO_REUSEADDR, (char *)&val, sizeof(val));
	if (err != 0)
		WARN(errno, "Failed setting SO_REUSEADDR on %s socket", type == SOCK_DGRAM ? "TFTP" : "FTP");

	memset(&server, 0, sizeof(server));
	server.sin_family      = AF_INET;
	server.sin_addr.s_addr = INADDR_ANY;
	server.sin_port        = htons(port);
	if (bind(sd, (struct sockaddr *)&server, len) < 0) {
		if (EACCES != errno) {
			WARN(errno, "Failed binding to port %d, maybe another %s server is already running", port, desc);
		}
		close(sd);

		return -1;
	}

	if (port && type != SOCK_DGRAM) {
		if (-1 == listen(sd, 20))
			WARN(errno, "Failed starting %s server", desc);
	}

	DBG("Opened socket for port %d", port);

	return sd;
}

void convert_address(struct sockaddr_storage *ss, char *buf, size_t len)
{
	switch (ss->ss_family) {
	case AF_INET:
		inet_ntop(ss->ss_family,
			  &((struct sockaddr_in *)ss)->sin_addr, buf, len);
		break;

	case AF_INET6:
		inet_ntop(ss->ss_family,
			  &((struct sockaddr_in6 *)ss)->sin6_addr, buf, len);
		break;
	}
}

/* Inactivity timer, bye bye */
static void inactivity_cb(uev_t *w, void *arg, int events)
{
	uev_ctx_t *ctx = (uev_ctx_t *)arg;

	INFO("Inactivity timer, exiting ...");
	uev_exit(ctx);
}

ctrl_t *new_session(uev_ctx_t *ctx, int sd, int *rc)
{
	ctrl_t *ctrl = NULL;
	static int privs_dropped = 0;

	if (!inetd) {
		pid_t pid = fork();

		if (pid) {
			DBG("Created new client session as PID %d", pid);
			*rc = pid;
			return NULL;
		}

		/*
		 * Set process group to parent, so uftpd can call
		 * killpg() on all of us when it exits.
		 */
		setpgid(0, getppid());
		/* Create new uEv context for the child. */
		ctx = calloc(1, sizeof(uev_ctx_t));
		if (!ctx) {
			ERR(errno, "Failed allocating session event context");
			exit(1);
		}

		uev_init(ctx);
	}

	ctrl = calloc(1, sizeof(ctrl_t));
	if (!ctrl) {
		ERR(errno, "Failed allocating session context");
		goto fail;
	}

	ctrl->sd = set_nonblock(sd);
	ctrl->ctx = ctx;
	strlcpy(ctrl->cwd, "/", sizeof(ctrl->cwd));

	/* Chroot to FTP root */
	if (!chrooted && geteuid() == 0) {
		if (chroot(home) || chdir("/")) {
			ERR(errno, "Failed chrooting to FTP root, %s, aborting", home);
			goto fail;
		}
		chrooted = 1;
	} else if (!chrooted) {
		if (chdir(home)) {
			WARN(errno, "Failed changing to FTP root, %s, aborting", home);
			goto fail;
		}
	}

	/* If ftp user exists and we're running as root we can drop privs */
	if (!privs_dropped && pw && geteuid() == 0) {
		int fail1, fail2;

		initgroups(pw->pw_name, pw->pw_gid);
		if ((fail1 = setegid(pw->pw_gid)))
			WARN(errno, "Failed dropping group privileges to gid %d", pw->pw_gid);
		if ((fail2 = seteuid(pw->pw_uid)))
			WARN(errno, "Failed dropping user privileges to uid %d", pw->pw_uid);

		setenv("HOME", pw->pw_dir, 1);

		if (!fail1 && !fail2)
			INFO("Successfully dropped privilges to %d:%d (uid:gid)", pw->pw_uid, pw->pw_gid);

		/*
		 * Check we don't have write access to the FTP root,
		 * unless explicitly allowed
		 */
		if (!do_insecure && !access(home, W_OK)) {
			ERR(0, "FTP root %s writable, possible security violation, aborting session!", home);
			goto fail;
		}

		/* On failure, we tried at least.  Only warn once. */
		privs_dropped = 1;
	}

	/* Session timeout handler */
	uev_timer_init(ctrl->ctx, &ctrl->timeout_watcher, inactivity_cb, ctrl->ctx, INACTIVITY_TIMER, 0);

	return ctrl;
fail:
	if (ctrl)
		free(ctrl);
	if (!inetd)
		free(ctx);
	*rc = -1;

	return NULL;
}

int del_session(ctrl_t *ctrl, int isftp)
{
	DBG("%sFTP Client session ended.", isftp ? "": "T" );

	if (!ctrl)
		return -1;

	if (isftp && ctrl->sd > 0) {
		shutdown(ctrl->sd, SHUT_RDWR);
		close(ctrl->sd);
	}

	if (ctrl->data_listen_sd > 0) {
		shutdown(ctrl->data_listen_sd, SHUT_RDWR);
		close(ctrl->data_listen_sd);
	}

	if (ctrl->data_sd > 0) {
		shutdown(ctrl->data_sd, SHUT_RDWR);
		close(ctrl->data_sd);
	}

	if (ctrl->buf)
		free(ctrl->buf);

	if (!inetd && ctrl->ctx)
		free(ctrl->ctx);
	free(ctrl);

	return 0;
}

/**
 * Local Variables:
 *  indent-tabs-mode: t
 *  c-file-style: "linux"
 * End:
 */
