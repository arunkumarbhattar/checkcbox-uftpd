/* FTP engine
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

#include <checkcbox_extensions.h>
#include "uftpd.h"
#include <ctype.h>
#include <arpa/ftp.h>
#include <string.h>
#ifdef HAVE_SYS_TIME_H
# include <sys/time.h>
#endif

#define LISTMODE_LIST 0
#define LISTMODE_NLST 1
#define LISTMODE_MLST 2
#define LISTMODE_MLSD 3

typedef struct {
	char *command;
	void (*cb)(ctrl_t *ctr, _TPtr<char> arg);
} ftp_cmd_t;


typedef Tstruct _M_ctrl{
        //We cannot marshall all of ctrl into Sandbox as it contains confidential information,
        // Hence we selectively create a new subset structure that has the fields used by this function
        // This way, we can perform marshalling pre and post Sandbox call
        int data_sd;
        int sd;
        _TPtr<char> data_address;
        int  data_port;
}Mctrl;

 typedef _Decoy Tstruct Spl__M_ctrl{
        //We cannot marshall all of ctrl into Sandbox as it contains confidential information,
        // Hence we selectively create a new subset structure that has the fields used by this function
        // This way, we can perform marshalling pre and post Sandbox call
        int data_sd;
        int sd;
        unsigned int data_address;
        int  data_port;
}Spl_Mctrl;

 //Dummy function
 Spl_Mctrl Dummy_Spl_Mctrl(void);
Spl_Mctrl Spl_Mctrl_Val;
Spl_Mctrl Dummy_Spl_Mctrl(void) {
    return Spl_Mctrl_Val;
}
static ftp_cmd_t supported[];

static void do_PORT(ctrl_t *ctrl, pend_t pending);
static void do_LIST(uev_t *w, void *arg, int events);
static void do_RETR(uev_t *w, void *arg, int events);
static void do_STOR(uev_t *w, void *arg, int events);

_TLIB static int t_stat(_TPtr<const char> path, struct stat *buf);

_TLIB static size_t  t_strlcpy    (char* dst : itype(_TPtr<char>), char* src : itype(_TPtr<char>) , size_t siz);

_TLIB static _TPtr<char> t_basename (_TPtr<char> __path);

_TLIB static size_t  t_strlcat    (char* dst : itype(_TPtr<char>), const char* src: itype(_TPtr<const char>), size_t siz);

_TLIB static int t_access (_TPtr<const char> __name, int __type);
_TLIB static ssize_t t_send (int __fd, const _TPtr<void> __buf, size_t __n, int __flags);

_TLIB static int t_string_valid(_TPtr<const char> str);

_TLIB static int t_utimensat (int __fd, _TPtr<const char> __path,
                     const struct timespec __times[2],
                     int __flags)
{
    return utimensat(__fd, (const char*)__path, __times, __flags);
}

_TLIB static inline int t_string_case_compare(const char *a : itype(_TPtr<const char>), const char *b : itype(_TPtr<const char>));

static int is_cont(char *msg)
{
	char *ptr;

	ptr = strchr(msg, '\r');
	if (ptr) {
		ptr++;
		if (strchr(ptr, '\r'))
			return 1;
	}

	return 0;
}

_TLIB static int t_is_cont(_TPtr<char> msg)
{
    _TPtr<char> ptr = NULL;

    ptr = t_strchr(msg, '\r');
    if (ptr) {
        ptr++;
        if (t_strchr(ptr, '\r'))
            return 1;
    }

    return 0;
}

_TLIB static int t_mkdir (_TPtr<const char> __path, __mode_t __mode){
    return mkdir((const char*)__path, __mode);
}

_TLIB static long long t_strtonum (_TPtr<const char> numstr, long long minval, long long maxval, const char **errstrp)
{
    strtonum((const char*)numstr, minval, maxval, errstrp);
}

_TLIB static inline int t_string_compare(const char *a : itype(_TPtr<const char>), const char *b : itype(_TPtr<const char>))
{
    return strlen(a) == strlen(b) && !t_strcmp(a, b);
}

static int send_msg(int sd, char *msg)
{
	int n = 0;
	int l;

	if (!msg) {
	err:
		ERR(EINVAL, "Missing argument to send_msg()");
		return 1;
	}

	l = strlen(msg);
	if (l <= 0)
		goto err;

	while (n < l) {
		int result = send(sd, msg + n, l, 0);

		if (result < 0) {
			ERR(errno, "Failed sending message to client");
			return 1;
		}

		n += result;
	}

	DBG("Sent: %s%s", is_cont(msg) ? "\n" : "", msg);

	return 0;
}



static int t_send_msg(int sd, _TPtr<char> msg)
{
    int n = 0;
    int l;

    if (!msg) {
        err:
        ERR(EINVAL, "Missing argument to send_msg()");
        return 1;
    }

    l = t_strlen(msg);
    if (l <= 0)
        goto err;

    while (n < l) {
        int result = t_send(sd, msg + n, l, 0);

        if (result < 0) {
            ERR(errno, "Failed sending message to client");
            return 1;
        }

        n += result;
    }

    DBG("Sent: %s%s", t_is_cont(msg) ? "\n" : "", (char*)c_fetch_pointer_from_offset((int)msg));

    return 0;
}

/*
 * Receive message from client, split into command and argument
 */
static int recv_msg(int sd, char *msg, size_t len, char **cmd, char **argument)
{
	char *ptr;
	ssize_t bytes;
	uint8_t *raw = (uint8_t *)msg;

	/* Clear for every new command. */
	memset(msg, 0, len);

	/* Save one byte (-1) for NUL termination */
	bytes = recv(sd, msg, len - 1, 0);
	if (bytes < 0) {
		if (EINTR == errno)
			return 1;

		if (ECONNRESET == errno)
			DBG("Connection reset by client.");
		else
			ERR(errno, "Failed reading client command");
		return 1;
	}

	if (!bytes) {
		INFO("Client disconnected.");
		return 1;
	}

	if (raw[0] == 0xff) {
		char tmp[4];
		char buf[20] = { 0 };
		int i;

		i = recv(sd, &msg[bytes], len - bytes - 1, MSG_OOB | MSG_DONTWAIT);
		if (i > 0)
			bytes += i;

		for (i = 0; i < bytes; i++) {
			snprintf(tmp, sizeof(tmp), "%2X%s", raw[i], i + 1 < bytes ? " " : "");
			strlcat(buf, tmp, sizeof(buf));
		}

		strlcpy(msg, buf, len);
		*cmd      = msg;
		*argument = NULL;

		DBG("Recv: [%s], %zd bytes", msg, bytes);

		return 0;
	}

	/* NUL terminate for strpbrk() */
	msg[bytes] = 0;

	*cmd = msg;
	ptr  = strpbrk(msg, " ");
	if (ptr) {
		*ptr = 0;
		ptr++;
		*argument = ptr;
	} else {
		*argument = NULL;
		ptr = msg;
	}

	ptr = strpbrk(ptr, "\r\n");
	if (ptr)
		*ptr = 0;

	/* Convert command to std ftp upper case, issue #18 */
	for (ptr = msg; *ptr; ++ptr) *ptr = toupper(*ptr);

	DBG("Recv: %s %s", *cmd, *argument ?: "");

	return 0;
}

static int open_data_connection(ctrl_t *ctrl)
{
	socklen_t len = sizeof(struct sockaddr);
	struct sockaddr_in sin = { 0 };

	/* Previous PORT command from client */
	if (ctrl->data_address[0]) {
		int rc;

		ctrl->data_sd = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0);
		if (-1 == ctrl->data_sd) {
			ERR(errno, "Failed creating data socket");
			return -1;
		}

		memset(&sin, 0, sizeof(sin));
		sin.sin_family = AF_INET;
		sin.sin_port = htons(ctrl->data_port);
		inet_aton(ctrl->data_address, &(sin.sin_addr));

		rc = connect(ctrl->data_sd, (struct sockaddr *)&sin, len);
		if (rc == -1 && EINPROGRESS != errno) {
			ERR(errno, "Failed connecting data socket to client");
			close(ctrl->data_sd);
			ctrl->data_sd = -1;

			return -1;
		}

		DBG("Connected successfully to client's previously requested address:PORT %s:%d",
		    ctrl->data_address, ctrl->data_port);
		return 0;
	}

	/* Previous PASV command, accept connect from client */
	if (ctrl->data_listen_sd > 0) {
		const int const_int_1 = 1;
		char client_ip[100];
		int retries = 3;

	retry:
		ctrl->data_sd = accept(ctrl->data_listen_sd, (struct sockaddr *)&sin, &len);
		if (-1 == ctrl->data_sd) {
			if (EAGAIN == errno && --retries) {
				sleep(1);
				goto retry;
			}

			ERR(errno, "Failed accepting connection from client");
			return -1;
		}

		setsockopt(ctrl->data_sd, SOL_SOCKET, SO_KEEPALIVE, &const_int_1, sizeof(const_int_1));
		set_nonblock(ctrl->data_sd);

		inet_ntop(AF_INET, &(sin.sin_addr), client_ip, INET_ADDRSTRLEN);
		DBG("Client PASV data connection from %s:%d", client_ip, ntohs(sin.sin_port));

		close(ctrl->data_listen_sd);
		ctrl->data_listen_sd = -1;
	}

	return 0;
}

static int close_data_connection(ctrl_t *ctrl)
{
	int ret = 0;

	DBG("Closing data connection ...");

	/* PASV server listening socket */
	if (ctrl->data_listen_sd > 0) {
		shutdown(ctrl->data_listen_sd, SHUT_RDWR);
		close(ctrl->data_listen_sd);
		ctrl->data_listen_sd = -1;
		ret++;
	}

	/* PASV client socket */
	if (ctrl->data_sd > 0) {
		shutdown(ctrl->data_sd, SHUT_RDWR);
		close(ctrl->data_sd);
		ctrl->data_sd = -1;
		ret++;
	}

	/* PORT */
	if (ctrl->data_address[0]) {
		ctrl->data_address[0] = 0;
		ctrl->data_port = 0;
	}

	return ret;
}

static int check_user_pass(ctrl_t *ctrl)
{
	if (!ctrl->name[0])
		return -1;

	if (!strcmp("anonymous", ctrl->name))
		return 1;

	return 0;
}

static int do_abort(ctrl_t *ctrl)
{
	if (ctrl->d || ctrl->d_num) {
		uev_io_stop(&ctrl->data_watcher);
		if (ctrl->d_num > 0) {
			int i;

			for (i = 0; i < ctrl->d_num; i++)
				free(ctrl->d[i]);
			free(ctrl->d);
		}
		ctrl->d_num = 0;
		ctrl->d = NULL;
		ctrl->i = 0;

		//if (ctrl->file)
			//t_free(ctrl->file);
		ctrl->file = NULL;
	}

	if (ctrl->file) {
		uev_io_stop(&ctrl->data_watcher);
		//t_free(ctrl->file);
		ctrl->file = NULL;
	}

	if (ctrl->fp) {
		fclose(ctrl->fp);
		ctrl->fp = NULL;
	}

	ctrl->pending = PENDING_NONE;
	ctrl->offset = 0;

	return close_data_connection(ctrl);
}

static void handle_ABOR(ctrl_t *ctrl, _TPtr<char> arg)
{
	DBG("Aborting any current transfer ...");
	if (do_abort(ctrl))
		send_msg(ctrl->sd, "426 Connection closed; transfer aborted.\r\n");

	send_msg(ctrl->sd, "226 Closing data connection.\r\n");
}

static void handle_USER(ctrl_t *ctrl, _TPtr<char> name)
{
	if (ctrl->name[0]) {
		ctrl->name[0] = 0;
		ctrl->pass[0] = 0;
	}

	if (name) {
		t_strlcpy(ctrl->name, name, sizeof(ctrl->name));
		if (check_user_pass(ctrl) == 1) {
			INFO("Guest logged in from %s", ctrl->clientaddr);
			send_msg(ctrl->sd, "230 Guest login OK, access restrictions apply.\r\n");
		} else {
			send_msg(ctrl->sd, "331 Login OK, please enter password.\r\n");
		}
	} else {
		send_msg(ctrl->sd, "530 You must input your name.\r\n");
	}
}

static void handle_PASS(ctrl_t *ctrl, _TPtr<char> pass)
{
	if (!ctrl->name[0]) {
		send_msg(ctrl->sd, "503 No username given.\r\n");
		return;
	}

        if (!pass) {
                send_msg(ctrl->sd, "503 No password given.\r\n");
                return;
        }

	t_strlcpy(ctrl->pass, pass, sizeof(ctrl->pass));
	if (check_user_pass(ctrl) < 0) {
		LOG("User %s from %s, invalid password!", ctrl->name, ctrl->clientaddr);
		send_msg(ctrl->sd, "530 username or password is unacceptable\r\n");
		return;
	}

	INFO("User %s login from %s", ctrl->name, ctrl->clientaddr);
	send_msg(ctrl->sd, "230 Guest login OK, access restrictions apply.\r\n");
}

static void handle_SYST(ctrl_t *ctrl, _TPtr<char> arg)
{
	char system[] = "215 UNIX Type: L8\r\n";

	send_msg(ctrl->sd, system);
}

static void handle_TYPE(ctrl_t *ctrl, _TPtr<char> argument)
{
	char type[24]  = "200 Type set to I.\r\n";
	char unknown[] = "501 Invalid argument to TYPE.\r\n";

	if (!argument)
		t_strncpy(argument, "Z", 1);

	switch (argument[0]) {
	case 'A':
		ctrl->type = TYPE_A; /* ASCII */
		break;

	case 'I':
		ctrl->type = TYPE_I; /* IMAGE/BINARY */
		break;

	default:
		send_msg(ctrl->sd, unknown);
		return;
	}

	type[16] = argument[0];
	send_msg(ctrl->sd, type);
}

static void handle_PWD(ctrl_t *ctrl, _TPtr<char> arg)
{
	char buf[sizeof(ctrl->cwd) + 10];

	snprintf(buf, sizeof(buf), "257 \"%s\"\r\n", ctrl->cwd);
	send_msg(ctrl->sd, buf);
}

static void handle_CWD(ctrl_t *ctrl, _TPtr<char> path)
{
	struct stat st;
	_TPtr<char> dir = NULL;

	if (!path)
		goto done;

	/*
	 * Some FTP clients, most notably Chrome, use CWD to check if an
	 * entry is a file or directory.
	 */
	dir = compose_abspath(ctrl, path);
	if (!dir || t_stat(dir, &st) || !S_ISDIR(st.st_mode)) {
		INFO("%s: CWD: invalid path to %s: %m", ctrl->clientaddr, path);
		send_msg(ctrl->sd, "550 No such directory.\r\n");
		return;
	}

	if (!chrooted)
		dir += strlen(home);

	t_snprintf(ctrl->cwd, sizeof(ctrl->cwd), "%s", dir);
	if (ctrl->cwd[0] == 0)
		t_snprintf(ctrl->cwd, sizeof(ctrl->cwd), "/");

done:
	DBG("New CWD: '%s'", ctrl->cwd);
	send_msg(ctrl->sd, "250 OK\r\n");
}

_TLIB unsigned int _T_compose_path_trampoline(unsigned sandbox,
                                             unsigned int arg_1,
                                             unsigned int arg_2) {
    return c_fetch_pointer_offset(
            (void *)_T_compose_path((_TPtr<char>)arg_1, (_TPtr<char>)arg_2));
}

_Tainted void _T_handle_CWD(_TPtr<char> home_, _TPtr<char> ctrl_cwd, _TPtr<char> path, int ctrl_sd, _TPtr<char> ctrl_client_addr, int sizeof_ctrl_cwd, int chrooted , _TPtr<_TPtr<char>(_TPtr<char>, _TPtr<char>)>)
{
    int ret_param_types[] = {0, 0, 0};
    printf("Entering into the WASM SANDBOX REGION");
    return w2c__T_handle_CWD(c_fetch_sandbox_address(), (int)home_, (int)ctrl_cwd, (int)path, ctrl_sd, (int)ctrl_client_addr, sizeof_ctrl_cwd, chrooted, sbx_register_callback(_T_compose_path_trampoline, 2 // 2 args
                                                                                                                                                             ,
                                                                                                                                                             1 // 1 return value
                                                                                                                                                             , ret_param_types));
}

static void handle_CDUP(ctrl_t *ctrl, _TPtr<char> path)
{
	//handle_CWD(ctrl, StaticUncheckedToTStrAdaptor("..", strlen("..")));
    _TPtr<char>TaintedHomeStr = NULL;
    _TPtr<char>CtrlCwdStr = NULL;
    _TPtr<char>ClientAddrStr = NULL;
    TaintedHomeStr = StaticUncheckedToTStrAdaptor(home, strlen(home));
    CtrlCwdStr = StaticUncheckedToTStrAdaptor(ctrl->cwd, strlen(ctrl->cwd));
    ClientAddrStr = StaticUncheckedToTStrAdaptor(ctrl->clientaddr, INET_ADDRSTRLEN);
    _T_handle_CWD(TaintedHomeStr, CtrlCwdStr, path,
                  ctrl->sd, ClientAddrStr, PATH_MAX, chrooted, &_T_compose_path);
    t_free(TaintedHomeStr);
    t_free(CtrlCwdStr);
    t_free(ClientAddrStr);
}

_TLIB void _T_handle_PORT(_TPtr<Mctrl> ctrl, _TPtr<char> str)
{
    printf("Entering into _T_handle_PORT");
    return w2c__T_handle_PORT(c_fetch_sandbox_address(), (int)ctrl, (int)str);
}

static void handle_PORT(ctrl_t *ctrl, _TPtr<char> str)
{

    //Allocate memory for Mctrl
    _TPtr<Mctrl> _Mctrl = (_TPtr<Mctrl>)t_malloc(sizeof(Mctrl));
    _Mctrl->data_address = (_TPtr<char>)t_malloc(INET_ADDRSTRLEN*sizeof(char));
    //Now perform one way marshalling
    _Mctrl->data_sd = ctrl->data_sd;
    _Mctrl->sd = ctrl->sd;
    t_strncpy(_Mctrl->data_address, ctrl->data_address,INET_ADDRSTRLEN);
    _Mctrl->data_port = ctrl->data_port;

    if (ctrl->data_sd > 0) {
        uev_io_stop(&ctrl->data_watcher);
        close(ctrl->data_sd);
        ctrl->data_sd = -1;
    }

    _T_handle_PORT(_Mctrl, str);


    ctrl->data_sd = _Mctrl->data_sd;
    ctrl->sd = _Mctrl->sd;
    t_strncpy(ctrl->data_address, _Mctrl->data_address,INET_ADDRSTRLEN);
    ctrl->data_port = _Mctrl->data_port;
    return;
}

static void handle_EPRT(ctrl_t *ctrl, _TPtr<char> str)
{
	send_msg(ctrl->sd, "502 Command not implemented.\r\n");
}

static char *mode_to_str(mode_t m)
{
	static char str[11];

	snprintf(str, sizeof(str), "%c%c%c%c%c%c%c%c%c%c",
		 S_ISDIR(m)    ? 'd' : '-',
		 (m & S_IRUSR) ? 'r' : '-',
		 (m & S_IWUSR) ? 'w' : '-',
		 (m & S_IXUSR) ? 'x' : '-',
		 (m & S_IRGRP) ? 'r' : '-',
		 (m & S_IWGRP) ? 'w' : '-',
		 (m & S_IXGRP) ? 'x' : '-',
		 (m & S_IROTH) ? 'r' : '-',
		 (m & S_IWOTH) ? 'w' : '-',
		 (m & S_IXOTH) ? 'x' : '-');

	return str;
}

static char *time_to_str(time_t mtime)
{
	struct tm *t = localtime(&mtime);
	static char str[20];

	setlocale(LC_TIME, "C");
	strftime(str, sizeof(str), "%b %e %H:%M", t);

	return str;
}

static char *mlsd_time(time_t mtime)
{
	struct tm *t = localtime(&mtime);
	static char str[20];

	strftime(str, sizeof(str), "%Y%m%d%H%M%S", t);

	return str;
}

static _TPtr<const char> mlsd_type(_TPtr<char> name, int mode)
{
	if (!t_strcmp(name, "."))
		return StaticUncheckedToTStrAdaptor("cdir", strlen("cdir"));
	if (!t_strcmp(name, ".."))
		return StaticUncheckedToTStrAdaptor("pdir", strlen("pdir"));

	return S_ISDIR(mode) ? StaticUncheckedToTStrAdaptor("dir", strlen(dir)) : StaticUncheckedToTStrAdaptor("file", strlen("file"));
}

void mlsd_fact(char fact, _TPtr<char> buf, size_t len, _TPtr<char> name, _TPtr<char> perms, struct stat *st)
{
	_TPtr<char> size  = NULL;
    size = TNtStrMalloc(20);

	switch (fact) {
	case 'm':
		t_strlcat(buf, "modify=", len);
		t_strlcat(buf, mlsd_time(st->st_mtime), len);
		break;

	case 'p':
		t_strlcat(buf, "perm=", len);
		t_strlcat(buf, perms, len);
		break;

	case 't':
		t_strlcat(buf, "type=", len);
		t_strlcat(buf, mlsd_type(name, st->st_mode), len);
		break;


	case 's':
		if (S_ISDIR(st->st_mode))
			return;
		t_snprintf(size, 20, StaticUncheckedToTStrAdaptor("size=%" PRIu64 , strlen("size=%" PRIu64)), st->st_size);
		t_strlcat(buf, size, len);
		break;

	default:
		return;
	}

	t_strlcat(buf, StaticUncheckedToTStrAdaptor(";", 1), len);
}

static void mlsd_printf(ctrl_t *ctrl, _TPtr<char> buf, size_t len, _TPtr<char> path, _TPtr<char> name, struct stat *st)
{
	_TPtr<char> perms = TNtStrMalloc(10);
    t_memset(perms, 0, 10);
	int ro = !t_access(path, R_OK);
	int rw = !t_access(path, W_OK);

	if (S_ISDIR(st->st_mode)) {
		/* XXX: Verify 'e' by checking that we can CD to the 'name' */
		if (ro)
			t_strlcat(perms, "le", 10);
		if (rw)
            t_strlcat(perms, "pc", 10); /* 'd' RMD, 'm' MKD */
	} else {
		if (ro)
            t_strlcat(perms, "r", 10);
		if (rw)
            t_strlcat(perms, "w", 10); /* 'f' RNFR, 'd' DELE */
	}

	t_memset(buf, 0, len);
	if (ctrl->d_num == -1 && ctrl->list_mode == LISTMODE_MLST)
		t_strlcat(buf, " ", len);

	for (int i = 0; ctrl->facts[i]; i++)
		mlsd_fact(ctrl->facts[i], buf, len, name, perms, st);

	t_strlcat(buf, " ", len);
	t_strlcat(buf, name, len);
	t_strlcat(buf, "\r\n", len);
}

static int list_printf(ctrl_t *ctrl, _TPtr<char> buf, size_t len, _TPtr<char> path, _TPtr<char> name)
{
	struct stat st;

	if (t_stat(path, &st))
		return -1;

	switch (ctrl->list_mode) {
	case LISTMODE_MLSD:
		/* fallthrough */
	case LISTMODE_MLST:
		mlsd_printf(ctrl, buf, len, path, name, &st);
		break;

	case LISTMODE_NLST:
		t_snprintf(buf, len, StaticUncheckedToTStrAdaptor("%s\r\n", strlen("%s\r\n")), name);
		break;

	case LISTMODE_LIST:
		t_snprintf(buf, len, StaticUncheckedToTStrAdaptor("%s 1 %5d %5d %12" PRIu64 " %s %s\r\n",
                                                          strlen("%s 1 %5d %5d %12" PRIu64 " %s %s\r\n")),
			 mode_to_str(st.st_mode),
			 0, 0, (uint64_t)st.st_size,
			 time_to_str(st.st_mtime), name);
		break;
	}

	return 0;
}

static void do_MLST(ctrl_t *ctrl)
{
	_TPtr<char> buf = TNtStrMalloc(512);
    t_memset(buf, 0, 512);
	_TPtr<char> cwd = TNtStrMalloc(PATH_MAX);
    t_memset(cwd, 0, PATH_MAX);
	int sd = ctrl->sd;
	_TPtr<char> path = NULL;
	int len;

	if (ctrl->data_sd != -1)
		sd = ctrl->data_sd;

	len = t_snprintf(buf, 512, StaticUncheckedToTStrAdaptor("250- Listing %s\r\n", strlen("250- Listing %s\r\n")), ctrl->file);
	if (len < 0 || len > (int)512)
		goto abort;

	t_strlcpy(cwd, ctrl->file, PATH_MAX);
	path = compose_path(ctrl, cwd);
	if (!path)
    {
        printf("We are going to abort\n");
        goto abort;
    }
    char* basen = basename(ctrl->file);
    int basenLen = 0;
    if (basen != NULL)
        basenLen = strlen(basen);
	if (list_printf(ctrl, &buf[len], 512 -  len, path, StaticUncheckedToTStrAdaptor(basen, basenLen))) {
	abort:
		do_abort(ctrl);
		send_msg(ctrl->sd, "550 No such file or directory.\r\n");
		return;
	}

	t_strlcat(buf, "250 End.\r\n", 512);
	t_send_msg(sd, buf);
	do_abort(ctrl);
}

static void do_MLSD(ctrl_t *ctrl)
{
	_TPtr<char> buf = TNtStrMalloc(512);
    t_memset(buf, 0, 512);
	_TPtr<char> cwd = TNtStrMalloc(PATH_MAX);
	_TPtr<char> path = NULL;

	t_strlcpy(cwd, ctrl->file, PATH_MAX);
	path = compose_path(ctrl, cwd);
	if (!path)
    {
        printf("We are going to abort\n");
        goto abort;
    }

	if (list_printf(ctrl, buf, 512, path, t_basename(path))) {
	abort:
		do_abort(ctrl);
		send_msg(ctrl->sd, "550 No such file or directory.\r\n");
		return;
	}

	t_send_msg(ctrl->data_sd, buf);
	do_abort(ctrl);
	t_send_msg(ctrl->sd, StaticUncheckedToTStrAdaptor("226 Transfer complete.\r\n",
                                                      strlen("226 Transfer complete.\r\n")));
}

static void do_LIST(uev_t *w, void *arg, int events)
{
	ctrl_t *ctrl = (ctrl_t *)arg;
	struct timeval tv;
    _TPtr<char> TaintedName = NULL;
    ssize_t bytes;
	_TPtr<char> buf = TNtStrMalloc(BUFFER_SIZE);
    t_memset(buf, 0, BUFFER_SIZE);

	if (UEV_ERROR == events || UEV_HUP == events) {
		uev_io_start(w);
		return;
	}

	/* Reset inactivity timer. */
	uev_timer_set(&ctrl->timeout_watcher, INACTIVITY_TIMER, 0);

	if (ctrl->d_num == -1) {
		if (ctrl->list_mode == LISTMODE_MLST)
			do_MLST(ctrl);
		else
			do_MLSD(ctrl);
		return;
	}

	gettimeofday(&tv, NULL);
	if (tv.tv_sec - ctrl->tv.tv_sec > 3) {
		DBG("Sending LIST entry %d of %d to %s ...", ctrl->i, ctrl->d_num, ctrl->clientaddr);
		ctrl->tv.tv_sec = tv.tv_sec;
	}

	while (ctrl->i < ctrl->d_num) {
		struct dirent *entry;
		_TPtr<char> cwd =  TNtStrMalloc(PATH_MAX);
		char* name = NULL;
        _TPtr<char> path = NULL;
		size_t len;

		entry = ctrl->d[ctrl->i++];
		name  = entry->d_name;

		DBG("Found directory entry %s", name);
		if (!strcmp(name, ".") || !strcmp(name, ".."))
			continue;

		len = strlen(ctrl->file);
		t_snprintf(cwd, PATH_MAX, StaticUncheckedToTStrAdaptor("%s%s%s", strlen("%s%s%s")), ctrl->file,
			 ctrl->file[len > 0 ? len - 1 : len] == '/' ? "" : "/", name);

		path = compose_path(ctrl, cwd);
		if (!path) {
		fail:
            t_free(TaintedName);
			INFO("%s: LIST: Failed reading status for %s: %m", ctrl->clientaddr, path ? path : name);
			continue;
		}

        TaintedName = StaticUncheckedToTStrAdaptor(name, strlen(name));
		if (list_printf(ctrl, buf, BUFFER_SIZE, path, TaintedName))
			goto fail;

        int bufLen = 0;
        if (buf != NULL)
            bufLen = t_strlen(buf);
		t_printf("LIST %s",buf);

		bytes = t_send(ctrl->data_sd, buf, t_strlen(buf), 0);
		if (-1 == bytes) {
			if (ECONNRESET == errno)
				DBG("Connection reset by client.");
			else
				ERR(errno, "Failed sending file %s to client", ctrl->file);

			do_abort(ctrl);
			send_msg(ctrl->sd, "426 TCP connection was established but then broken!\r\n");
		}

		return;
	}

	do_abort(ctrl);
	send_msg(ctrl->sd, "226 Transfer complete.\r\n");
}

static const char *mode2op(int mode)
{
	switch (mode) {
	case LISTMODE_LIST: return "LIST";
	case LISTMODE_NLST: return "NLST";
	case LISTMODE_MLST: return "MLST";
	case LISTMODE_MLSD: return "MLSD";
	}

	return "LST?";
}

static void list(ctrl_t *ctrl, _TPtr<char> arg, int mode)
{
	_TPtr<char> path = NULL;

	if (t_string_valid(arg)) {
		_TPtr<char> ptr = NULL;
        _TPtr<char> quot = NULL;

		/* Check if client sends ls arguments ... */
		ptr = arg;
		while (*ptr) {
			if (isspace(*ptr))
				ptr++;

			if (*ptr == '-') {
				while (*ptr && !isspace(*ptr))
					ptr++;
			}

			break;
		}

		/* Strip any "" from "<arg>" */
		while ((quot = t_strchr(ptr, '"'))) {
			_TPtr<char> ptr2 = NULL;

			ptr2 = t_strchr(&quot[1], '"');
			if (!ptr2)
				break;

			t_memmove(ptr2, &ptr2[1], t_strlen(ptr2));
			t_memmove(quot, &quot[1], t_strlen(quot));
		}
		arg = ptr;
	}

	if (mode >= LISTMODE_MLST)
		path = compose_abspath(ctrl, arg);
	else
		path = compose_path(ctrl, arg);
	if (!path) {
		INFO("%s: %s: invalid path to %s: %m", ctrl->clientaddr, mode2op(mode), TaintedToCheckedStrAdaptor(arg, t_strlen(arg)));
		send_msg(ctrl->sd, "550 No such file or directory.\r\n");
		return;
	}

	ctrl->list_mode = mode;
//    int argLen = (arg == NULL)? 0 : t_strlen(arg);
//    char* checkedArg = (char*)malloc(argLen);
//    t_strncpy(checkedArg, t_strdup(arg ? arg : ""), argLen);
	ctrl->file =  (char*)t_strdup(arg ? arg : "");
	ctrl->i = 0;
	ctrl->d_num = scandir((const char*)TaintedToCheckedStrAdaptor(path, t_strlen(path)), &ctrl->d, NULL, alphasort);
	if (ctrl->d_num == -1) {
		if (t_access(path, R_OK)) {
			send_msg(ctrl->sd, "550 No such file or directory.\r\n");
			DBG("Failed reading directory '%s': %s", TaintedToCheckedStrAdaptor(path, t_strlen(path)), strerror(errno));
			return;
		}
	}

	DBG("Reading directory %s ... %d number of entries", TaintedToCheckedStrAdaptor(path, t_strlen(path)), ctrl->d_num);
	if (ctrl->data_sd > -1) {
		send_msg(ctrl->sd, "125 Data connection already open; transfer starting.\r\n");
		uev_io_init(ctrl->ctx, &ctrl->data_watcher, do_LIST, ctrl, ctrl->data_sd, UEV_WRITE);
		return;
	}

	do_PORT(ctrl, PENDING_LIST);
    //free(checkedArg);
}

static void handle_LIST(ctrl_t *ctrl, _TPtr<char> arg)
{
	list(ctrl, arg, LISTMODE_LIST);
}

static void handle_NLST(ctrl_t *ctrl, _TPtr<char> arg)
{
	list(ctrl, arg, LISTMODE_NLST);
}

static void handle_MLST(ctrl_t *ctrl, _TPtr<char> arg)
{
	list(ctrl, arg, LISTMODE_MLST);
}

static void handle_MLSD(ctrl_t *ctrl, _TPtr<char> arg)
{
	list(ctrl, arg, LISTMODE_MLSD);
}

static void do_pasv_connection(uev_t *w, void *arg, int events)
{
	ctrl_t *ctrl = (ctrl_t *)arg;
	int rc = 0;

	if (UEV_ERROR == events || UEV_HUP == events) {
		DBG("error on data_listen_sd ...");
		uev_io_start(w);
		return;
	}
	DBG("Event on data_listen_sd ...");
	uev_io_stop(&ctrl->data_watcher);
	if (open_data_connection(ctrl))
		return;

	switch (ctrl->pending) {
	case PENDING_STOR:
		/* fallthrough */
	case PENDING_RETR:
		if (ctrl->offset)
			rc = fseek(ctrl->fp, ctrl->offset, SEEK_SET);
		if (rc) {
			do_abort(ctrl);
			send_msg(ctrl->sd, "551 Failed seeking to that position in file.\r\n");
			return;
		}
		/* fallthrough */
	case PENDING_LIST:
		break;

	case PENDING_NONE:
		DBG("No pending command, waiting ...");
		return;
	}

	switch (ctrl->pending) {
	case PENDING_STOR:
		DBG("Pending STOR, starting ...");
		uev_io_init(ctrl->ctx, &ctrl->data_watcher, do_STOR, ctrl, ctrl->data_sd, UEV_READ);
		break;

	case PENDING_RETR:
		DBG("Pending RETR, starting ...");
		uev_io_init(ctrl->ctx, &ctrl->data_watcher, do_RETR, ctrl, ctrl->data_sd, UEV_WRITE);
		break;

	case PENDING_LIST:
		DBG("Pending LIST, starting ...");
		uev_io_init(ctrl->ctx, &ctrl->data_watcher, do_LIST, ctrl, ctrl->data_sd, UEV_WRITE);
		break;

	case PENDING_NONE:
		/* cannot get here */
		return;
	}

	if (ctrl->pending == PENDING_LIST && ctrl->list_mode == LISTMODE_MLST)
		send_msg(ctrl->sd, "150 Opening ASCII mode data connection for MLSD.\r\n");
	else
		send_msg(ctrl->sd, "150 Data connection accepted; transfer starting.\r\n");
	ctrl->pending = PENDING_NONE;
}

static int do_PASV(ctrl_t *ctrl, _TPtr<char> arg, struct sockaddr *data, socklen_t *len)
{
	struct sockaddr_in server;

	if (ctrl->data_sd > 0) {
		close(ctrl->data_sd);
		ctrl->data_sd = -1;
	}

	if (ctrl->data_listen_sd > 0)
		close(ctrl->data_listen_sd);

	ctrl->data_listen_sd = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0);
	if (ctrl->data_listen_sd < 0) {
		ERR(errno, "Failed opening data server socket");
		send_msg(ctrl->sd, "426 Internal server error.\r\n");
		return 1;
	}

	memset(&server, 0, sizeof(server));
	server.sin_family      = AF_INET;
	server.sin_addr.s_addr = inet_addr(ctrl->serveraddr);
	server.sin_port        = htons(0);
	if (bind(ctrl->data_listen_sd, (struct sockaddr *)&server, sizeof(server)) < 0) {
		ERR(errno, "Failed binding to client socket");
		send_msg(ctrl->sd, "426 Internal server error.\r\n");
		close(ctrl->data_listen_sd);
		ctrl->data_listen_sd = -1;
		return 1;
	}

	INFO("Data server port established.  Waiting for client to connect ...");
	if (listen(ctrl->data_listen_sd, 1) < 0) {
		ERR(errno, "Client data connection failure");
		send_msg(ctrl->sd, "426 Internal server error.\r\n");
		close(ctrl->data_listen_sd);
		ctrl->data_listen_sd = -1;
		return 1;
	}

	memset(data, 0, sizeof(*data));
	if (-1 == getsockname(ctrl->data_listen_sd, data, len)) {
		ERR(errno, "Cannot determine our address, need it if client should connect to us");
		close(ctrl->data_listen_sd);
		ctrl->data_listen_sd = -1;
		return 1;
	}

	uev_io_init(ctrl->ctx, &ctrl->data_watcher, do_pasv_connection, ctrl, ctrl->data_listen_sd, UEV_READ);

	return 0;
}

static void handle_PASV(ctrl_t *ctrl, _TPtr<char> arg)
{
	struct sockaddr_in data;
	socklen_t len = sizeof(data);
	char *msg, *p, buf[200];
	int port;

	if (do_PASV(ctrl, arg, (struct sockaddr *)&data, &len))
		return;

	/* Convert server IP address and port to comma separated list */
	if (pasv_addr)
		msg = strdup(pasv_addr);
	else
		msg = strdup(ctrl->serveraddr);
	if (!msg) {
		send_msg(ctrl->sd, "426 Internal server error.\r\n");
		exit(1);
	}
	p = msg;
	while ((p = strchr(p, '.')))
		*p++ = ',';

	port = ntohs(data.sin_port);
	snprintf(buf, sizeof(buf), "227 Entering Passive Mode (%s,%d,%d)\r\n",
		 msg, port / 256, port % 256);
	send_msg(ctrl->sd, buf);

	free(msg);
}

static void handle_EPSV(ctrl_t *ctrl, _TPtr<char> arg)
{
	struct sockaddr_in data;
	socklen_t len = sizeof(data);
	char buf[200];

	if (t_string_valid(arg) && t_string_case_compare(arg, "ALL")) {
		send_msg(ctrl->sd, "200 Command OK\r\n");
		return;
	}

	if (do_PASV(ctrl, arg, (struct sockaddr *)&data, &len))
		return;

	snprintf(buf, sizeof(buf), "229 Entering Extended Passive Mode (|||%d|)\r\n", ntohs(data.sin_port));
	send_msg(ctrl->sd, buf);
}

static void do_RETR(uev_t *w, void *arg, int events)
{
	ctrl_t *ctrl = (ctrl_t *)arg;
	struct timeval tv;
	ssize_t bytes;
	size_t num;
	char buf[BUFFER_SIZE];

	if (UEV_ERROR == events || UEV_HUP == events) {
		DBG("error on data_sd ...");
		uev_io_start(w);
		return;
	}

	if (!ctrl->fp) {
		DBG("no fp for RETR, bailing.");
		return;
	}

	num = fread(buf, sizeof(char), sizeof(buf), ctrl->fp);
	if (!num) {
		if (feof(ctrl->fp))
			LOG("User %s from %s downloaded '%s'", ctrl->name, ctrl->clientaddr, ctrl->file);
		else if (ferror(ctrl->fp))
			ERR(0, "Error while reading %s",  ctrl->file);
		do_abort(ctrl);
		send_msg(ctrl->sd, "226 Transfer complete.\r\n");
		return;
	}

	/* Reset inactivity timer. */
	uev_timer_set(&ctrl->timeout_watcher, INACTIVITY_TIMER, 0);

	gettimeofday(&tv, NULL);
	if (tv.tv_sec - ctrl->tv.tv_sec > 3) {
		DBG("Sending %zd bytes of %s to %s ...", num,ctrl->file, ctrl->clientaddr);
		ctrl->tv.tv_sec = tv.tv_sec;
	}

	bytes = send(ctrl->data_sd, buf, num, 0);
	if (-1 == bytes) {
		if (ECONNRESET == errno)
			DBG("Connection reset by client.");
		else
			ERR(errno, "Failed sending file %s to client", ctrl->file);

		do_abort(ctrl);
		send_msg(ctrl->sd, "426 TCP connection was established but then broken!\r\n");
	}
}

/*
 * Check if previous command was PORT, then connect to client and
 * transfer file/listing similar to what's done for PASV conns.
 */
static void do_PORT(ctrl_t *ctrl, pend_t pending)
{
	if (!ctrl->data_address[0]) {
		/* Check if previous command was PASV */
		if (ctrl->data_sd == -1 && ctrl->data_listen_sd == -1) {
			if (pending == 1)
				do_MLST(ctrl);
			return;
		}

		ctrl->pending = pending;
		return;
	}

	if (open_data_connection(ctrl)) {
		do_abort(ctrl);
		send_msg(ctrl->sd, "425 TCP connection cannot be established.\r\n");
		return;
	}

	if (pending != PENDING_LIST || ctrl->list_mode != LISTMODE_MLST)
		send_msg(ctrl->sd, "150 Data connection opened; transfer starting.\r\n");

	switch (pending) {
	case PENDING_STOR:
		uev_io_init(ctrl->ctx, &ctrl->data_watcher, do_STOR, ctrl, ctrl->data_sd, UEV_READ);
		break;

	case PENDING_RETR:
		uev_io_init(ctrl->ctx, &ctrl->data_watcher, do_RETR, ctrl, ctrl->data_sd, UEV_WRITE);
		break;

	case PENDING_LIST:
		uev_io_init(ctrl->ctx, &ctrl->data_watcher, do_LIST, ctrl, ctrl->data_sd, UEV_WRITE);
		break;

	default:
		ERR(0, "Unhandled pending command (%d) in %s()!", pending, __func__);
		break;
	}

	ctrl->pending = PENDING_NONE;
}

static void handle_RETR(ctrl_t *ctrl, _TPtr<char> file)
{
	FILE *fp;
	_TPtr<char> path = NULL;
	struct stat st;

	path = compose_abspath(ctrl, file);
	if (!path || t_stat(path, &st)) {
        if (!path)
            printf("PATH RETURNED NULL");

		//INFO("%s: RETR: invalid path to %s: %m", ctrl->clientaddr, file);
		send_msg(ctrl->sd, "550 No such file or directory.\r\n");
		return;
	}
	if (!S_ISREG(st.st_mode)) {
		LOG("%s: Failed opening '%s'. Not a regular file", ctrl->clientaddr, (char*)TaintedToCheckedStrAdaptor(file, t_strlen(path)));
		send_msg(ctrl->sd, "550 Not a regular file.\r\n");
		return;
	}

	fp = t_fopen(path, "rb");
	if (!fp) {
		if (errno != ENOENT)
			ERR(errno, "Failed RETR %s for %s", (char*)TaintedToCheckedStrAdaptor(file, t_strlen(path)), ctrl->clientaddr);
		send_msg(ctrl->sd, "451 Trouble to RETR file.\r\n");
		return;
	}

	ctrl->fp = fp;
//    int argLen = (file == NULL)? 0 : t_strlen(file);
//    char* checkedArg = (char*)malloc(argLen);
//    t_strncpy(checkedArg, t_strdup(file ? file : ""), argLen);
	ctrl->file = (char*)t_strdup(file ? file : "");

	if (ctrl->data_sd > -1) {
		if (ctrl->offset) {
			DBG("Previous REST %ld of file size %ld", ctrl->offset, st.st_size);
			if (fseek(fp, ctrl->offset, SEEK_SET)) {
				do_abort(ctrl);
				send_msg(ctrl->sd, "551 Failed seeking to that position in file.\r\n");
				return;
			}
		}

		send_msg(ctrl->sd, "125 Data connection already open; transfer starting.\r\n");
		uev_io_init(ctrl->ctx, &ctrl->data_watcher, do_RETR, ctrl, ctrl->data_sd, UEV_WRITE);
 //       free(checkedArg);
        return;
	}

	do_PORT(ctrl, PENDING_RETR);
   // free(checkedArg);
}

/* Request to set mtime, ncftp does this */
static void handle_MDTM(ctrl_t *ctrl, _TPtr<char>  file)
{
	struct stat st;
	struct tm *tm;
	_TPtr<char> path = NULL;
    _TPtr<char> ptr = NULL;
	char *mtime = NULL;
	char buf[80];

        if (!file)
		goto missing;

	ptr = t_strchr(file, ' ');
	if (ptr) {
		*ptr++ = 0;
		mtime = (char*)TaintedToCheckedStrAdaptor(file, t_strlen(file));
		file  = ptr;
        }

	path = compose_abspath(ctrl, file);
	if (!path || t_stat(path, &st) || !S_ISREG(st.st_mode)) {
	missing:
		INFO("MDTM: invalid path to %s: %m", file);
		send_msg(ctrl->sd, "550 Not a regular file.\r\n");
		return;
	}

	if (mtime) {
		struct timespec times[2] = {
			{ 0, UTIME_OMIT },
			{ 0, 0 }
		};
		struct tm tm;
		int rc;

		if (!strptime(mtime, "%Y%m%d%H%M%S", &tm)) {
		fail:
			send_msg(ctrl->sd, "550 Invalid time format\r\n");
			return;
		}

		times[1].tv_sec = mktime(&tm);
		rc = t_utimensat(0, path, times, 0);
		if (rc) {
			ERR(errno, "Failed setting MTIME %s of %s", mtime, file);
			goto fail;
		}

		LOG("User %s from %s changed mtime of %s", ctrl->name, ctrl->clientaddr, file);
		(void)t_stat(path, &st);
	}

	tm = gmtime(&st.st_mtime);
	strftime(buf, sizeof(buf), "213 %Y%m%d%H%M%S\r\n", tm);

	send_msg(ctrl->sd, buf);
}

static void do_STOR(uev_t *w, void *arg, int events)
{
	ctrl_t *ctrl = (ctrl_t *)arg;
	struct timeval tv;
	ssize_t bytes;
	size_t num;
	char buf[BUFFER_SIZE];

	if (UEV_ERROR == events || UEV_HUP == events) {
		DBG("error on data_sd ...");
		uev_io_start(w);
		return;
	}

	if (!ctrl->fp) {
		DBG("no fp for STOR, bailing.");
		return;
	}

	/* Reset inactivity timer. */
	uev_timer_set(&ctrl->timeout_watcher, INACTIVITY_TIMER, 0);

	bytes = recv(ctrl->data_sd, buf, sizeof(buf), 0);
	if (bytes < 0) {
		if (ECONNRESET == errno)
			DBG("Connection reset by client.");
		else
			ERR(errno, "Failed receiving file %s from client", ctrl->file);
		do_abort(ctrl);
		send_msg(ctrl->sd, "426 TCP connection was established but then broken!\r\n");
		return;
	}
	if (bytes == 0) {
		LOG("User %s from %s uploaded file %s", ctrl->name, ctrl->clientaddr, ctrl->file);
		do_abort(ctrl);
		send_msg(ctrl->sd, "226 Transfer complete.\r\n");
		return;
	}

	gettimeofday(&tv, NULL);
	if (tv.tv_sec - ctrl->tv.tv_sec > 3) {
		DBG("Receiving %zd bytes of %s from %s ...", bytes, ctrl->file, ctrl->clientaddr);
		ctrl->tv.tv_sec = tv.tv_sec;
	}

	num = fwrite(buf, 1, bytes, ctrl->fp);
	if ((size_t)bytes != num)
		ERR(errno, "552 Disk full.");
}

static void handle_STOR(ctrl_t *ctrl, _TPtr<char> file)
{
	FILE *fp = NULL;
    _TPtr<char> path = NULL;
	int rc = 0;

	path = compose_abspath(ctrl, file);
	if (!path) {
		INFO("STOR: invalid path to %s: %m", file);
		goto fail;
	}

	DBG("Trying to write to %s ...", path);
	fp = t_fopen(path, "wb");
	if (!fp) {
		/* If EACCESS client is trying to do something disallowed */
		ERR(errno, "Failed writing %s", path);
	fail:
		send_msg(ctrl->sd, "451 Trouble storing file.\r\n");
		do_abort(ctrl);
		return;
	}

	ctrl->fp = fp;
//    int argLen = (file == NULL)? 0 : t_strlen(file);
//    char* checkedArg = (char*)malloc(argLen);
//    t_strncpy(checkedArg, t_strdup(file ? file : ""), argLen);
	ctrl->file =  (char*)t_strdup(file ? file : "");

	if (ctrl->data_sd > -1) {
		if (ctrl->offset)
			rc = fseek(fp, ctrl->offset, SEEK_SET);
		if (rc) {
			do_abort(ctrl);
			send_msg(ctrl->sd, "551 Failed seeking to that position in file.\r\n");
			return;
		}

		send_msg(ctrl->sd, "125 Data connection already open; transfer starting.\r\n");
		uev_io_init(ctrl->ctx, &ctrl->data_watcher, do_STOR, ctrl, ctrl->data_sd, UEV_READ);
  //      free(checkedArg);
        return;
	}

	do_PORT(ctrl, PENDING_STOR);
    //free(checkedArg);
}

static void handle_DELE(ctrl_t *ctrl, _TPtr<char> file)
{
    _TPtr<char> path = NULL;

	path = compose_abspath(ctrl, file);
	if (!path) {
		INFO("DELE: invalid path to %s: %m", file);
		goto fail;
	}

	if (t_remove(path)) {
		if (ENOENT == errno)
		fail:	send_msg(ctrl->sd, "550 No such file or directory.\r\n");
		else if (EPERM == errno)
			send_msg(ctrl->sd, "550 Not allowed to remove file or directory.\r\n");
		else if (ENOTEMPTY == errno)
			send_msg(ctrl->sd, "550 Not allowed to remove directory, not empty.\r\n");
		else
			send_msg(ctrl->sd, "550 Unknown error.\r\n");
		return;
	}

	LOG("User %s from %s deleted %s", ctrl->name, ctrl->clientaddr, file);
	send_msg(ctrl->sd, "200 Command OK\r\n");
}

static void handle_MKD(ctrl_t *ctrl, _TPtr<char> arg)
{
	_TPtr<char> path = NULL;

	path = compose_abspath(ctrl, arg);
	if (!path) {
		INFO("MKD: invalid path to %s: %m", arg);
		goto fail;
	}

	if (t_mkdir(path, 0755)) {
		if (EPERM == errno)
		fail:	send_msg(ctrl->sd, "550 Not allowed to create directory.\r\n");
		else
			send_msg(ctrl->sd, "550 Unknown error.\r\n");
		return;
	}

	LOG("User %s from %s created directory %s", ctrl->name, ctrl->clientaddr, arg);
	send_msg(ctrl->sd, "200 Command OK\r\n");
}

static void handle_RMD(ctrl_t *ctrl, _TPtr<char> arg)
{
	handle_DELE(ctrl, arg);
}

static void handle_REST(ctrl_t *ctrl, _TPtr<char> arg)
{
	const char *errstr;
	char buf[80];

	if (!t_string_valid(arg)) {
		send_msg(ctrl->sd, "550 Invalid argument.\r\n");
		return;
	}

	ctrl->offset = t_strtonum(arg, 0, INT64_MAX, &errstr);
	snprintf(buf, sizeof(buf), "350 Restarting at %ld.  Send STOR or RETR to continue transfer.\r\n", ctrl->offset);
	send_msg(ctrl->sd, buf);
}

static size_t num_nl(_TPtr<char> file)
{
    FILE *fp;
    char buf[80];
    size_t len, num = 0;

    fp = t_fopen(file, "r");
    if (!fp)
        return 0;

    do {
        char *ptr = buf;

        len = fread(buf, sizeof(char), sizeof(buf) - 1, fp);
        if (len > 0) {
            buf[len] = 0;
            while ((ptr = strchr(ptr, '\n'))) {
                ptr++;
                num++;
            }
        }
    } while (len > 0);
    fclose(fp);

    return num;
}

static void handle_SIZE(ctrl_t *ctrl, _TPtr<char> file)
{
	_TPtr<char> path = NULL;
	char buf[80];
	size_t extralen = 0;
	struct stat st;

	path = compose_abspath(ctrl, file);
	if (!path || t_stat(path, &st) || S_ISDIR(st.st_mode)) {
		send_msg(ctrl->sd, "550 No such file, or argument is a directory.\r\n");
		return;
	}

	DBG("SIZE %s", (const char*)TaintedToCheckedStrAdaptor(path, t_strlen(path)));

	if (ctrl->type == TYPE_A)
		extralen = num_nl(path);

	snprintf(buf, sizeof(buf), "213 %"  PRIu64 "\r\n", (uint64_t)(st.st_size + extralen));
	send_msg(ctrl->sd, buf);
}

/* No operation - used as session keepalive by clients. */
static void handle_NOOP(ctrl_t *ctrl, _TPtr<char> arg)
{
	send_msg(ctrl->sd, "200 NOOP OK.\r\n");
}

#if 0
static void handle_RNFR(ctrl_t *ctrl, char *arg)
{
}

static void handle_RNTO(ctrl_t *ctrl, char *arg)
{
}
#endif

static void handle_QUIT(ctrl_t *ctrl, _TPtr<char> arg)
{
	send_msg(ctrl->sd, "221 Goodbye.\r\n");
	uev_exit(ctrl->ctx);
}

static void handle_CLNT(ctrl_t *ctrl, _TPtr<char> arg)
{
	send_msg(ctrl->sd, "200 CLNT\r\n");
}

static void handle_OPTS(ctrl_t *ctrl, _TPtr<char> arg)
{
	/* OPTS MLST type;size;modify;perm; */
	if (arg && t_strstr(arg, "MLST")) {
		size_t i = 0;
		_TPtr<char> ptr = NULL;
		char buf[42] = "200 MLST OPTS ";
		char facts[10] = { 0 };

		ptr = t_strtok(arg + 4, " \t;");
		while (ptr && i < sizeof(facts) - 1) {
			if (!t_strcmp(ptr, "modify") ||
			    !t_strcmp(ptr, "perm")   ||
			    !t_strcmp(ptr, "size")   ||
			    !t_strcmp(ptr, "type")) {
				facts[i++] = ptr[0];
				t_strlcat(buf, ptr, sizeof(buf));
				t_strlcat(buf, ";", sizeof(buf));
			}

			ptr = t_strtok(NULL, ";");
		}
		strlcat(buf, "\r\n", sizeof(buf));

		DBG("New MLSD facts: %s", facts);
		strlcpy(ctrl->facts, facts, sizeof(ctrl->facts));
		send_msg(ctrl->sd, buf);
	} else
		send_msg(ctrl->sd, "200 UTF8 OPTS ON\r\n");
}

static void handle_HELP(ctrl_t *ctrl, _TPtr<char> arg)
{
	ftp_cmd_t *cmd;
	char buf[80];
	int i = 0;

	if (t_string_valid(arg) && !t_string_compare(arg, "SITE")) {
		send_msg(ctrl->sd, "500 command HELP does not take any arguments on this server.\r\n");
		return;
	}

	snprintf(ctrl->buf, ctrl->bufsz, "214-The following commands are recognized.");
	for (cmd = &supported[0]; cmd->command; cmd++, i++) {
		if (i % 14 == 0)
			strlcat(ctrl->buf, "\r\n", ctrl->bufsz);
		snprintf(buf, sizeof(buf), " %s", cmd->command);
		strlcat(ctrl->buf, buf, ctrl->bufsz);
	}
	snprintf(buf, sizeof(buf), "\r\n214 Help OK.\r\n");
	strlcat(ctrl->buf, buf, ctrl->bufsz);

	send_msg(ctrl->sd, ctrl->buf);
}

static void handle_FEAT(ctrl_t *ctrl, _TPtr<char> arg)
{
	snprintf(ctrl->buf, ctrl->bufsz, "211-Features:\r\n"
		 " EPSV\r\n"
		 " PASV\r\n"
		 " SIZE\r\n"
		 " UTF8\r\n"
		 " REST STREAM\r\n"
		 " MLST modify*;perm*;size*;type*;\r\n"
		 "211 End\r\n");
	send_msg(ctrl->sd, ctrl->buf);
}

static void handle_UNKNOWN(ctrl_t *ctrl, char *command)
{
	char buf[128];

	snprintf(buf, sizeof(buf), "500 command '%s' not recognized by server.\r\n", command);
	send_msg(ctrl->sd, buf);
}

#define COMMAND(NAME) { #NAME, handle_ ## NAME }

static ftp_cmd_t supported[] = {
	COMMAND(ABOR),
	COMMAND(DELE),
	COMMAND(USER),
	COMMAND(PASS),
	COMMAND(SYST),
	COMMAND(TYPE),
	COMMAND(PORT),
	COMMAND(EPRT),
	COMMAND(RETR),
	COMMAND(MKD),
	COMMAND(RMD),
	COMMAND(REST),
	COMMAND(MDTM),
	COMMAND(PASV),
	COMMAND(EPSV),
	COMMAND(QUIT),
	COMMAND(LIST),
	COMMAND(NLST),
	COMMAND(MLST),
	COMMAND(MLSD),
	COMMAND(CLNT),
	COMMAND(OPTS),
	COMMAND(PWD),
	COMMAND(STOR),
	COMMAND(CWD),
	COMMAND(CDUP),
	COMMAND(SIZE),
	COMMAND(NOOP),
	COMMAND(HELP),
	COMMAND(FEAT),
	{ NULL, NULL }
};

static void child_exit(uev_t *w, void *arg, int events)
{
	DBG("Child exiting ...");
	uev_exit(w->ctx);
}

static void  read_client_command(uev_t *w, void *arg, int events)
{
	char *command, *argument;
	ctrl_t *ctrl = (ctrl_t *)arg;
	ftp_cmd_t *cmd;

	if (UEV_ERROR == events || UEV_HUP == events) {
		uev_io_start(w);
		return;
	}

	/* Reset inactivity timer. */
	uev_timer_set(&ctrl->timeout_watcher, INACTIVITY_TIMER, 0);

	if (recv_msg(w->fd, ctrl->buf, ctrl->bufsz, &command, &argument)) {
		DBG("Short read, exiting.");
		uev_exit(ctrl->ctx);
		return;
	}

	if (!string_valid(command))
		return;

	if (string_match(command, "FF F4")) {
		DBG("Ignoring IAC command, client should send ABOR as well.");
		return;
	}

	for (cmd = &supported[0]; cmd->command; cmd++) {
		if (string_compare(command, cmd->command)) {
            //print the argument here
            printf("we have argument as %s", argument);
            int argLen = 0;
            if (argument!= NULL)
                argLen = strlen(argument);
			cmd->cb(ctrl, StaticUncheckedToTStrAdaptor(argument, argLen));
			return;
		}
	}

	handle_UNKNOWN(ctrl, command);
}

static void ftp_command(ctrl_t *ctrl)
{
	uev_t sigterm_watcher;

	ctrl->bufsz = BUFFER_SIZE * sizeof(char);
	ctrl->buf   = malloc(ctrl->bufsz);
	if (!ctrl->buf) {
                WARN(errno, "FTP session failed allocating buffer");
                exit(1);
	}

	snprintf(ctrl->buf, ctrl->bufsz, "220 %s (%s) ready.\r\n", prognm, VERSION);
	send_msg(ctrl->sd, ctrl->buf);

	uev_signal_init(ctrl->ctx, &sigterm_watcher, child_exit, NULL, SIGTERM);
	uev_io_init(ctrl->ctx, &ctrl->io_watcher, read_client_command, ctrl, ctrl->sd, UEV_READ);
	uev_run(ctrl->ctx, 0);
}

int ftp_session(uev_ctx_t *ctx, int sd)
{
	int pid = 0;
	ctrl_t *ctrl;
	socklen_t len;

	ctrl = new_session(ctx, sd, &pid);
	if (!ctrl) {
		if (pid < 0)
			shutdown(sd, SHUT_RDWR);
		close(sd);

		return pid;
	}

	len = sizeof(ctrl->server_sa);
	if (-1 == getsockname(sd, (struct sockaddr *)&ctrl->server_sa, &len)) {
		ERR(errno, "Cannot determine our address");
		goto fail;
	}
	convert_address(&ctrl->server_sa, ctrl->serveraddr, sizeof(ctrl->serveraddr));

	len = sizeof(ctrl->client_sa);
	if (-1 == getpeername(sd, (struct sockaddr *)&ctrl->client_sa, &len)) {
		ERR(errno, "Cannot determine client address");
		goto fail;
	}
	convert_address(&ctrl->client_sa, ctrl->clientaddr, sizeof(ctrl->clientaddr));

	ctrl->type = TYPE_A;
	ctrl->data_listen_sd = -1;
	ctrl->data_sd = -1;
	ctrl->name[0] = 0;
	ctrl->pass[0] = 0;
	ctrl->data_address[0] = 0;
	strlcpy(ctrl->facts, "mpst", sizeof(ctrl->facts));

	INFO("Client connection from %s", ctrl->clientaddr);
	ftp_command(ctrl);

	DBG("Client exiting, bye");
	exit(del_session(ctrl, 1));
fail:
	free(ctrl);
	shutdown(sd, SHUT_RDWR);
	close(sd);

	return -1;
}

/**
 * Local Variables:
 *  indent-tabs-mode: t
 *  c-file-style: "linux"
 * End:
 */
