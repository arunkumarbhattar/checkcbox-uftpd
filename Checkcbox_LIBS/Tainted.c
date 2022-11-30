#include "Tainted.h"

int _C_send_msg(int sd, char* msg);

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


void _T_handle_CWD(char* home, char* ctrl_cwd, char* path, int ctrl_sd, char* ctrl_client_addr, int sizeof_ctrl_cwd, int chrooted, 
		char*(_T_compose_path)(char*, char*), int (*_C_send_msg)(int, char*))
{
	struct stat st;
	char* dir = NULL;

	if (!path)
		goto done;

	/*
	 * Some FTP clients, most notably Chrome, use CWD to check if an
	 * entry is a file or directory.
	 */
	dir =  _T_compose_abspath(path, ctrl_cwd, sizeof_ctrl_cwd, _T_compose_path);
	if (!dir || stat(dir, &st) || !S_ISDIR(st.st_mode)) {
		printf("%s: CWD: invalid path to %s: %m", ctrl_client_addr, path);
		_C_send_msg(ctrl_sd, "550 No such directory.\r\n");
		return;
	}

	if (!chrooted)
		dir += strlen(home);

	snprintf(ctrl_cwd, sizeof_ctrl_cwd, "%s", dir);
	if (ctrl_cwd[0] == 0)
		snprintf(ctrl_cwd, sizeof_ctrl_cwd, "/");

done:
	printf("New CWD: '%s'", ctrl_cwd);
	_C_send_msg(ctrl_sd, "250 OK\r\n");
}

char *_T_compose_abspath(char* path, char* ctrl_cwd, int sizeof_ctrl_cwd, char*(_T_compose_path)(char*, char*))
{
	char *ptr;
	char cwd[sizeof_ctrl_cwd];

	if (path && path[0] == '/') {
		strlcpy(cwd, ctrl_cwd, sizeof_ctrl_cwd);
		memset(ctrl_cwd, 0, sizeof_ctrl_cwd);
	}

	ptr = _T_compose_path(ctrl_cwd, path);

	if (path && path[0] == '/')
		strlcpy(ctrl_cwd, cwd, sizeof_ctrl_cwd);

	return ptr;
}

void _T_handle_PORT(Mctrl *ctrl, char* str
		,int (*_C_send_msg)(int, char*))
{
	int a, b, c, d, e, f;
	char addr[INET_ADDRSTRLEN];
	struct sockaddr_in sin;
        if (!str) {
                _C_send_msg(ctrl->sd, "500 No PORT specified.\r\n");
                return;
        }
	/* Convert PORT command's argument to IP address + port */
	sscanf(str, "%d,%d,%d,%d,%d,%d", &a, &b, &c, &d, &e, &f);
	snprintf(addr, sizeof(addr), "%d.%d.%d.%d", a, b, c, d);

	/* Check IPv4 address using inet_aton(), throw away converted result */
	if (!inet_aton(addr, &(sin.sin_addr))) {
		printf("Invalid address '%s' given to PORT command", addr);
		_C_send_msg(ctrl->sd, "500 Illegal PORT command.\r\n");
		return;
	}

	strlcpy(ctrl->data_address, addr, sizeof(ctrl->data_address));
	ctrl->data_port = e * 256 + f;

	printf("Client PORT command accepted for %s:%d", ctrl->data_address, ctrl->data_port);
	_C_send_msg(ctrl->sd, "200 PORT command successful.\r\n");
	return;
}
