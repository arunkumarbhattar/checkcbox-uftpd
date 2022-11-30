#include <string.h>
#include <sys/socket.h>
#include <stdio.h>
#include <sys/stat.h>
#include <arpa/inet.h>
typedef struct _M_ctrl{
        //We cannot marshall all of ctrl into Sandbox as it contains confidential information,
        // Hence we selectively create a new subset structure that has the fields used by this function
        // This way, we can perform marshalling pre and post Sandbox call
        int data_sd;
        int sd;
        char* data_address;
        int  data_port;
}Mctrl;

void _T_handle_CWD(char* home, char* ctrl_cwd, char* path, int ctrl_sd, char* ctrl_client_addr, int sizeof_ctrl_cwd, int chrooted, 
		char*(compose_path)(char*, char*), int (*_C_send_msg)(int, char*));
char *_T_compose_abspath(char* path, char* ctrl_cwd, int sizeof_ctrl_cwd,char*(compose_path)(char*, char*));
static int send_msg(int sd, char *msg);
static int is_cont(char *msg);
void _T_handle_PORT(Mctrl *ctrl, char* str, int (*_C_send_msg)(int, char*));
