#include <stdint.h>    /* uint8_t, uint16_t, uint32_t, INT32_MAX, etc. */
#include <string.h>
#include <sys/param.h> /* MAX(), isset(), setbit(), TRUE, FALSE, et consortes. :-) */
#include <stdio.h>
#include <libgen.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/syslog.h>
#define	INTERNAL_NOPRI	0x10
#ifndef min
/** Geneirc min() macro, if a < b => a, else b */
#define min(a,b)				\
	({					\
		__typeof__ (a) _a = (a);	\
		__typeof__ (b) _b = (b);	\
		_a < _b ? _a : _b;		\
	})
#endif
#ifndef max
/** Geneirc max() macro, if a > b => a, else b */
#define max(a,b)				\
	({					\
		__typeof__ (a) _a = (a);	\
		__typeof__ (b) _b = (b);	\
		_a > _b ? _a : _b;		\
	})
#endif
extern int loglevel;
extern int   do_syslog;  
int     t_strnmatch  (const char *str, const char **list, size_t num);
int     t_strmatch   (const char *str, const char **list);

size_t  t_strlcpy    (char *dst, const char *src, size_t siz);
size_t  t_strlcat    (char *dst, const char *src, size_t siz);
long long t_strtonum (const char *numstr, long long minval, long long maxval, const char **errstrp);

char   *t_strtrim    (char *str);

int t_atonum(const char *str);
int t_string_valid(const char *str);
int t_string_match(const char *a, const char *b);
int t_string_compare(const char *a, const char *b);
int t_string_case_compare(const char *a, const char *b);
char *t_basename (char *__path);
ssize_t t_send (int fd, void* buf, size_t n, int flags);
char *t_dirname (char *__path);
char *t_realpath (const char *__restrict __name,
                       char *__restrict __resolved);
int t_stat(const char *restrict path, struct stat *restrict buf);
void t_logit(int severity, const char* fmt, ...);
