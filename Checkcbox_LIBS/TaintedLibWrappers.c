#include "TaintedLibWrappers.h"
#include "strlite.h"

int     t_strnmatch  (const char *str, const char **list, size_t num)
{
	return strnmatch(str, list, num);
}

int     t_strmatch   (const char *str, const char **list)
{
	return strmatch(str, list);
}

size_t  t_strlcpy    (char *dst, const char *src, size_t siz)
{
	return strlcpy(dst, src, siz);
}

size_t  t_strlcat    (char *dst, const char *src, size_t siz)
{
	return strlcat(dst, src, siz);
}

long long t_strtonum (const char *numstr, long long minval, long long maxval, const char **errstrp)
{
	return strtonum(numstr, minval, maxval, errstrp);
}

char   *t_strtrim    (char *str)
{
	return strtrim(str);
}

int t_atonum(const char *str)
{
	return atonum(str);
}

int t_string_valid(const char *str)
{
   return string_valid(str);
}

int t_string_match(const char *a, const char *b)
{
	return string_match(a, b);
}

int t_string_compare(const char *a, const char *b)
{
   return string_compare(a, b);
}

int t_string_case_compare(const char *a, const char *b)
{
   return string_case_compare(a,b);
}

char* t_basename (char* path)
{
   return basename(path);
}

ssize_t t_send (int fd, void* buf, size_t n, int flags)
{
	return send(fd, buf, n, flags);
}
char *t_dirname (char *__path)
{
	return dirname(__path);

}

char *t_realpath (const char *__restrict __name,
		       char *__restrict __resolved)
{
	return realpath(__name, __resolved);
}

int t_stat(const char *restrict path, struct stat *restrict buf)
{
	return stat(path, buf);
}

void t_logit(int severity, const char *fmt, ...)
{
	FILE *file;
        va_list args;

	if (loglevel == INTERNAL_NOPRI)
		return;

	if (severity > LOG_WARNING)
		file = stdout;
	else
		file = stderr;

        va_start(args, fmt);
	if (do_syslog)
		vsyslog(severity, fmt, args);
	else if (severity <= loglevel) {
		if (loglevel == LOG_DEBUG)
			fprintf(file, "%d> ", getpid());
		vfprintf(file, fmt, args);
		fflush(file);
	}
        va_end(args);
}
