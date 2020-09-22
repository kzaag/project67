#if !defined(P67_LOG)
#define P67_LOG 1

#include <stdarg.h>
#include <stdio.h>

#define p67_log_cb (*p67_log_cb_location())

typedef int (* p67_log_cb_t)(const char *, va_list);

p67_log_cb_t *
p67_log_cb_location(void);

#define __p67_log(...) __p67_flog(stdout, __VA_ARGS__)
#define __p67_errlog(...) __p67_flog(stderr, __VA_ARGS__)

int
__p67_flog(FILE * __restrict__ f, const char * __restrict__ fmt, ...);

#if defined(DEBUG) 

#define p67_log_debug(...) p67_log(__VA_ARGS__)

#else

#define p67_log_debug(...) (void)0

#endif

#define p67_log(...) __p67_log(__VA_ARGS__)
#define p67_flog(f, ...) __p67_flog(f, __VA_ARGS__)
#define p67_errlog(f, ...) __p67_errlog(f, __VA_ARGS__)

extern int P67_LOG_TERM_ENC_SGN_STR_LEN;
extern char * P67_LOG_TERM_ENC_SGN_STR;

int
p67_log_cb_terminal(const char * fmt, va_list list);

void
p67_log_set_term_char(const char * c);

void
p67_log_free(void);

#endif
