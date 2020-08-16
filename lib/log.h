#if !defined(P67_LOG)
#define P67_LOG 1

#include <stdarg.h>

#define p67_log_cb (*p67_log_cb_location())

typedef int (* p67_log_cb_t)(const char *, va_list);

p67_log_cb_t *
p67_log_cb_location(void);

int
__p67_log(const char * fmt, ...);

#if defined(DEBUG) 

#define p67_log_debug(...) p67_log(__VA_ARGS__)

#else

#define p67_log_debug(...) (void)0

#endif

#define p67_log(...) __p67_log(__VA_ARGS__)

#endif
