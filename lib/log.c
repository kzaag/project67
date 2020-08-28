#include "log.h"

#include <stdlib.h>
#include <stdio.h>

p67_log_cb_t __cb = NULL;

p67_log_cb_t *
p67_log_cb_location(void)
{
    return &__cb;
}

int
__p67_log(const char * fmt, ...)
{
    va_list args;
    va_start(args, fmt);
    int ret = __cb ? 
        __cb(fmt, args) : vprintf(fmt, args);
    va_end(args);
    return ret;
}

int
p67_log_cb_terminal(const char * fmt, va_list list)
{
    printf("\r");
    vprintf(fmt, list);
    printf(P67_TERMINAL_ENC_SGN_STR);
    fflush(stdout);
    return 0;
}
