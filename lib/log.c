#include <stdlib.h>
#include <string.h>

#include <p67/log.h>
#include <p67/cmn.h>

p67_log_cb_t __cb = NULL;

p67_log_cb_t *
p67_log_cb_location(void)
{
    return &__cb;
}

int free_sgn_str = 0;
char * P67_LOG_TERM_ENC_SGN_STR = "\r> ";
int P67_LOG_TERM_ENC_SGN_STR_LEN = 3;

void
p67_log_set_term_char(const char * c) 
{
    if(c && free_sgn_str) free(P67_LOG_TERM_ENC_SGN_STR);
    free_sgn_str = 1;
    P67_LOG_TERM_ENC_SGN_STR = p67_cmn_strdup(c);
    P67_LOG_TERM_ENC_SGN_STR_LEN = strlen(c);
}

void
p67_log_free(void)
{
    if(free_sgn_str) {
        free(P67_LOG_TERM_ENC_SGN_STR);
    }
}

int
__p67_flog(FILE * f, const char * fmt, ...)
{
    va_list args;
    va_start(args, fmt);
    int ret = __cb ? 
        __cb(fmt, args) : vfprintf(f, fmt, args);
    va_end(args);
    return ret;
}

int
p67_log_cb_terminal(const char * fmt, va_list list)
{
    printf("\r");
    vprintf(fmt, list);
    printf(P67_LOG_TERM_ENC_SGN_STR);
    fflush(stdout);
    return 0;
}
