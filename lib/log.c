#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <termios.h>

#include <p67/async.h>
#include <p67/log.h>
#include <p67/cmn.h>


p67_log_cb_t __cb = NULL;

p67_log_cb_t *
p67_log_cb_location(void)
{
    return &__cb;
}

int free_sgn_str = 0;
char * P67_LOG_TERM_ENC_SGN_STR = ">";
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

p67_async_t termlock = P67_XLOCK_STATE_UNLOCKED;
#define MAX_BUF 400
static char buf[MAX_BUF];
static char ubuf[MAX_BUF];
static volatile int buf_ix = 0;

static int is_noblock = 0;

P67_CMN_NO_PROTO_ENTER
p67_err 
setup_noblock(void)
{
    struct termios t = {0};

    if(tcgetattr(0, &t) < 0) {
        return p67_err_eerrno;
    }

    t.c_lflag &= ~ICANON;
    t.c_lflag &= ~ECHO;

    if(tcsetattr(STDIN_FILENO, TCSANOW, &t) < 0) {
        return p67_err_eerrno;
    }

    return 0;
}
P67_CMN_NO_PROTO_EXIT

void
p67_log_restore_echo_canon(void)
{
    struct termios t = {0};

    if(!is_noblock) return;

    if(tcgetattr(0, &t) < 0) {
        return;
    }

    t.c_lflag |= ICANON;
    t.c_lflag |= ECHO;

    tcsetattr(STDIN_FILENO, TCSANOW, &t);
}

/* is not thread safe */
const char *
p67_log_read_term(int * bl, p67_err * err)
{
    int is_spec;
    char nc;
    
    if(!is_noblock) {
        if(setup_noblock() < 0) {
            if(err) *err = p67_err_eerrno;
            return NULL;
        }
        is_noblock = 1;
    }
    
    while(1) {

        __p67_log(NULL);

        /*
            TODO: use select so you can timeout reader.
        */
        if(read(STDIN_FILENO, &nc, 1) != 1) {
            continue;
        }

        is_spec = 0;

        switch(nc) {
        case 127:
            if(buf_ix > 0)
                buf_ix--;
            is_spec = 1;
            break;
        }

        if(is_spec) continue;

        write(STDOUT_FILENO, &nc, 1);
        buf[buf_ix++] = nc;

        if(nc == '\n' || buf_ix == MAX_BUF) {
            ubuf[buf_ix] = 0;
            /*
                copy without new line
            */
            if(nc == '\n')
                memcpy(ubuf, buf, buf_ix-1);
            else
                memcpy(ubuf, buf, buf_ix);
            if(bl) *bl = buf_ix;
            buf_ix = 0;
            return ubuf;
        }
    }
}

int
p67_log_cb_term(const char * fmt, va_list list)
{
    p67_spinlock_lock(&termlock);

    printf("\r\033[2K");
    if(fmt)
        vprintf(fmt, list);
    if(buf_ix > 0) {
        printf(
            "%s %.*s", 
            P67_LOG_TERM_ENC_SGN_STR,
            buf_ix, buf);
    } else {
        printf("%s ", P67_LOG_TERM_ENC_SGN_STR);
    }
    fflush(stdout);

    p67_spinlock_unlock(&termlock);

    return 0;
}
