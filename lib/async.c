#include <linux/futex.h>
#include <sys/time.h>
#include <stdatomic.h>
#include <sys/syscall.h>
#include <limits.h>
#include <unistd.h>
#include <errno.h>

#include "async.h"

#define futex(uaddr, op, val, timeout, uaddr2, val3) \
    syscall(SYS_futex, \
            (int*)(uaddr), \
            (int)(op), \
            (int)(val), \
            (const struct timeval *)(timeout), \
            (int*)(uaddr2), \
            (int)(val3))

#define futex_wake_all(uaddr) \
    futex(uaddr, FUTEX_WAKE, INT_MAX, NULL, NULL, 0)

/*
    set state without locking async
*/
p67_err
p67_async_set_state(p67_async_t * async, int old, int new)
{
    int x = old;
    if(atomic_compare_exchange_strong(&async->state, &x, new) != 1)
        return p67_err_easync;
    if(futex_wake_all(&async->state) == -1) 
        return p67_err_eerrno;
    return 0;
}

/*
    waits for async to leave specified state for up to maxms milliseconds.
*/
p67_err
p67_async_wait_change(p67_async_t * async, int state, int maxms)
{
    int err;
    struct timeval tv;
    tv.tv_sec = maxms / 1000;
    tv.tv_usec = (maxms % 1000) * 1000;

    err = futex(&async->state, FUTEX_WAIT, state, &tv, NULL, 0);
    
    if(err != 0 && errno == 110)
        return p67_err_eerrno | p67_err_etime;

    if(err != 0)
        return p67_err_eerrno;
    
    return 0;
}

p67_err
p67_async_terminate(p67_async_t * async, int to)
{
    p67_err err;
    int state;

    if(async->state != P67_ASYNC_STATE_RUNNING)
        return p67_err_einval;

    if((err = p67_async_set_state(async, P67_ASYNC_STATE_RUNNING, P67_ASYNC_STATE_SIG_STOP)) != 0)
        return err;

    err = p67_async_wait_change(async, P67_ASYNC_STATE_SIG_STOP, to);
    
    state = async->state;

    if(state == P67_ASYNC_STATE_STOP)
        return 0;

    if(state == P67_ASYNC_STATE_RUNNING)
        return p67_err_easync;

    /* if timeout then just kill the thread*/
    if((err & p67_err_etime)) {
        if(atomic_compare_exchange_strong(
                    &async->state, 
                    &state, 
                    P67_ASYNC_STATE_STOP) != 1)
            return p67_err_easync;
        p67_cmn_thread_kill(async->thr);
        return 0;
    }
    
    return err;
}
