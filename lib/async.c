#include <linux/futex.h>
#include <sys/time.h>
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

p67_err
p67_sm_wake_all(int * pptr)
{
    if(futex_wake_all(pptr) != 0)
        return p67_err_eerrno;
    return 0;    
}

p67_err
p67_sm_set_state(int * uaddr, int old, int new)
{
    if(atomic_compare_exchange_strong(uaddr, &old, new) != 1)
        return p67_err_easync;
    if(futex_wake_all(uaddr) == -1) 
        return p67_err_eerrno;
    return 0;
}

/*
    waits for async to leave specified state for up to maxms milliseconds.
*/
p67_err
p67_sm_wait_for(int * pptr, int state, int maxms)
{
    int err;
    int actstate;

    struct timeval tv;
    if(maxms > 0) {
        tv.tv_sec = maxms / 1000;
        tv.tv_usec = (maxms % 1000) * 1000;
    }


    while(1) {
        actstate = *pptr;

        if(maxms > 0) {
            err = futex(pptr, FUTEX_WAIT, actstate, &tv, NULL, 0);
        } else {
            err = futex(pptr, FUTEX_WAIT, actstate, NULL, NULL, 0);
        }

        if(err != 0) {
            if(errno == 110)
                return p67_err_etime;
            else
                return p67_err_eerrno;
        }

        if(*pptr == state)
            break;
    }

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
