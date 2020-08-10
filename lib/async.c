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
            (const struct timespec *)(timeout), \
            (int*)(uaddr2), \
            (int)(val3))

#define futex_wake_all(uaddr) \
    futex(uaddr, FUTEX_WAKE, INT_MAX, NULL, NULL, 0)

void
p67_atomic_wait_exit_and_set(
        p67_async_t * uaddr, p67_async_t pval, p67_async_t nval)
{
    p67_async_t x;
    while(1) {
        x = *uaddr;
        if(x == pval) continue;
        if(p67_atomic_set_state(uaddr, &x, nval)) break;
    }
}

p67_err
p67_mutex_wait_and_set(p67_async_t * uaddr, p67_async_t pval, p67_async_t nval)
{
    p67_async_t state;
    p67_err err;
    do {
        state = *uaddr;

        if(state != pval) {
            if((err = p67_mutex_wait_for_change(uaddr, state, -1)) != 0) {
                return err;
            }
        }

        err = p67_mutex_set_state(uaddr, pval, nval);

        switch(err) {
        case 0:
            return 0;
        case p67_err_easync:
            continue;
        default:
            return err;
        }

    } while(1);
}

p67_err
p67_mutex_set_state(p67_async_t * uaddr, p67_async_t pval, p67_async_t nval)
{
    if(!p67_atomic_set_state(uaddr, &pval, nval))
        return p67_err_easync;
    if(futex_wake_all(uaddr) < 0) {
        return p67_err_eerrno;
    }
    return 0;
}

p67_err
p67_mutex_wait_for_change(int * pptr, int state, int maxms)
{
    int err;

    struct timespec tv;
    if(maxms > 0) {
        tv.tv_sec = maxms / 1000;
        tv.tv_nsec = (maxms % 1000) * 1e6;
    }

    while(1) {

        if(maxms > 0) {
            err = futex(pptr, FUTEX_WAIT, state, &tv, NULL, 0);
        } else {
            err = futex(pptr, FUTEX_WAIT, state, NULL, NULL, 0);
        }
        if(err != 0) {
            if(errno == EAGAIN) {
                continue;
            } else if(errno == 110)
                return p67_err_etime;
            else
                return p67_err_eerrno;
        }

        if(*pptr != state)
            break;
    }

    return 0;
}

p67_err
p67_thread_sm_terminate(p67_thread_sm_t * sm, int timeout)
{
    p67_err err;
    p67_async_t state;

    if(sm->state != P67_THREAD_SM_STATE_RUNNING)
        return p67_err_enconn;

    if((err = p67_mutex_set_state(
                &sm->state, 
                P67_THREAD_SM_STATE_RUNNING, 
                P67_THREAD_SM_STATE_SIG_STOP)) != 0)
        return err;

    err = p67_mutex_wait_for_change(
                &sm->state, 
                P67_THREAD_SM_STATE_SIG_STOP, 
                timeout);
    
    state = sm->state;

    switch(sm->state) {
    case P67_THREAD_SM_STATE_STOP:
        return 0;
    case P67_THREAD_SM_STATE_RUNNING:
        /* this _really_ shouldnt happen */
        return p67_err_easync;
    }

    /* if timeout then just kill the thread */
    if((err & p67_err_etime)) {
        if(p67_mutex_set_state(&sm->state, state, P67_THREAD_SM_STATE_STOP) != 0)
            return p67_err_easync;
        p67_cmn_thread_kill(sm->thr);
        return 0;
    }
    
    return err;
}

p67_err
p67_thread_sm_start(
    p67_thread_sm_t * t, p67_thread_callback cb, void * arg)
{
    p67_err err;

    if(t->state != P67_THREAD_SM_STATE_STOP)
        return p67_err_eaconn;

    p67_thread_sm_lock(t);

    if(t->state != P67_THREAD_SM_STATE_STOP) {
        p67_thread_sm_unlock(t);
        return p67_err_eaconn;
    }

    t->state = P67_THREAD_SM_STATE_RUNNING;

    err = p67_cmn_thread_create(&t->thr, cb, arg);

    p67_thread_sm_unlock(t);

    return err;
}
