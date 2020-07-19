#if !defined(ASYNC_H)
#define ASYNC_H 1

/*
    locking and synchronization helpers
*/

#include <stdatomic.h>

#include "cmn.h"
#include "err.h"

#define P67_SL_STATE_LOCKED   1
#define P67_SL_STATE_UNLOCKED 0

typedef int p67_async_t;

#define P67_ASYNC_INTIIALIZER 0

#define PARG(a) &(p67_async_t){(a)}

/*
    try to move state from src to dest
    returns 1 on success 0 on fail
*/
#define p67_atomic_set_state(uaddr, optr, nval) \
    atomic_compare_exchange_strong((uaddr), (optr), (nval))

#define p67_atomic_set_state_any(uaddr, nval) \
    p67_atomic_set_state((uaddr), PARG(*(uaddr)), nval)

/*
    wait for sm to enter state a and set it to state b.
    may cause excessive cpu usage if used incorrectly
*/
#define p67_atomic_wait_and_set(uaddr, optr, nval) \
    { while(!p67_atomic_set_state((uaddr), (optr), (nval))); }

#define p67_atomic_must_set_state(lptr, a, b) \
    if(!p67_atomic_set_state(lptr, PARG(a), b)) { \
        fprintf(stderr, "XLOCK state changed unexpectedly. Aborting.\n"); \
        exit(2); }

void
p67_atomic_wait_exit_and_set(
            p67_async_t * uaddr, p67_async_t pval, p67_async_t nval);

/* 1 on success 0 on failure */
p67_err
p67_mutex_set_state(
            p67_async_t * uaddr, p67_async_t pval, p67_async_t nval);

p67_err
p67_mutex_wait_and_set(
            p67_async_t * uaddr, p67_async_t pval, p67_async_t nval);

/*
    waits for async to leave specified state for up to maxms milliseconds.
*/
p67_err
p67_mutex_wait_for_change(int * pptr, int state, int maxms);

#define P67_XLOCK_STATE_UNLOCKED 0
#define P67_XLOCK_STATE_LOCKED   1

#define p67_spinlock_lock(lptr) \
    p67_atomic_wait_and_set((lptr), PARG(P67_XLOCK_STATE_UNLOCKED), P67_XLOCK_STATE_LOCKED)

/*
    lock if unlocked then return 1. else return 0
*/
#define p67_spinlock_lock_once(lptr) \
    p67_atomic_set_state(lptr, PARG(P67_XLOCK_STATE_UNLOCKED), P67_XLOCK_STATE_LOCKED)

#define p67_spinlock_unlock(lptr) \
    if(!p67_atomic_set_state(lptr, PARG(P67_XLOCK_STATE_LOCKED), P67_XLOCK_STATE_UNLOCKED)) { \
        fprintf(stderr, "XLOCK state changed unexpectedly. Aborting.\n"); \
        exit(2); }

#define p67_mutex_lock(lptr) \
    p67_mutex_wait_and_set(lptr, P67_XLOCK_STATE_UNLOCKED, P67_XLOCK_STATE_LOCKED)

#define p67_mutex_unlock(lptr) \
    if(p67_mutex_set_state((lptr), P67_XLOCK_STATE_LOCKED, P67_XLOCK_STATE_UNLOCKED) != 0) {\
        fprintf(stderr, "XLOCK state changed unexpectedly. Aborting.\n"); \
        exit(2); }


#define P67_THREAD_SM_STATE_STOP     0
#define P67_THREAD_SM_STATE_RUNNING  1
#define P67_THREAD_SM_STATE_SIG_STOP 2

#define P67_THREAD_SM_TIMEOUT_DEF 5000

#define P67_THREAD_SM_INITIALIZER {0}

typedef struct p67_thread_sm {
    p67_async_t  state;
    p67_thread_t thr;
} p67_thread_sm_t;

p67_err
p67_thread_sm_terminate(p67_thread_sm_t * sm, int timeout);

#endif