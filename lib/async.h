#if !defined(ASYNC_H)
#define ASYNC_H 1

#include <stdatomic.h>

#include "cmn.h"
#include "err.h"

#define P67_ASYNC_STATE_STOP     0
#define P67_ASYNC_STATE_RUNNING  1
#define P67_ASYNC_STATE_SIG_STOP 2

#define P67_TO_DEF 5000

#define P67_ASYNC_INITIALIZER {0}

typedef struct p67_async {
    int          state;
    p67_thread_t thr;
} p67_async_t;

p67_err
p67_async_set_state(p67_async_t * async, int old, int new);

p67_err
p67_sm_wait_for(int * pptr, int state, int maxms);

#define p67_async_wait_change(async, __state, __maxms) \
    p67_sm_wait_for(&async->state, __state, __maxms)

p67_err
p67_async_terminate(p67_async_t * async, int to);

#define p67_sm_update(pptr, optr, nval) \
    atomic_compare_exchange_strong(pptr, optr, nval)

p67_err
p67_sm_wake_all(int * pptr);

#endif