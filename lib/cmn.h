#if !defined(CMN_H)
#define CMN_H 1

#include "err.h"
#include <pthread.h>

/*
    cross platform wrappers around common procedures
*/

typedef pthread_mutex_t p67_mutex_t;

typedef pthread_t p67_thread_t;

typedef void * (* p67_thread_callback)(void *);

#define P67_CMN_MUTEX_INITIALIZER PTHREAD_MUTEX_INITIALIZER

p67_err
p67_cmn_mutex_lock(p67_mutex_t * mutex);

p67_err
p67_cmn_mutex_unlock(p67_mutex_t * mu);

p67_err
p67_cmn_thread_create(
    p67_thread_t * thr, 
    p67_thread_callback cb, 
    void * arg);

p67_err
p67_cmn_thread_kill(p67_thread_t t);

p67_err
p67_cmn_sleep_ms(int ms);

p67_err
p67_cmn_sleep_micro(int micro);

#endif
