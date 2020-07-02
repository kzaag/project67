#include <pthread.h>
#include <signal.h>
#include <unistd.h>
#include <sys/time.h>
#include <time.h>

#include "err.h"
#include "cmn.h"

#define LOCK_MAX_RETRIES 3

p67_err
p67_cmn_mutex_lock(p67_mutex_t * mutex)
{
    int left = LOCK_MAX_RETRIES;
    while(left-->0) {
        if(pthread_mutex_trylock(mutex) == 0) break;
        sleep(1);
    }

    if(left < 0) return p67_err_eerrno;
    return 0;
}

p67_err
p67_cmn_mutex_unlock(p67_mutex_t * mu)
{
    int left = LOCK_MAX_RETRIES;
    while(left-->0) {
        if(pthread_mutex_unlock(mu) == 0) break;
        sleep(1);
    }

    if(left < 0) return p67_err_eerrno;
    return 0;
}

p67_err
p67_cmn_thread_create(p67_thread_t * thr, p67_thread_callback cb, void * arg)
{
    if(pthread_create(thr, NULL, cb, arg) != 0)
        return p67_err_eerrno;
    return 0;
}

p67_err
p67_cmn_thread_kill(p67_thread_t t)
{
    if(pthread_cancel(t) != 0) {
        return p67_err_eerrno;
    }
    return 0;
}

p67_err
p67_cmn_sleep_ms(int ms)
{
    struct timespec ts;
    ts.tv_sec = ms / 1000;
    ts.tv_nsec = (ms % 1000) * 1000000;
    if(nanosleep(&ts, &ts) != 0) return p67_err_einval;
    return 0;
}
