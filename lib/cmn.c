#include <pthread.h>

#include <unistd.h>

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


