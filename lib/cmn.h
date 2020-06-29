#if !defined(CMN_H)
#define CMN_H 1

#include "err.h"
#include <pthread.h>

/*
    cross platform wrappers around common procedures
*/

typedef pthread_mutex_t p67_mutex_t;

#define P67_CMN_MUTEX_INITIALIZER PTHREAD_MUTEX_INITIALIZER

p67_err
p67_cmn_mutex_lock(p67_mutex_t * mutex);

p67_err
p67_cmn_mutex_unlock(p67_mutex_t * mu);


#endif
