#if !defined(CMN_H)
#define CMN_H 1

#include "err.h"
#include <pthread.h>
#include <arpa/inet.h>

#define p67_cmn_ntohs(x) ntohs(x)
#define p67_cmn_ntohl(x) ntohl(x)
#define p67_cmn_htons(x) htons(x)
#define p67_cmn_htonl(x) htonl(x)

#include <endian.h>
#include <stdint.h>

#if __BYTE_ORDER == __LITTLE_ENDIAN

#define p67_cmn_hton64(x) (((uint64_t)p67_cmn_htonl((x))) << 32 | p67_cmn_htonl((x)>>32))
#define p67_cmn_ntoh64(x) (((uint64_t)p67_cmn_ntohl((x))) << 32 | p67_cmn_ntohl((x)>>32))

#else

#define p67_cmn_hton64(x) (x)
#define p67_cmn_ntoh64(x) (x)

#endif

/*
    TODO: cross platform wrappers around common procedures
*/

typedef pthread_mutex_t p67_mutex_t;

typedef pthread_t p67_thread_t;

typedef unsigned long long p67_epoch_t;

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

p67_err
p67_cmn_time_ms(p67_epoch_t * t);

p67_err
p67_cmn_sleep_s(int s);

#endif
