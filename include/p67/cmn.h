#if !defined(CMN_H)
#define CMN_H 1

#include "err.h"
#include "log.h"

#define P67_CMN_MICROSEC "\u00b5s"

#include <pthread.h>
#include <arpa/inet.h>
#include <endian.h>
#include <stdint.h>
#include <assert.h>

#define p67_cmn_static_assert(name, test) typedef char __p67_static_assert__##name[( !!(test) )*2-1 ]

#define p67_cmn_static_assert_size(s1, s2) \
    p67_cmn_static_assert(s1##_v_##s2, sizeof(s1) == sizeof(s2))

#define p67_cmn_ntohs(x) ntohs(x)
#define p67_cmn_ntohl(x) ntohl(x)
#define p67_cmn_htons(x) htons(x)
#define p67_cmn_htonl(x) htonl(x)

#if __BYTE_ORDER == __LITTLE_ENDIAN

#define p67_cmn_hton64(x) (((uint64_t)p67_cmn_htonl((x))) << 32 | p67_cmn_htonl((x)>>32))
#define p67_cmn_ntoh64(x) (((uint64_t)p67_cmn_ntohl((x))) << 32 | p67_cmn_ntohl((x)>>32))

#else

#define p67_cmn_hton64(x) (x)
#define p67_cmn_ntoh64(x) (x)

#endif

#define p67_cmn_assert_abort(cnd, msg) \
    if(cnd) { p67_log(msg); abort(); }

#define p67_cmn_ejmp(err, verr, lbl) \
    { err = verr; goto lbl; }

#define P67_CMN_NO_PROTO_ENTER \
    _Pragma("GCC diagnostic push") \
    _Pragma("GCC diagnostic ignored \"-Wmissing-prototypes\"")

#define P67_CMN_NO_PROTO_EXIT \
    _Pragma("GCC diagnostic pop")

typedef pthread_mutex_t p67_mutex_t;

typedef pthread_t p67_thread_t;

typedef unsigned long long p67_cmn_epoch_t;

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
p67_cmn_epoch_ms(p67_cmn_epoch_t * t);

p67_err
p67_cmn_epoch_micro(p67_cmn_epoch_t * t);

p67_err
p67_cmn_sleep_s(int s);

char *
p67_cmn_strdup(const char * str);

/*
    generic refcount functionalities 
    user can add to his structures.
*/

#define P67_CMN_REFCOUNT_FIELDS(prefix) \
    p67_async_t prefix##lock; \
    int         prefix##refcount;

#define P67_CMN_REFCOUNT_INIT_FN(ref, prefix) \
    { (ref)->prefix##refcount = 1; \
      (ref)->prefix##lock = P67_XLOCK_STATE_UNLOCKED; }

#define P67_CMN_REFCOUNT_FREE_FN(ref, prefix, freecb) \
    { \
        if(!(ref)) return;                      \
        p67_spinlock_lock(&(ref)->prefix##lock); \
        (ref)->prefix##refcount--;             \
        if(!(ref)->prefix##refcount) {         \
            p67_spinlock_unlock(&(ref)->prefix##lock); \
            p67_cmn_sleep_ms(1);               \
            freecb(ref);                              \
        } else {                                        \
            p67_spinlock_unlock(&(ref)->prefix##lock); \
        }                                               \
    }

#define P67_CMN_REFCOUNT_REFCPY_FN(ref, prefix)        \
    {                                               \
        if(!(ref)) return NULL;                     \
        p67_spinlock_lock(&(ref)->prefix##lock);   \
        if(!(ref)->prefix##refcount) return NULL; \
        (ref)->prefix##refcount++;                    \
        p67_spinlock_unlock(&(ref)->prefix##lock); \
        return ref;                                     \
    }

#endif
