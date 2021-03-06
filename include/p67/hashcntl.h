#if !defined(P67_HASHCNTL_H)
#define P67_HASHCNTL_H 1

#include "async.h"

typedef struct p67_hashcntl_entry p67_hashcntl_entry_t; 

typedef struct p67_hashcntl p67_hashcntl_t;

#define P67_HASHCNTL_DEFAULT_BUFFERL 337

typedef void (* p67_hashcntl_free_entry_cb)(p67_hashcntl_entry_t *);

struct p67_hashcntl {
    p67_hashcntl_entry_t ** buffer;
    size_t bufferl;
    p67_async_t lock;
    int count;
    p67_hashcntl_free_entry_cb free_entry;

    p67_thread_sm_t ttlsm;
    int ttl;
    p67_async_t sig;

    P67_CMN_REFCOUNT_FIELDS(_)
};

#define P67_HASHCNTL_ENTRY_PADDING_SIZE \
    (sizeof(size_t)+sizeof(p67_hashcntl_entry_t *)+sizeof(p67_cmn_epoch_t))

struct p67_hashcntl_entry {
    void * key;
    size_t keyl;
    void * value;
    /* pad */
    size_t valuel;
    p67_hashcntl_entry_t * next;
    p67_cmn_epoch_t ts;
};

#define p67_hashcntl_lock(ctx) p67_spinlock_lock(&ctx->lock);

#define p67_hashcntl_unlock(ctx) p67_spinlock_unlock(&ctx->lock)

void
p67_hashcntl_free(p67_hashcntl_t * ctx);

void
p67_hashcntl_remove_all(p67_hashcntl_t * ctx);

p67_hashcntl_t *
p67_hashcntl_new(
    size_t bufferl, 
    p67_hashcntl_free_entry_cb free_entry, 
    p67_err * err);

p67_err
p67_hashcntl_add(p67_hashcntl_t * ctx, p67_hashcntl_entry_t * item);

p67_hashcntl_entry_t *
p67_hashcntl_lookup(
    p67_hashcntl_t * ctx, 
    const void * key, size_t keyl);

p67_hashcntl_entry_t *
p67_hashcntl_remove(
    p67_hashcntl_t * ctx, 
    const void * key, size_t keyl);

p67_err
p67_hashcntl_remove_and_free(
    p67_hashcntl_t * ctx, 
    const void * key, size_t keyl);

p67_hashcntl_t *
p67_hashcntl_refcpy(p67_hashcntl_t * ctx);

#define p67_hashcntl_getter_fn(spin_val, val, cache_len, free_fn, errmsg)  \
    { \
        if(!(val)) {                               \
            p67_spinlock_lock(&(spin_val));      \
            if(!(val)) {                   \
                (val) = p67_hashcntl_new(        \
                    (cache_len), (free_fn), NULL);     \
                p67_cmn_assert_abort(                           \
                    !(val),                          \
                    errmsg);    \
            }                                       \
            p67_spinlock_unlock(&(spin_val));        \
        }                                                 \
        return (val);                                    \
    }

p67_err
p67_hashcntl_set_ttl(p67_hashcntl_t * ctx, int ttl);

void
p67_hashcntl_foreach(
    p67_hashcntl_t * ctx, void (* callback)(p67_hashcntl_entry_t * item));

#endif
