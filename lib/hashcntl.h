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

    // flags

    uint8_t can_lock : 1;
};

struct p67_hashcntl_entry {
    unsigned char * key;
    size_t keyl;
    unsigned char * value;
    size_t valuel;
    p67_hashcntl_entry_t * next;
};

#define p67_hashcntl_lock(ctx) \
    if(ctx->can_lock) p67_spinlock_lock(&ctx->lock);

#define p67_hashcntl_unlock(ctx) \
    if(ctx->can_lock) { p67_spinlock_unlock(&ctx->lock); }

void
p67_hashcntl_free(p67_hashcntl_t * ctx);

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
    unsigned char * key, size_t keyl);

p67_hashcntl_entry_t *
p67_hashcntl_remove(
    p67_hashcntl_t * ctx, 
    unsigned char * key, size_t keyl);

p67_err
p67_hashcntl_remove_and_free(
    p67_hashcntl_t * ctx, 
    unsigned char * key, size_t keyl);

#endif
