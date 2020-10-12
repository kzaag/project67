/* generic hash table controls */

#include <string.h>

#include <p67/hash.h>
#include <p67/hashcntl.h>

/* private functions */
P67_CMN_NO_PROTO_ENTER

static void
__p67_hashcntl_free(p67_hashcntl_t * ctx)
{
    if(!ctx) return;
    
    size_t i;
    p67_hashcntl_entry_t * entry, * next_entry;

    if(ctx->ttl > 0) {
        p67_thread_sm_terminate(&ctx->ttlsm, 3000);
    }

    if(!(ctx->buffer && ctx->free_entry)) {
        free(ctx);
        return;
    }

    for(i = 0; i < ctx->bufferl; i++) {
        if(!(entry = ctx->buffer[i]))
            continue;        
        do {
            next_entry = entry->next;
            ctx->free_entry(entry);
        } while((entry = next_entry));
    }
    free(ctx->buffer);
    free(ctx);

    return;
}


P67_CMN_NO_PROTO_EXIT

void
p67_hashcntl_free(p67_hashcntl_t * ctx)
{
    P67_CMN_REFCOUNT_FREE_FN(ctx, _, __p67_hashcntl_free)
}

p67_hashcntl_t *
p67_hashcntl_refcpy(p67_hashcntl_t * ctx)
{
    P67_CMN_REFCOUNT_REFCPY_FN(ctx, _)
}

p67_hashcntl_t *
p67_hashcntl_new(
    size_t bufferl, 
    p67_hashcntl_free_entry_cb free_entry, 
    p67_err * err)
{
    p67_hashcntl_t * ctx;

    if((ctx = malloc(sizeof(*ctx))) == NULL) {
        if(err != NULL) *err = p67_err_eerrno; 
        return NULL;
    }

    if(bufferl <= 0) {
        bufferl = P67_HASHCNTL_DEFAULT_BUFFERL;
    }

    if((ctx->buffer = calloc(
                bufferl,
                sizeof(**ctx->buffer))) == NULL) {
        free(ctx);
        if(err != NULL) *err = p67_err_eerrno; 
        return NULL;
    }

    ctx->bufferl = bufferl;
    ctx->lock = P67_ASYNC_INTIIALIZER;
    ctx->free_entry = free_entry;
    ctx->count = 0;
    ctx->ttl = -1;

    P67_CMN_REFCOUNT_INIT_FN(ctx, _)

    return ctx;
}

p67_err
p67_hashcntl_add(p67_hashcntl_t * ctx, p67_hashcntl_entry_t * item)
{
    p67_hash_t hash = p67_hash_fn(item->key, item->keyl, ctx->bufferl);
    
    p67_hashcntl_entry_t ** prev_entry, * entry;

    p67_hashcntl_lock(ctx);

    for(prev_entry = ctx->buffer + hash; (entry = *prev_entry); prev_entry=&entry->next) {
        if(item->keyl == entry->keyl 
                    && (memcmp(item->key, entry->key, entry->keyl) == 0)) {
            p67_hashcntl_unlock(ctx);
            return p67_err_eaconn;
        }
    }

    item->next = NULL;
    if(ctx->ttl > 0) {
        if(p67_cmn_epoch_ms(&item->ts)) {
            return p67_err_eerrno;
        }
    }

    *prev_entry = item;

    ctx->count++;

    if(ctx->ttl > 0) p67_mutex_set_state(&ctx->sig, 0, 1);

    p67_hashcntl_unlock(ctx);

    return 0;
}

p67_hashcntl_entry_t *
p67_hashcntl_lookup(
    p67_hashcntl_t * ctx, 
    const void * key, size_t keyl)
{
    p67_hash_t hash = p67_hash_fn(key, keyl, ctx->bufferl);
    p67_hashcntl_entry_t ** prev_entry, * entry;

    p67_hashcntl_lock(ctx);

    for(prev_entry = ctx->buffer + hash; (entry = *prev_entry); prev_entry=&entry->next) {
        if(entry->keyl == keyl 
                    && (memcmp(entry->key, key, keyl) == 0)) {
            p67_hashcntl_unlock(ctx);
            return entry;
        }
    }
    
    p67_hashcntl_unlock(ctx);
    return NULL;
}

p67_hashcntl_entry_t *
p67_hashcntl_remove(
    p67_hashcntl_t * ctx, 
    const void * key, size_t keyl)
{
    p67_hash_t hash = p67_hash_fn(key, keyl, ctx->bufferl);
    p67_hashcntl_entry_t * prev_entry = NULL, * entry;

    p67_hashcntl_lock(ctx);

    for(entry = ctx->buffer[hash]; entry != NULL; entry=entry->next) {
        if(keyl == entry->keyl 
                    && (memcmp(entry->key, key, keyl) == 0))
            break;
        prev_entry = entry;
    }

    if(entry == NULL) {
        p67_hashcntl_unlock(ctx);
        return NULL;
    }

    if(prev_entry == NULL) {
        ctx->buffer[hash] = NULL;
    } else {
        prev_entry->next = entry->next;
    }

    ctx->count--;
    p67_hashcntl_unlock(ctx);

    return entry;
}

p67_err
p67_hashcntl_remove_and_free(
    p67_hashcntl_t * ctx, 
    const void * key, size_t keyl)
{
    p67_hashcntl_entry_t * e = p67_hashcntl_remove(ctx, key, keyl);
    if(!e)
        return p67_err_enconn;
    if(ctx->free_entry)
        ctx->free_entry(e);
    return 0;
}

P67_CMN_NO_PROTO_ENTER  
void *
p67_hashcntl_ttl_loop(
P67_CMN_NO_PROTO_EXIT
    void * args)
{
    p67_err err;
    p67_hashcntl_t * ctx = (p67_hashcntl_t *)args;
    p67_hashcntl_entry_t * e;
    p67_cmn_epoch_t now;
    unsigned char tmpkey[P67_HASH_KEY_MAX_LENGTH];
    int tmpkeyl, ms_until_to;
    int32_t next_sleep_ms = 1;
    size_t i;

    #define tsm (&ctx->ttlsm)

    while(1) {
        if(ms_until_to == INT32_MAX) ms_until_to = -1;
        err = p67_mutex_wait_for_change(&ctx->sig, 0, next_sleep_ms);
        if(err == p67_err_eerrno) goto end;
        ctx->sig = 0;

        if(p67_thread_sm_stop_requested(tsm)) {
            err = 0;
            goto end;
        }
        
        if((err = p67_cmn_epoch_ms(&now)))
            goto end;

        next_sleep_ms = INT32_MAX;
 
        for(i = 0; i < ctx->bufferl; i++) {
            e = ctx->buffer[i];
            if(!e) continue;
            p67_hashcntl_lock(ctx);
            e = ctx->buffer[i];
            if(!e) continue;
            ms_until_to = (e->ts + ctx->ttl) - now;
            if(ms_until_to <= 0) {
                memcpy(tmpkey, e->key, e->keyl);
                tmpkeyl = e->keyl;
                p67_hashcntl_unlock(ctx);
                p67_hashcntl_remove_and_free(ctx, tmpkey, tmpkeyl);
            } else {
                p67_hashcntl_unlock(ctx);
                if(ms_until_to < next_sleep_ms) {
                    next_sleep_ms = ms_until_to;
                }
            }
        }

    }

end:
    if(err) {
        p67_err_print_err("Terminating hashcntl ttl loop with error/s: ", err);
    }
    p67_thread_sm_stop_notify(tsm);
    #undef tsm
    return NULL;
}

P67_CMN_NO_PROTO_ENTER
p67_err
p67_hashcntl_ttl_start_loop(
P67_CMN_NO_PROTO_EXIT
    p67_hashcntl_t * ctx)
{
    return p67_thread_sm_start(&ctx->ttlsm, p67_hashcntl_ttl_loop, ctx);
}

p67_err
p67_hashcntl_set_ttl(p67_hashcntl_t * ctx, int ttl)
{
    assert(ctx);
    
    ctx->ttl = ttl;
    ctx->sig = 0;
    ctx->ttlsm.mutex = P67_XLOCK_STATE_UNLOCKED;
    ctx->ttlsm.state = 0;
    ctx->ttlsm.thr = 0;
    
    return p67_hashcntl_ttl_start_loop(ctx);
}

void
p67_hashcntl_foreach(
    p67_hashcntl_t * ctx, void (* callback)(p67_hashcntl_entry_t * item))
{
    assert(ctx);
    assert(callback);

    p67_hashcntl_lock(ctx);
    p67_hashcntl_entry_t ** e, * ne;

    for(e = ctx->buffer; e < ctx->buffer + ctx->bufferl; e++) {
        ne = *e;
        if(!ne) continue;
        do {
            callback(ne);
            ne=ne->next;
        } while((ne));
    }

    p67_hashcntl_unlock(ctx);
}
