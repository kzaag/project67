/* generic hash table controls */

#include <string.h>

#include "hash.h"
#include "hashcntl.h"

void
p67_hashcntl_free(p67_hashcntl_t * ctx)
{
    if(!ctx) return;
    
    size_t i;
    p67_hashcntl_entry_t * entry, * next_entry;

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
    ctx->can_lock = 1;
    ctx->lock = P67_ASYNC_INTIIALIZER;
    ctx->free_entry = free_entry;

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

    *prev_entry = item;

    ctx->count++;

    p67_hashcntl_unlock(ctx);

    return 0;
}

p67_hashcntl_entry_t *
p67_hashcntl_lookup(
    p67_hashcntl_t * ctx, 
    const unsigned char * key, size_t keyl)
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
    const unsigned char * key, size_t keyl)
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
    const unsigned char * key, size_t keyl)
{
    p67_hashcntl_entry_t * e = p67_hashcntl_remove(ctx, key, keyl);
    if(!e)
        return p67_err_enconn;
    if(ctx->free_entry)
        ctx->free_entry(e);
    return 0;
}