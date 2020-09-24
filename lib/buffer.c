#include <stdlib.h>
#include <string.h>

#include <p67/async.h>
#include <p67/buffer.h>
#include <p67/log.h>

struct p67_buffer {
    unsigned char * buff;
    p67_async_t lock;
    int buffl;
    int refcount;
    unsigned int is_cstr : 1; 
};

#define p67_buffer_lock(b) \
    p67_spinlock_lock(&b->lock)
#define p67_buffer_unlock(b) \
    p67_spinlock_unlock(&b->lock)

p67_buffer_t *
p67_buffer_new(const char * src, int len)
{
    p67_buffer_t * ret;
    if(len <= 0)
        len = strlen(src) + 1;
    if(!(ret = malloc(sizeof(p67_buffer_t) + len)))
        return NULL;
    ret->buff = (unsigned char *)ret + sizeof(p67_buffer_t);
    ret->buffl = len;
    ret->refcount = 1;
    ret->is_cstr = src[len - 1] == 0 ? 1 : 0;
    memcpy(ret->buff, src, len);
    return ret;
}

const char * 
p67_buffer_cstr(const p67_buffer_t * buff)
{
    if(!buff || !buff->is_cstr)
        return NULL;
    return (const char *)buff->buff;
}

unsigned char *
p67_buffer_arr(const p67_buffer_t * b, int * len)
{
    if(!b) return NULL;
    if(len) *len = b->buffl;
    return b->buff;
}

p67_buffer_t *
p67_buffer_ref_cpy(p67_buffer_t * src)
{
    assert(src);
    
    p67_buffer_lock(src);

    src->refcount++;

    p67_buffer_unlock(src);

    return src;
}

void
p67_buffer_free(p67_buffer_t * b)
{
    if(!b) return;
    
    p67_buffer_lock(b);

    if(b->refcount < 1) {
        p67_log(
            "Warn: Tried to perform free on buffer with refcount = %u", 
            b->refcount);
        p67_buffer_unlock(b);
        return;
    }

    if(b->refcount == 1) {
        b->refcount--;
        p67_buffer_unlock(b);
        p67_cmn_sleep_ms(10);
        free(b);
    } else {
        b->refcount--;
        p67_buffer_unlock(b);
    }
}
