/*
    timeout peers
*/

#include <string.h>

#include "net.h"
#include "timeout.h"

typedef struct p67_timeout_entry {
    p67_addr_t  * addr;
    /* time when address should be freed */
    p67_cmn_epoch_t tf;     
} p67_timeout_entry_t;

struct p67_timeout {
    p67_hashcntl_t * ix;
    p67_thread_sm_t loophndl;
};

P67_CMN_NO_PROTO_ENTER
void
p67_timeout_entry_free(
P67_CMN_NO_PROTO_EXIT
    p67_hashcntl_entry_t * e)
{
    p67_timeout_entry_t * te = (p67_timeout_entry_t *)e->value;
    p67_hashcntl_entry_t * node_entry;
    p67_node_t * node;
    if(!(node_entry = p67_hashcntl_lookup(
            p67_node_cache(), 
            (unsigned char *)&te->addr->sock, 
            te->addr->socklen))) {
        p67_addr_free(te->addr);
        free(e);
        return;
    }
    node = (p67_node_t *)node_entry->value;
    /*
        one could also remove node from cache.
        in that case peer could connect 
        but would have to go through more restrict authorization process
    */
    node->state = P67_NODE_STATE_NODE;
    p67_addr_free(te->addr);
    free(e);
}

P67_CMN_NO_PROTO_ENTER
void *
p67_timeout_run_loop(
P67_CMN_NO_PROTO_EXIT
    void * args)
{
    if(!args) return NULL;
    p67_timeout_entry_t * te;
    p67_timeout_t * ctx = (p67_timeout_t *)args;
    size_t i = 0;
    p67_cmn_epoch_t now;
    p67_err err;

    while(1) {
        p67_mutex_wait_for_change(
            &ctx->loophndl.state, P67_THREAD_SM_STATE_RUNNING, 1000);
        if(ctx->loophndl.state != P67_THREAD_SM_STATE_RUNNING) {
            p67_mutex_set_state(
                &ctx->loophndl.state, ctx->loophndl.state, P67_THREAD_SM_STATE_STOP);
            //ctx->loophndl.state = P67_THREAD_SM_STATE_STOP;
            return NULL;
        }
        if(ctx->ix->count == 0)
            continue;
        if((err = p67_cmn_epoch_ms(&now)) != 0) {
            p67_err_print_err(
                "timeout_loop: couldnt read epoch. Error was: ", err);
            continue;
        }
        for(i = 0; i < ctx->ix->bufferl; i++) {
            if(!ctx->ix->buffer[i])
                continue;
            if(ctx->ix->buffer[i]->next) {
                /*
                    if there are more elements in this hashtbl node
                    then stay in it.
                */
                i--;
            }
            te = (p67_timeout_entry_t *)ctx->ix->buffer[i]->value;
            if(te->tf <= now) {
                err = p67_hashcntl_remove_and_free(
                    ctx->ix, 
                    (uint8_t *)&te->addr->sock,
                    te->addr->socklen);
                if(err != 0) {
                    p67_err_print_err(
                        "timeout_loop: couldnt unlock address. Error was: ", 
                        err);
                }
            }
        }
    }
}

p67_timeout_t *
p67_timeout_create(size_t capacity, p67_err * err)
{
    if(capacity == 0) {
        capacity = P67_TIMEOUT_DEFAULT_LEN;
    }

    p67_err __err;

    p67_timeout_t * ret = malloc(sizeof(p67_timeout_t));
    if(!ret) return NULL;

    ret->loophndl.mutex = P67_XLOCK_STATE_UNLOCKED;
    ret->loophndl.state = P67_THREAD_SM_STATE_STOP;

    ret->ix = p67_hashcntl_new(
        capacity, p67_timeout_entry_free, err);
    if(!ret->ix) {
        free(ret);
        return NULL;
    }

    __err = p67_thread_sm_start(
            &ret->loophndl, p67_timeout_run_loop, ret);

    if(__err != 0) {
        if(err) *err = __err;
        return NULL;
    } else {
        if(err) *err = 0;
        return ret;
    }

}

void
p67_timeout_free(p67_timeout_t * t)
{
    if(!t) return;
    p67_thread_sm_terminate(&t->loophndl, 2000);
    p67_hashcntl_free(t->ix);
    free(t);
}

p67_err
p67_timeout_addr_for_epoch(
    p67_timeout_t * ctx, 
    p67_addr_t * addr,
    p67_cmn_epoch_t timeout_duration_ms,
    int with_shutdown)
{
    if(!addr || !ctx) return p67_err_einval;

    p67_timeout_entry_t * timeout_entry;
    p67_hashcntl_entry_t * entry;
    p67_cmn_epoch_t now;
    p67_err err;
    
    entry = malloc(
        sizeof(p67_hashcntl_entry_t) + 
        addr->socklen + 
        sizeof(p67_timeout_entry_t));
    if(!entry) return p67_err_eerrno;

    if((err = p67_cmn_epoch_ms(&now)) != 0) {
        free(entry);
        return err;
    }

    if((err = p67_timeout_addr(addr, with_shutdown)) != 0) {
        free(entry);
        return err;
    }

    entry->key = (unsigned char *)entry + sizeof(p67_hashcntl_entry_t);
    memcpy(entry->key, &addr->sock, addr->socklen);
    entry->keyl = addr->socklen;
    entry->next = NULL;
    entry->value = entry->key + addr->socklen;
    entry->valuel = sizeof(p67_timeout_entry_t);

    timeout_entry = (p67_timeout_entry_t *)entry->value;
    timeout_entry->addr = p67_addr_ref_cpy(addr);
    if(!timeout_entry->addr) return p67_err_einval;
    timeout_entry->tf = timeout_duration_ms + now;

    return p67_hashcntl_add(ctx->ix, entry);
}

p67_err
p67_timeout_addr(p67_addr_t * addr, int with_shutdown)
{
    if(!addr) return p67_err_einval;
    p67_hashcntl_entry_t * entry;
    p67_node_t * node;
    if(!(entry = p67_hashcntl_lookup(
            p67_node_cache(), 
            (unsigned char *)&addr->sock, 
            addr->socklen))) {
        return p67_err_enconn;
    }
    node = (p67_node_t *)entry->value;
    node->state = P67_NODE_STATE_QUEUE;
    if(!with_shutdown)
        return 0;
    return p67_conn_shutdown(addr);
}

