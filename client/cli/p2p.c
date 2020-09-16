#include <string.h>
#include <strings.h>

#include <client/cli/p2p.h>
#include <p67/dml/dml.h>

static p67_hashcntl_t * __p2p_cache = NULL;
static p67_async_t p2p_cache_lock = P67_ASYNC_INTIIALIZER;

p67_err
p2pclient_callback(
    p67_addr_t * addr, p67_pckt_t * msg, int msgl, void * args)
{
    //p67_dml_pretty_print_addr(addr, msg, msgl);
    return p67_dml_handle_msg(addr, msg, msgl, args);
}

p67_hashcntl_t *
__get_p2p_cache(void) {
    if(!__p2p_cache) {
        p67_spinlock_lock(&p2p_cache_lock);
        if(!__p2p_cache) {
            __p2p_cache = p67_hashcntl_new(
                0, p67_p2p_cache_entry_free, NULL);
            p67_cmn_assert_abort(
                !__p2p_cache, 
                "Couldnt initialize p2p cache.");
        }
        p67_spinlock_unlock(&p2p_cache_lock);
    }

    return __p2p_cache;
}

void
p67_p2p_cache_free(void)
{
    p67_hashcntl_free(__p2p_cache);
}

// void
// p67_p2p_free_conn_args(void * args)
// {
//     p67_log("disposing p2p ctx\n");
//     p67_err err;
//     p67_hashcntl_entry_t * e = (p67_hashcntl_entry_t *)args;
//     if((err = p67_hashcntl_remove_and_free(
//             p2p_cache, e->key, e->keyl)) != 0) {
//         p67_err_print_err("Coudlnt free p2p ctx, err was: ", err);
//     }
// }

void
p67_p2p_cache_entry_free(p67_hashcntl_entry_t * e)
{
    if(!e) return;
    p67_p2p_t * p2p = (p67_p2p_t *)e->value;
    
    //p67_thread_sm_t connect_sm;
    //p67_pdp_keepalive_ctx_t keepalive_ctx;

    p67_pdp_free_keepalive_ctx(&p2p->keepalive_ctx);
    p67_net_connect_terminate(&p2p->connect_sm);

    p67_addr_free(p2p->peer_addr);
    
    free(e);
}

p67_p2p_t *
p67_p2p_cache_lookup(p67_addr_t * addr)
{
    p67_hashcntl_entry_t * e = p67_hashcntl_lookup(
        p2p_cache, (unsigned char *)&addr->sock, addr->socklen);
    if(!e) return NULL;
    return (p67_p2p_t *)e->value;
}

p67_err
p67_p2p_cache_accept_by_name(
    p67_addr_t * local_addr,
    p67_addr_t * server_addr,
    p67_net_cred_t * cred,
    const char * name)
{
    assert(name);
    
    p67_err err;

    p67_p2p_t * ctx = p67_p2p_cache_find_by_name(name);
    p67_net_cb_ctx_t cbctx = p67_net_cb_ctx_initializer(p2pclient_callback);
    if(!ctx) return p67_err_enconn;
    //p67_async_t connect_sig = P67_ASYNC_INTIIALIZER;

    if(ctx->should_respond) {
        if(p67_atomic_set_state(&ctx->should_respond, &(int){1}, 0)) {
            err = p67_pdp_write_ack_for_urg(server_addr, &ctx->req);
            if(err) return err;
        }
    }
    
    err = p67_net_start_connect(
        &ctx->connect_sm,
        NULL, //&connect_sig, 
        local_addr, 
        ctx->peer_addr,
        cred, 
        cbctx, 
        NULL);
    if(err) return err;

    //p67_mutex_wait_for_change(&connect_sig, 0, -1);

    err = p67_pdp_start_keepalive_loop(&ctx->keepalive_ctx);

    return err;
}

/*
    gotta be careful when using this function since its not thread safe.
    if p2p_ctx gets disposed this may throw segv fault 
*/
p67_p2p_t *
p67_p2p_cache_find_by_name(const char * name)
{
    int namel = strlen(name), i;
    p67_hashcntl_entry_t * entry;
    p67_p2p_t * ctx;

    for(i = 0; i < p2p_cache->bufferl; i++) {
        if(!(entry = p2p_cache->buffer[i])) continue;
        do {
            ctx = (p67_p2p_t *)entry->value;
            if(namel == ctx->peer_usernamel 
                    && memcmp(name, ctx->peer_username, namel) == 0) {
                return ctx;
            }
            entry = entry->next;
        } while((entry));  
    }

    return NULL;
}

p67_p2p_t *
p67_p2p_cache_add(
    p67_addr_t * remote_addr, 
    const unsigned char * peer_username, 
    int peer_usernamel,
    p67_pdp_urg_hdr_t * req)
{
    assert(remote_addr);
    assert(peer_username);
    assert(peer_usernamel > 0);

    p67_hashcntl_entry_t * e = malloc(
        sizeof(p67_hashcntl_entry_t) +
        remote_addr->socklen + 
        sizeof(p67_p2p_t) + 
        peer_usernamel);

    e->key = (unsigned char *)e + sizeof(p67_hashcntl_entry_t);
    e->keyl = remote_addr->socklen;
    e->next = NULL;
    e->value = e->key + remote_addr->socklen;
    e->valuel = sizeof(p67_p2p_t);

    memcpy(e->key, &remote_addr->sock, remote_addr->socklen);

    p67_p2p_t * p2pctx = (p67_p2p_t *)e->value;
    
    bzero(p2pctx, sizeof(p67_p2p_t));

    p2pctx->peer_addr = p67_addr_ref_cpy(remote_addr);
    p2pctx->state = P67_P2P_STATE_INCOMING;
    p2pctx->peer_username = (char *)e->value + sizeof(p67_p2p_t);
    p2pctx->peer_usernamel = peer_usernamel;
    p2pctx->keepalive_ctx.addr = p67_addr_ref_cpy(remote_addr);
    if(req) {
        p2pctx->should_respond = 1;
        p2pctx->req = *req;
    } else {
        p2pctx->should_respond = 0;
    }

    if(peer_username)
        memcpy(p2pctx->peer_username, peer_username, peer_usernamel);

    if(p67_hashcntl_add(p2p_cache, e) != 0) {
        p67_p2p_cache_entry_free(e);
        return NULL;
    }

    return p2pctx;
}
