#include <string.h>
#include <strings.h>

#include <client/cli/p2p.h>
#include <p67/dml/dml.h>
#include <p67/log.h>

static p67_hashcntl_t * __p2p_cache = NULL;
static p67_async_t p2p_cache_lock = P67_ASYNC_INTIIALIZER;

void
p67_p2p_cache_entry_free(p67_hashcntl_entry_t * e);

p67_err
p67_p2p_callback(
    p67_addr_t * addr, p67_pckt_t * msg, int msgl, void * args)
{
    p67_p2p_t * p = p67_p2p_cache_lookup(addr);
    if(p) {
        const p67_dml_hdr_store_t * h = p67_dml_parse_hdr(msg, msgl, NULL);
        if(!h)
            return p67_err_epdpf;
        switch(h->cmn.cmn_stp) {
        case P67_DML_STP_PDP_URG:
            if(h->cmn.cmn_utp != 0) {
                p67_log(
                    "%s:%s: %.*s\n",
                    addr->hostname, addr->service,
                    msgl-sizeof(p67_pdp_urg_hdr_t),
                    msg+sizeof(p67_pdp_urg_hdr_t));
            }
            break;
        case P67_DML_STP_QDP_DAT:
            if(p->audio.qdp)
                return p67_qdp_handle_data(addr, msg, msgl, p->audio.qdp);
            else
                // not ready to accept stream so just ignore. 
                // maybe notify user / kill connection?
                return 0;
            break;
        }
    }
    //p67_dml_pretty_print_addr(addr, msg, msgl);
    return p67_dml_handle_msg(addr, msg, msgl, NULL);
}

void
p67_p2p_shutdown_cb(p67_addr_t * addr)
{
    p67_err err = p67_hashcntl_remove_and_free(
         p2p_cache, &addr->sock, addr->socklen);
    if(err)
        p67_err_print_err("In p2p_free_args couldnt remove p2p context. ", err);
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

    p67_thread_sm_terminate(&p2p->audio.i_sm, 100);
    p67_thread_sm_terminate(&p2p->audio.o_sm, 100);

    p67_audio_free(p2p->audio.i);
    p67_audio_free(p2p->audio.o);
    p67_qdp_free(p2p->audio.qdp);

    /*
        DONT shutdown connection here.
        shutdown will call this function!!!
    */
    //p67_net_shutdown(p2p->peer_addr);
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

/*
    TODO: add timeouts so command can properly terminate
*/
p67_err
p67_p2p_cache_accept_by_name(
    p67_addr_t * local_addr,
    p67_addr_t * server_addr,
    p67_net_cred_t * cred,
    const char * name,
    p67_async_t * connect_sig)
{
    assert(name);
    
    p67_err err;

    p67_p2p_t * ctx = p67_p2p_cache_find_by_name(name);

    p67_net_cb_ctx_t cbctx = p67_net_cb_ctx_initializer(p67_p2p_callback);
    cbctx.on_shutdown = p67_p2p_shutdown_cb;

    if(!ctx) return p67_err_enconn;

    if(!p67_node_insert(ctx->peer_addr, NULL, 0, NULL, NULL, P67_NODE_STATE_NODE)) {
        p67_log("warn: couldnt add node. Already exists?\n");
        //return p67_err_einval;
    }

    if(ctx->should_respond) {
        if(p67_atomic_set_state(&ctx->should_respond, &(int){1}, 0)) {
            err = p67_pdp_write_ack_for_urg(server_addr, &ctx->req);
            if(err) return err;
        }
    }
    
    err = p67_net_start_connect(
        &ctx->connect_sm,
        connect_sig, 
        local_addr, 
        ctx->peer_addr,
        cred, 
        cbctx, 
        NULL);
    if(err) return err;

    // client will wait
    //p67_mutex_wait_for_change(&connect_sig, 0, -1);

    /*
        keeaplive thread can be started without active connection 
            - it will wait until connection appears.
    */
    if((err = p67_pdp_start_keepalive_loop(&ctx->keepalive_ctx))) {
        return err;
    }

    return err;
}

/*
    this takes O(N)
    TODO: add hash index.
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
    e->value = (unsigned char *)e->key + remote_addr->socklen;
    e->valuel = sizeof(p67_p2p_t);

    memcpy(e->key, &remote_addr->sock, remote_addr->socklen);

    p67_p2p_t * p2pctx = (p67_p2p_t *)e->value;
    
    bzero(p2pctx, sizeof(p67_p2p_t));

    p2pctx->peer_addr = p67_addr_ref_cpy(remote_addr);
    p2pctx->peer_username = (char *)e->value + sizeof(p67_p2p_t);
    p2pctx->peer_usernamel = peer_usernamel;
    p2pctx->keepalive_ctx.addr = p67_addr_ref_cpy(remote_addr);
    if(req) {
        p2pctx->should_respond = 1;
        p2pctx->req = *req;
    } else {
        p2pctx->should_respond = 0;
    }
    p67_p2p_audio_init(p2pctx->audio);

    if(peer_username)
        memcpy(p2pctx->peer_username, peer_username, peer_usernamel);

    if(p67_hashcntl_add(p2p_cache, e) != 0) {
        p67_p2p_cache_entry_free(e);
        return NULL;
    }

    return p2pctx;
}

p67_err 
p67_p2p_shutdown(p67_addr_t * addr)
{
    // err = p67_hashcntl_remove_and_free(
    //     p2p_cache, (p67_pckt_t *)&addr->sock, addr->socklen);

    return p67_net_shutdown(addr);
}
