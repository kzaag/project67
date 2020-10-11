#include <string.h>
#include <strings.h>

#include <client/cli/p2p.h>
#include <p67/dml/dml.h>
#include <p67/log.h>

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

void
p67_p2p_free(p67_p2p_t * p2p)
{
    if(!p2p) return;
    
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
    
    free(p2p);
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
    p67_hashcntl_t * h = p67_node_cache();

    for(i = 0; i < h->bufferl; i++) {
        if(!(entry = h->buffer[i])) continue;
        do {
            if(!entry->value) continue;
            ctx = (p67_node_t *)entry->value;
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
p67_p2p_node_insert(
    p67_addr_t * remote_addr, 
    const unsigned char * peer_username, 
    int peer_usernamel,
    p67_pdp_urg_hdr_t * req)
{
    assert(remote_addr);
    assert(peer_username);
    assert(peer_usernamel > 0);

    p67_node_t * node = p67_node_lookup(remote_addr);
    if(!node) {
        if(!(node = p67_node_insert(
                remote_addr, NULL, 0, NULL, NULL, P67_NODE_STATE_NODE))) {
            return NULL;
        }
    }

    p67_p2p_t * p2p = (p67_p2p_t *)node->args;

    if(p2p) {
        p67_p2p_free(p2p);
    }

    if(!(p2p = calloc(1, sizeof(p67_p2p_t) + peer_usernamel)))
        return NULL;

    if(req) {
        p2p->should_respond = 1;
        p2p->req = *req;
    } else {
        p2p->should_respond = 0;
    }

    p2p->peer_addr = p67_addr_ref_cpy(remote_addr);

    if(peer_username) {
        p2p->peer_username = (char *)p2p+sizeof(p67_p2p_t);
        memcpy(p2p->peer_username, peer_username, peer_usernamel);
        p2p->peer_usernamel = peer_usernamel;
    } else {
        p2p->peer_username = 0;
        p2p->peer_usernamel = 0;
    }

    p67_p2p_audio_init(p2p->audio);
    
    p67_thread_sm_init(p2p->connect_sm);

    p67_thread_sm_init(p2p->keepalive_ctx.th);
    p2p->keepalive_ctx.addr = p67_addr_ref_cpy(remote_addr);

    return p2p;
}
