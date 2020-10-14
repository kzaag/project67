#include <p67/log.h>
#include <client/cli/node.h>
#include <p67/dml/dml.h>
#include <p67/cert.h>

#include <string.h>

struct p67_ext_node {
    /* this is null terminated, however but dont waste cpu on strlen use usernamel field. */
    char * username;
    p67_thread_sm_t connect_sm;
    p67_pdp_keepalive_ctx_t keepalive;
    int usernamel;
};

P67_CMN_NO_PROTO_ENTER
void
p67_ext_node_free(
P67_CMN_NO_PROTO_EXIT
    void * e)
{
    if(!e) {
        return;
    }
    struct p67_ext_node * ext = (struct p67_ext_node *)e;
    p67_pdp_free_keepalive_ctx(&ext->keepalive);
    p67_net_connect_terminate(&ext->connect_sm);
    free(ext);
}

const char * empty = "";
const char * queue_warn = "NOT_TRUSTED ";

/* use this function instead of p67_node_remove. 
   This will shutdown connection first thus ensuring safe freeing of node
*/
p67_err
p67_ext_node_remove(p67_addr_t * addr)
{
    p67_err err = 0;
    err |= p67_net_shutdown(addr);
    err |= p67_node_remove(addr);
    return err;
}

P67_CMN_NO_PROTO_ENTER
p67_err
p67_ext_node_callback(
P67_CMN_NO_PROTO_EXIT
    p67_addr_t * addr, p67_pckt_t * msg, int msgl, void * args)
{
    p67_node_t * node = p67_node_lookup(addr);
    //p67_p2p_t * p = p67_p2p_cache_lookup(addr);
    if(node) {
        const p67_dml_hdr_store_t * h = p67_dml_parse_hdr(msg, msgl, NULL);
        if(!h)
            return p67_err_epdpf;
        switch(h->cmn.cmn_stp) {
        case P67_DML_STP_PDP_URG:
            if(h->cmn.cmn_utp != 0) {
                p67_log(
                    "%s%s:%s: %.*s\n",
                    node->state == P67_NODE_STATE_QUEUE ? queue_warn : empty,
                    addr->hostname, addr->service,
                    msgl-sizeof(p67_pdp_urg_hdr_t),
                    msg+sizeof(p67_pdp_urg_hdr_t));
            }
            break;
        case P67_DML_STP_QDP_DAT:
            // if(p->audio.qdp)
            //     return p67_qdp_handle_data(addr, msg, msgl, p->audio.qdp);
            // else
            //     // not ready to accept stream so just ignore. 
            //     // maybe notify user / kill connection?
            //     return 0;
            break;
        }
        return p67_dml_handle_msg(addr, msg, msgl, NULL);
    } else if(node) {
        return p67_dml_handle_msg(addr, msg, msgl, NULL);
    }
    return p67_err_einval;
    //p67_dml_pretty_print_addr(addr, msg, msgl);
}

P67_CMN_NO_PROTO_ENTER
void
p67_ext_node_on_connection_shutdown(
P67_CMN_NO_PROTO_EXIT
    p67_addr_t * addr)
{
    p67_node_t * n = p67_node_lookup(addr);
    if(!n) return;
    p67_ext_node_t * en = (p67_ext_node_t *)n->args;
    if(!en) return;
    p67_net_connect_terminate(&en->connect_sm);
    p67_pdp_free_keepalive_ctx(&en->keepalive);
}

p67_net_cb_ctx_t
p67_ext_node_p2p_cb(void)
{
    p67_net_cb_ctx_t cb = p67_net_cb_ctx_initializer(p67_ext_node_callback);
    cb.on_shutdown = p67_ext_node_on_connection_shutdown;
    return cb;
}

/*
    start keepalive and connect to the node
*/
p67_err
p67_ext_node_start_connect(
    p67_node_t * node, 
    p67_addr_t * local_addr, p67_net_cred_t * local_cred, p67_net_cb_ctx_t cbctx)
{
    if(!node || !node->args) return p67_err_einval;
    p67_ext_node_t * extnode = (p67_ext_node_t *)node->args;
    p67_err err;
    
    err = p67_net_start_connect(
        &extnode->connect_sm,
        NULL,
        local_addr,
        node->trusted_addr,
        local_cred,
        cbctx,
        NULL);

    if(err) return err;

    p67_thread_sm_init(extnode->keepalive.th);
    extnode->keepalive.addr = p67_addr_ref_cpy(node->trusted_addr);

    err = p67_pdp_start_keepalive_loop(&extnode->keepalive);
    
    if(err) {
        p67_addr_free(extnode->keepalive.addr);
        p67_net_connect_terminate(&extnode->connect_sm);
    }

    return err;
}

p67_err
p67_ext_node_stop_connect(p67_node_t * node)
{
    if(!node || !node->args) return p67_err_einval;
    p67_ext_node_t * extnode = (p67_ext_node_t *)node->args;
    p67_net_connect_terminate(&extnode->connect_sm);
    p67_pdp_free_keepalive_ctx(&extnode->keepalive);
    return 0;
}

void
p67_ext_node_print(p67_node_t * node, int print_flags)
{
    if(!node) return;

    char node_state[10], conn_state[10], keepalive_state[10];
    char * username = "", * pk = NULL;
    conn_state[0] = 0;
    keepalive_state[0] = 0;

    if((print_flags & P67_EXT_NODE_PRINT_FLAGS_ALL) && node->trusted_pub_key) {
        pk = malloc(strlen(node->trusted_pub_key) + 3); /* new-line and 0 terminator*/
        sprintf(pk, "\n%s", node->trusted_pub_key);
    } else {
        pk = p67_cmn_strdup("");
    }

    p67_node_state_str(node_state, 10, node->state);

    struct p67_ext_node * ext = (struct p67_ext_node *)node->args;
    if(ext) {
        username = ext->username;
        if(ext->connect_sm.state == P67_THREAD_SM_STATE_RUNNING) {
            snprintf(conn_state, sizeof(conn_state), "CONN_ACTV");
        } else {
            snprintf(conn_state, sizeof(conn_state), "CONN_PASV");
        }
        if(ext->keepalive.th.state == P67_THREAD_SM_STATE_RUNNING) {
            snprintf(keepalive_state, sizeof(keepalive_state), "KEEPALIVE");
        }
    }

    p67_log( "%s:%s %s %s %s %s %s\n",
             node->trusted_addr->hostname,
             node->trusted_addr->service,
             node_state,
             /* ext data */
             username,
             conn_state,
             keepalive_state,
             /* optional pk */
             pk);

    free(pk);
}

void
p67_ext_node_print_all(int print_flags)
{
    p67_hashcntl_t * hc = p67_node_cache();
    if(!hc) return;
    p67_hashcntl_lock(hc);
    p67_hashcntl_entry_t ** e, * ne;

    for(e = hc->buffer; e < hc->buffer + hc->bufferl; e++) {
        ne = *e;
        if(!ne) continue;
        do {
            p67_ext_node_print((p67_node_t*)ne->value, print_flags);
            ne=ne->next;
        } while((ne));
    }

    p67_hashcntl_unlock(hc);
}

p67_node_t *
p67_ext_node_find_by_name(char * username)
{
    assert(username);
    int usernamel = strlen(username);
    p67_hashcntl_entry_t ** e, * ne;
    p67_hashcntl_t * ctx = p67_node_cache();
    p67_ext_node_t * en;
    p67_node_t * n = NULL;

    p67_hashcntl_lock(ctx);

    for(e = ctx->buffer; e < ctx->buffer + ctx->bufferl; e++) {
        ne = *e;
        if(!ne) continue;
        do {
            if(ne->value && ((p67_node_t *)ne->value)->args) {
                n = (p67_node_t *)ne->value;
                en = (p67_ext_node_t *)n->args;
                if(en->usernamel == usernamel && memcmp(username, en->username, usernamel) == 0) {
                    p67_hashcntl_unlock(ctx);
                    return n;
                }
            }
            ne=ne->next;
        } while((ne));
    }

    p67_hashcntl_unlock(ctx);
    return NULL;
}

p67_err
p67_ext_node_insert_and_connect(
    p67_addr_t * addr,
    const char * trusted_pk_path,
    const char * username,
    p67_addr_t * local_addr,
    p67_net_cred_t * cred,
    p67_net_cb_ctx_t cbctx)
{
    p67_node_t * node = p67_ext_node_insert(
        addr, trusted_pk_path, P67_NODE_STATE_NODE, username);
    if(!node) {
        return p67_err_eerrno | p67_err_eaconn;
    }
    p67_err err = p67_ext_node_start_connect(node, local_addr, cred, cbctx);
    if(err) p67_ext_node_remove(addr);
    return err;
}

p67_node_t *
p67_ext_node_insert(
    p67_addr_t * addr,
    const char * trusted_pk_path,
    int state,
    const char * username)
{
    int usernamel = username ? strlen(username) : 0;
    struct p67_ext_node * ext = malloc(sizeof(struct p67_ext_node)+usernamel+1);
    if(!ext) return NULL;
    char * pk = NULL;
    int pkl = 0;

    p67_thread_sm_init(ext->connect_sm);
    ext->usernamel = usernamel;
    if(username) {
        ext->username = (char*)ext+sizeof(struct p67_ext_node);
        memcpy(ext->username, username, usernamel+1);
    } else {
        ext->username = NULL;
    }

    p67_thread_sm_init(ext->keepalive.th);
    ext->keepalive.addr = NULL;

    if(trusted_pk_path) {
        if(p67_cert_get_pk(trusted_pk_path, &pk, &pkl))
            return NULL;
    }

    p67_node_t * node = p67_node_insert(
        addr,
        pk,
        pkl,
        ext,
        p67_ext_node_free,
        state);

    free(pk);

    if(!node) {
        free(ext);
        return NULL;
    }

    return node;
}
