#include <p67/sfd.h>
#include <p67/cmn.h>
#include <p67/conn_ctx.h>
#include <p67/dml/dml.h>
#include <p67/web/tlv.h>

#include "wc.h"

#include <stdlib.h>
#include <string.h>

#define P67_WS_UTP_PATH_LOGIN 'l'
#define P67_WS_UTP_PATH_CALL  'c'

#define P67_WS_TLV_TAG_USERNAME 'u'
#define P67_WS_TLV_TAG_PASSWORD 'p'

#define P67_WS_MAX_CREDENTIAL_LENGTH 128

/*
    forward call cache entry.
    used in ws_session to keep track of user pending calls
    and threads associated with them.
*/
typedef struct p67_ws_session_fwc_entry {
    p67_sockaddr_t * peer_saddr;
    size_t peer_saddr_l;
    p67_thread_sm_t * tsm;
    size_t tsm_l;
    char __padd[sizeof(p67_hashcntl_entry_t *) ]; // next
} p67_ws_session_fwc_entry_t;

p67_cmn_static_assert_size(p67_ws_session_fwc_entry_t, p67_hashcntl_entry_t);

/*
    server logged in users.
    it is nonclustered hash index 
        {username : user_addr}
    for conn_cache
        {user_addr: ssl_connection_ctx}
*/
typedef struct p67_ws_user_nchix_entry {
    char * username; /* it is null terminated */
    size_t usernamel;
    p67_addr_t * addr;
    char __padd[sizeof(size_t)+sizeof(p67_hashcntl_entry_t *)];
} p67_ws_user_ncix_entry_t;

p67_cmn_static_assert_size(p67_ws_user_ncix_entry_t, p67_hashcntl_entry_t);

#define P67_WS_DEFAULT_FWC_CAPACITY 11

typedef struct p67_ws_session {

    p67_hashcntl_t * fwc;
    p67_ws_ctx_t * server_ctx;
    char * username;

    int usernamel;
    p67_async_t lock;

    int refcount;
    int __align;

} p67_ws_session_t;

p67_thread_sm_t *
p67_fwc_add(p67_hashcntl_t * ctx, p67_addr_t * dst)
{
    if(!dst) return NULL;

    p67_ws_session_fwc_entry_t * entry = malloc(
        sizeof(p67_ws_session_fwc_entry_t) +
        dst->socklen + /* key */
        sizeof(p67_thread_sm_t) /* value */ );
    if(!entry) return NULL;

    entry->peer_saddr = (char *)entry + sizeof(p67_ws_session_fwc_entry_t);
    entry->peer_saddr_l = dst->socklen;
    entry->tsm = (char *)entry->peer_saddr + dst->socklen; 
    entry->tsm_l = sizeof(p67_thread_sm_t);
    
    memcpy(entry->peer_saddr, &dst->sock, dst->socklen);
    
    /* up to client to initialize this variable */
    entry->tsm->mutex = P67_XLOCK_STATE_UNLOCKED;
    entry->tsm->state = P67_THREAD_SM_STATE_STOP;
    entry->tsm->thr = 0;

    return entry->tsm;
}

void
p67_fwc_entry_free(p67_hashcntl_entry_t * e)
{
    p67_ws_session_fwc_entry_t * fwc = (p67_ws_session_fwc_entry_t *)e;
    if(fwc->tsm->state == P67_THREAD_SM_STATE_RUNNING)
        p67_thread_sm_terminate(fwc->tsm, 500);
    free(e);
}

p67_err
p67_ws_user_nchix_add(
    p67_hashcntl_t * h, 
    const char * username, int usernamel, p67_addr_t * addr)
{
    if(!addr || !username || 
            usernamel < 1 || usernamel > P67_WS_MAX_CREDENTIAL_LENGTH) 
        return p67_err_einval;

    p67_ws_user_ncix_entry_t * entry = malloc(
        sizeof(p67_ws_user_ncix_entry_t) + usernamel + 1);
    if(!entry) return p67_err_eerrno;

    p67_addr_t * addrcpy = p67_addr_ref_cpy(addr);
    if(!addrcpy) return p67_err_einval;

    entry->username = (char *)entry + sizeof(p67_ws_user_ncix_entry_t);
    entry->usernamel = usernamel;
    entry->addr = addrcpy;

    memcpy(entry->username, username, usernamel);
    entry->username[usernamel] = 0;

    return 0;
}

void
p67_ws_user_nchix_entry_free(p67_hashcntl_entry_t * e)
{
    free(e);
}

void * p67_ws_session_create(void * args)
{
    if(!args) return NULL;

    p67_ws_ctx_t * server = (p67_ws_ctx_t *)args;
    
    p67_ws_session_t * p = calloc(1, sizeof(p67_ws_session_t));
    if(p == NULL) {
        p67_err_print_err("ERR in create client session: ", p67_err_eerrno);
        return NULL;
    }

    p->fwc = p67_hashcntl_new(
        P67_WS_DEFAULT_FWC_CAPACITY, p67_fwc_entry_free, NULL);
    if(!p->fwc) {
        p67_err_print_err("ERR in create client session: ", p67_err_eerrno);
        return NULL;
    }

    p->server_ctx = server;
    p->lock = P67_XLOCK_STATE_UNLOCKED;
    p->refcount = 1;

    return p;
}

p67_ws_session_t *
p67_ws_session_refcpy(p67_ws_session_t * session)
{
    if(!session) return NULL;
    p67_spinlock_lock(&session->lock);
    if(session->refcount < 1) return NULL;
    session->refcount++;
    p67_spinlock_unlock(&session->lock);
    return session;
}

void p67_ws_session_free(void * arg)
{
    if(!arg) return;
    p67_ws_session_t * sess = (p67_ws_session_t *)arg;
    
    p67_spinlock_lock(&sess->lock);

    if(sess->refcount < 1) {
        p67_log_debug("Warn: tried to free session with refcount < 1.\n");
        return;
    } else if (sess->refcount > 1) {
        sess->refcount--;
    } else {
        sess->refcount--;
        p67_spinlock_unlock(&sess->lock);
        p67_cmn_sleep_ms(10);
        if(sess->username) {
            p67rs_usermap_remove(
                sess->server_ctx->user_nchix, 
                sess->username, 
                sess->usernamel);
            free(sess->username);
        }
        p67_hashcntl_free(sess->fwc);
        free(sess);
        return;
    }
    
    p67_spinlock_unlock(&sess->lock);
}

typedef struct p67_handle_call_ctx {
    p67_addr_t * addr;
    p67_ws_session_t * session;
    p67_pckt_t * msg;
    int msgl;
} p67_handle_call_ctx_t;

void *
p67_ws_handle_call(void * args)
{
    p67_handle_call_ctx_t * ctx = (p67_handle_call_ctx_t *)args;

    printf("handling call\n");

    return NULL;
}

p67_err
p67_ws_handle_call_async(
    p67_addr_t * addr, p67_ws_session_t * sess, p67_pckt_t * msg, int msgl)
{
    if(!addr || !sess)
        return p67_err_einval;

    p67_thread_sm_t * callthr;

    if((callthr = p67_fwc_add(sess->fwc, addr)) == NULL) {
        return p67_web_tlv_respond_with_status(
            (p67_pdp_urg_hdr_t *)msg, addr, p67_web_status_bad_request);
    }

    p67_handle_call_ctx_t * ctx = malloc(sizeof(p67_handle_call_ctx_t) + msgl);
    p67_addr_t * addrcpy = p67_addr_ref_cpy(addr);
    p67_ws_session_t * sesscpy = p67_ws_session_refcpy(sess);
    if(!addrcpy || !sesscpy)
        return p67_err_einval;
    ctx->addr = addrcpy;
    ctx->session = sesscpy;
    ctx->msgl = msgl;
    ctx->msg = (char *)ctx + sizeof(p67_handle_call_ctx_t);
    memcpy(ctx->msg, msg, msgl);

    p67_err err;

    if((err = p67_cmn_thread_create(&callthr->thr, p67_ws_handle_call, ctx)) != 0) {
        err |= p67_hashcntl_remove_and_free(
            sesscpy->fwc, 
            (unsigned char *)&addrcpy->sock, 
            addrcpy->socklen);
        p67_addr_free(addrcpy);
        p67_ws_session_free(sesscpy);
        free(ctx);
        return err;
    }

    return 0;
}

p67_err
p67_ws_handle_login(
    p67_addr_t * addr, p67_ws_session_t * sess, p67_pckt_t * msg, int msgl)
{

}

p67_err
p67_ws_cb(p67_addr_t * addr, p67_pckt_t * msg, int msgl, void * args)
{
    if(!args) return p67_err_einval;

    p67_ws_session_t * session;
    const p67_dml_hdr_store_t * h;
    p67_thread_sm_t * call_thread;
    p67_err err;

    if((h = p67_dml_parse_hdr(msg, msgl, NULL)) == NULL)
        return p67_err_epdpf;

    switch(h->cmn.cmn_stp) {
    case P67_DML_STP_PDP_ACK:
        return p67_dml_handle_msg(addr, msg, msgl, NULL);
    case P67_DML_STP_PDP_URG:
        switch(h->cmn.cmn_utp) {
        case P67_WS_UTP_PATH_LOGIN:
            // if((session = p67_ws_session_refcpy((p67_ws_session_t *)args)) == NULL)
            //     return p67_err_einval;
            err = p67_ws_handle_login(
                addr, (p67_ws_session_t *)args, msg, msgl);
            //p67_ws_session_free(session);
            return err;
        case P67_WS_UTP_PATH_CALL:
            err = p67_ws_handle_call_async(
                addr, (p67_ws_session_t *)args, msg, msgl);
            return err;
        default:
            return p67_err_einval;
        }
    default:
        return p67_err_epdpf;
    }

    return p67_err_einval;
}

void
p67_ws_setup_conn_ctx(p67_conn_ctx_t * conn, p67_ws_ctx_t * server)
{
    conn->cb = p67_ws_cb;
    conn->gen_args = p67_ws_session_create;
    conn->free_args = p67_ws_session_free;
    conn->args = server;
}

