#include <p67/sfd.h>
#include <p67/cmn.h>
#include <p67/conn_ctx.h>
#include <p67/dml/dml.h>
#include <p67/web/tlv.h>

#include "ws.h"

#include <stdlib.h>
#include <string.h>

#define P67_WS_UTP_PATH_LOGIN 'l'
#define P67_WS_UTP_PATH_CALL  'c'

#define P67_WS_TLV_TAG_USERNAME 'u'
#define P67_WS_TLV_TAG_PASSWORD 'p'

#define P67_WS_MAX_CREDENTIAL_LENGTH 128

#define __UC (unsigned char *)

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

#define P67_WS_DEFAULT_USER_NCHIX_CAPACITY 1009

/*
    server logged in users.
    it is nonclustered hash index 
        {username : user_addr}
    for conn_cache
        {user_addr: ssl_connection_ctx}
*/
typedef struct p67_ws_user_nchix_entry {
    char * username; /* cstr */
    size_t usernamel; /* = strlen(username) */
    p67_addr_t * addr;
    char __padd[sizeof(size_t)+sizeof(p67_hashcntl_entry_t *)];
} p67_ws_user_ncix_entry_t;

p67_cmn_static_assert_size(p67_ws_user_ncix_entry_t, p67_hashcntl_entry_t);
p67_cmn_static_assert(
    pointers_must_have_the_same_size, 
    sizeof(p67_addr_t *) == sizeof(unsigned char *));

#define P67_WS_DEFAULT_FWC_CAPACITY 11

typedef struct p67_ws_session {

    p67_db_ctx_t * db;

    p67_hashcntl_t * fwc;
    p67_ws_ctx_t * server_ctx;
    p67_pckt_t * username;

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

    entry->peer_saddr = (p67_sockaddr_t *)((char *)entry + sizeof(p67_ws_session_fwc_entry_t));
    entry->peer_saddr_l = dst->socklen;
    entry->tsm = (p67_thread_sm_t *)((char *)entry->peer_saddr + dst->socklen); 
    entry->tsm_l = sizeof(p67_thread_sm_t);
    
    memcpy(entry->peer_saddr, &dst->sock, dst->socklen);
    
    /* up to client to initialize this variable */
    entry->tsm->mutex = P67_XLOCK_STATE_UNLOCKED;
    entry->tsm->state = P67_THREAD_SM_STATE_STOP;
    entry->tsm->thr = 0;

    if(p67_hashcntl_add(ctx, (p67_hashcntl_entry_t *)entry) != 0)
        return NULL;

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

    return p67_hashcntl_add(h, (p67_hashcntl_entry_t *)entry);
}

void
p67_ws_user_nchix_entry_free(p67_hashcntl_entry_t * e)
{
    p67_addr_t * addr = ((p67_ws_user_ncix_entry_t *)e)->addr;
    p67_addr_free(addr);
    free(e);
}

void * p67_ws_session_create(void * args)
{
    if(!args) return NULL;

    p67_ws_ctx_t * server = (p67_ws_ctx_t *)args;
    
    p67_ws_session_t * p = calloc(1, sizeof(p67_ws_session_t));
    if(p == NULL) {
        p67_err_print_err("Couldnt create client session: ", p67_err_eerrno);
        return NULL;
    }
    p67_ws_err err;
    if((err = p67_db_ctx_create_from_dp_config(&p->db, NULL)) != 0) {
        p->db = NULL;
        p67_err_print_err("Couldnt create db connection for client: ", p67_err_eerrno);
        return NULL;
    }
    
    p->fwc = p67_hashcntl_new(
        P67_WS_DEFAULT_FWC_CAPACITY, p67_fwc_entry_free, NULL);
    if(!p->fwc) {
        p67_err_print_err("Couldnt create client session: ", p67_err_eerrno);
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
        p67_db_ctx_free(sess->db);
        if(sess->username) {
            p67_hashcntl_remove_and_free(
                sess->server_ctx->user_nchix, 
                sess->username, sess->usernamel);
            free(sess->username);
        }
        p67_hashcntl_free(sess->fwc);
        free(sess);
        return;
    }
    
    p67_spinlock_unlock(&sess->lock);
}

typedef struct p67_handle_call_ctx {

    /* fields forwarded from callback */
    p67_addr_t * src_addr;
    p67_ws_session_t * session;
    p67_pckt_t * msg;
    int msgl;

    /* fields deserialized from request */

    p67_addr_t * dst_addr;

    /* A call request ( see below ) */
    const p67_pckt_t * dst_username;
    const p67_pckt_t * src_message;

    char * src_svc;

    uint8_t src_svc_l;
    uint8_t dst_username_l;
    uint8_t src_message_l;

} p67_handle_call_ctx_t;

p67_err
p67_handle_call_ctx_free(p67_handle_call_ctx_t * ctx)
{
        p67_err err = 0;
        err |= p67_hashcntl_remove_and_free(
            ctx->session->fwc, 
            (unsigned char *)&ctx->dst_addr->sock, 
            ctx->dst_addr->socklen);
        p67_addr_free(ctx->dst_addr);
        p67_addr_free(ctx->src_addr);
        p67_ws_session_free(ctx->session);
        free(ctx);
        return err;
}


/*
   call proxy specification:
   all structures are tlv-encoded and encapsulated in DML-PDP messages
*/

/*
    A                         WEBSERVER                        B

    --------------------------->
    URG = { 
        * p  cstr  A service
          U  cstr  B username
        * m  cstr  message to B
    }


                                     --------------------------->
                                     URG = {
                                         p cstr  A service
                                         a cstr  A ip
                                       * m cstr  message to B
                                       * u cstr  A username
                                }

    <---------------------------
      PACK = {}

                                <---------------------------
                                 [optional] PACK = {}

                                                        (B decides whether to accept 
                                                        or reject call from A
                                                        this part may take long time
                                                        thus the optional PACKs )

                                <---------------------------
                                ACK = {
                                    s uint16_t response status
                                }

    <----------------------------
    ACK = {
        s  uint16_t response status
      * P  cstr B service
      * A  cstr B address
    }

*/
void *
p67_ws_handle_call(void * args)
{
    //p67_handle_call_ctx_t * ctx = (p67_handle_call_ctx_t *)args;

    p67_pckt_t msgbuf[P67_DML_SAFE_PAYLOAD_SIZE];
    p67_handle_call_ctx_t * ctx = (p67_handle_call_ctx_t *)args;
    const p67_tlv_header_t * tlv_hdr;
    const p67_pckt_t * tlv_value;
    const p67_pdp_urg_hdr_t * urg_hdr = (p67_pdp_urg_hdr_t *)ctx->msg;
    const p67_pckt_t * msgbufptr;

    int tlv_state;
    const int msgbufl = P67_DML_SAFE_PAYLOAD_SIZE;
    int msgbufix = 0;
    int msgbufptrix = 0;
    p67_err err = 0;

    p67_web_status dst_status;
    p67_web_status status;

    status = p67_web_status_server_fault;

    /* generate proxy request */

    if(!p67_pdp_generate_urg_for_msg(
                NULL, 0, msgbuf, msgbufl, urg_hdr->urg_utp)) {
        goto end;
    }

    msgbufix+=sizeof(p67_pdp_urg_hdr_t);

    if((err = p67_tlv_add_fragment(
            msgbuf+msgbufix, 
            msgbufl-msgbufix, 
            __UC "p", 
            ctx->src_svc ? 
                (p67_pckt_t *)ctx->src_svc : 
                (p67_pckt_t *)ctx->src_addr->service,
            ctx->src_svc ? 
                (uint8_t)(ctx->src_svc_l + 1) : 
                strlen(ctx->src_addr->service) + 1)) < 0) {
        err-=err;
        goto end;
    }

    msgbufix+=err;

    if(ctx->src_addr->socklen > UINT8_MAX) {
        goto end;
    }

    if((err = p67_tlv_add_fragment(
            msgbuf+msgbufix, 
            msgbufl-msgbufix, 
            __UC "a", 
            (p67_pckt_t *)ctx->src_addr->hostname,
            strlen(ctx->src_addr->hostname) + 1)) < 0) {
        err-=err;
        goto end;
    }

    msgbufix+=err;

    if(ctx->src_message != NULL && ctx->src_message_l > 0) {
        if((err = p67_tlv_add_fragment(
                msgbuf+msgbufix, 
                msgbufl-msgbufix, 
                __UC "m",
                ctx->src_message,
                ctx->src_message_l + 1)) < 0) {
            err-=err;
            goto end;
        }
        msgbufix+=err;
    }

    if(ctx->session->username) {
        if((err = p67_tlv_add_fragment(
                msgbuf+msgbufix, 
                msgbufl-msgbufix, 
                __UC "u", 
                ctx->session->username,
                ctx->session->usernamel + 1)) < 0) {
            err-=err;
            goto end;
        }
        msgbufix+=err;
    }

    p67_async_t flip = P67_PDP_EVT_NONE;

    /*
        proxy call request to B 
    */

    if((err = p67_pdp_write_urg(
            ctx->dst_addr,
            msgbuf, msgbufix, 30000, &flip, 
            msgbuf, &msgbufix)) != 0) {
        goto end;
    }

    /*
        if succeeded then write pre-ack response to A.
    */

    p67_pdp_ack_hdr_t pack_hdr;
    pack_hdr.ack_mid = urg_hdr->urg_mid;
    pack_hdr.ack_stp = P67_DML_STP_PDP_PACK;
    pack_hdr.ack_utp = urg_hdr->urg_utp;

    if((err = p67_conn_write_once(
            ctx->src_addr, (p67_pckt_t *)&pack_hdr, sizeof(pack_hdr))) != 0)
        goto end;

    /*
        wait for response from B
    */

    if((err = p67_mutex_wait_for_change(&flip, P67_PDP_EVT_NONE, -1)) != 0) {
        goto end;
    }

    if(flip != P67_PDP_EVT_GOT_ACK) {
        status = p67_web_status_not_found;
        goto end;
    }

    /*
        deserialize B's response
    */

    tlv_state = 0;
    status = p67_web_status_not_found;
    msgbufptr = msgbuf + sizeof(p67_pdp_ack_hdr_t);
    msgbufptrix = msgbufix - sizeof(p67_pdp_ack_hdr_t);


    while((err = p67_tlv_next(
            &msgbufptr, &msgbufptrix, &tlv_hdr, &tlv_value)) == 0) {
        switch(tlv_hdr->tlv_key[0]) {
        case 's':
            if(tlv_hdr->tlv_vlength != sizeof(dst_status))
                break;
            dst_status = *(uint16_t *)tlv_value;
            tlv_state |= 1;
            break;
        /*
            one could probably add here condition 
            which checks whether sockaddress fields
            are already present in B's response.
            or check for specific field like "direct_forward=true"
            If so then no modification of B's response 
            beyond mid and utp would be needed.    
        */

        }


        if(tlv_state == 1) {
            err = p67_err_eot;
            break;
        }
    }

    if(err != p67_err_eot || tlv_state != 1) {
        goto end;
    }

    /* create ACK for A based on B's ACK */
    
    status = p67_web_status_server_fault;

    p67_pdp_generate_ack_from_hdr(urg_hdr, NULL, 0, msgbuf, msgbufl);

    msgbufix = sizeof(p67_pdp_ack_hdr_t);

    if((err = p67_tlv_add_fragment(
            msgbuf+msgbufix,
            msgbufl-msgbufix,
            __UC "s", 
            (p67_pckt_t *)&dst_status,
            sizeof(dst_status))) < 0) {
        err=-err;
        goto end;
    }

    msgbufix+=err;
    err = 0;
    // now endiannes can be reversed to host 
    // since status hasbeen written into response.
    dst_status = p67_cmn_ntohs(dst_status);

    /* 
        if remote said ok then append to their response address.
    */
    if(dst_status == p67_web_status_ok) {

        if(ctx->dst_addr->socklen > UINT8_MAX) {
            status = p67_web_status_server_fault;
            goto end;
        }

        if((err = p67_tlv_add_fragment(
                msgbuf+msgbufix,
                msgbufl-msgbufix,
                __UC "A", 
                (p67_pckt_t *)&ctx->dst_addr->hostname,
                strlen(ctx->dst_addr->hostname) + 1)) < 0) {
            err=-err;
            goto end;
        }

        msgbufix+=err;
        err = 0;

        if((err = p67_tlv_add_fragment(
                msgbuf+msgbufix,
                msgbufl-msgbufix,
                __UC "P", 
                (p67_pckt_t *)ctx->dst_addr->service,
                strlen(ctx->dst_addr->service) + 1)) < 0) {
            err=-err;
            goto end;
        }
        
        msgbufix+=err;
        err = 0;
    }

    if((err = p67_conn_write_once(ctx->src_addr, msgbuf, msgbufix)) != 0)
        goto end;

    status = p67_web_status_ok;

end:
    if(status != p67_web_status_ok) {
        err |= p67_web_tlv_respond_with_status(
            urg_hdr, ctx->src_addr, status);
    }
    err |= p67_handle_call_ctx_free(ctx);
    if(err != 0) {
        p67_err_print_err("Terminating call handler with error/s: ", err);
    }
    return NULL;
}

p67_err
p67_ws_handle_call_async(
    p67_addr_t * addr, p67_ws_session_t * sess, p67_pckt_t * msg, int msgl)
{
    if(!addr || !sess)
        return p67_err_einval;

    p67_thread_sm_t * callthr;
    const p67_pckt_t * tlv_value;
    const p67_tlv_header_t * tlv_hdr;
    p67_hashcntl_entry_t * requested_user;
    p67_handle_call_ctx_t * ctx;
    const p67_pckt_t * payload;
    p67_err err = 0;
    int payload_len;

    if(!(ctx = malloc(sizeof(p67_handle_call_ctx_t) + msgl))) {
        return p67_web_tlv_respond_with_status(
            (p67_pdp_urg_hdr_t *)msg, addr, p67_web_status_server_fault);
    }

    ctx->src_svc = NULL;
    ctx->src_message_l = 0;
    ctx->src_message = NULL;
    ctx->msgl = msgl;
    ctx->msg = (p67_pckt_t *)((char *)ctx + sizeof(p67_handle_call_ctx_t));
    memcpy(ctx->msg, msg, msgl);
    ctx->dst_username = NULL;
    ctx->dst_username_l = 0;
    ctx->dst_addr = NULL;

    payload = ctx->msg + sizeof(p67_pdp_urg_hdr_t);
    payload_len = msgl - sizeof(p67_pdp_urg_hdr_t);

    while((err = p67_tlv_next(
                &payload, &payload_len, &tlv_hdr, &tlv_value)) == 0) {
        switch(tlv_hdr->tlv_key[0]) {
        case 'p':
            if(!(ctx->src_svc = (char *)p67_tlv_get_cstr(tlv_hdr, tlv_value))) {
                free(ctx);
                return p67_err_etlvf;
            }
            ctx->src_svc_l = tlv_hdr->tlv_vlength - 1;
            break;
        case 'U':
            ctx->dst_username = (p67_pckt_t *)p67_tlv_get_cstr(tlv_hdr, tlv_value);
            if(!ctx->dst_username){
                free(ctx);
                return p67_err_etlvf;
            }
            ctx->dst_username = tlv_value;
            ctx->dst_username_l = tlv_hdr->tlv_vlength - 1;
            break;
        case 'm':
            ctx->src_message = (p67_pckt_t *)p67_tlv_get_cstr(tlv_hdr, tlv_value);
            if(!ctx->src_message){
                free(ctx);
                return p67_err_etlvf;
            }
            ctx->src_message_l = tlv_hdr->tlv_vlength - 1;
            break;
        }
    }

    if(err != p67_err_eot || !ctx->dst_username) {
        free(ctx);
        return p67_web_tlv_respond_with_status(
            (p67_pdp_urg_hdr_t *)msg, addr, p67_web_status_bad_request);
    }

    /* find requested username amongst logged in users */
    requested_user = p67_hashcntl_lookup(
        sess->server_ctx->user_nchix, 
        ctx->dst_username, 
        ctx->dst_username_l);
    if(!requested_user) {
        free(ctx);
        return p67_web_tlv_respond_with_status(
            (p67_pdp_urg_hdr_t *)msg, addr, p67_web_status_not_found);
    }

    ctx->src_addr = p67_addr_ref_cpy(addr);
    ctx->dst_addr = p67_addr_ref_cpy((p67_addr_t*)requested_user->value);
    ctx->session = p67_ws_session_refcpy(sess);

    if(!ctx->src_addr || !ctx->dst_addr || !ctx->session) {
        p67_addr_free(ctx->src_addr);
        p67_addr_free(ctx->dst_addr);
        p67_ws_session_free(ctx->session);
        free(ctx);
        return p67_err_einval;
    }

    if((callthr = p67_fwc_add(sess->fwc, ctx->dst_addr)) == NULL) {
        p67_addr_free(ctx->src_addr);
        p67_addr_free(ctx->dst_addr);
        p67_ws_session_free(ctx->session);
        free(ctx);
        return p67_web_tlv_respond_with_status(
            (p67_pdp_urg_hdr_t *)msg, addr, p67_web_status_bad_request);
    }

    if((err = p67_cmn_thread_create(
                &callthr->thr, p67_ws_handle_call, ctx)) != 0) {
        err |= p67_handle_call_ctx_free(ctx);
        return err;
    }

    return 0;
}

p67_err
p67_ws_handle_login(
    p67_addr_t * addr, p67_ws_session_t * sess, p67_pckt_t * msg, int msgl)
{
    const p67_tlv_header_t * tlv_hdr;
    p67_err err = 0;
    const p67_pckt_t * payload = msg + sizeof(p67_pdp_urg_hdr_t);
    int payload_len = msgl - sizeof(p67_pdp_urg_hdr_t);
    const p67_pckt_t * tlv_value;
    p67_web_status status;
    const p67_pckt_t * username = NULL, * password = NULL;
    int usernamel, passwordl;

    status = p67_web_status_bad_request;

    while((err = p67_tlv_next(
            &payload, &payload_len, &tlv_hdr, &tlv_value)) == 0) {

        switch(tlv_hdr->tlv_key[0]) {
        case P67_WS_TLV_TAG_USERNAME:
            username = (p67_pckt_t *)p67_tlv_get_cstr(tlv_hdr, tlv_value);
            if(!username) goto end;
            usernamel = tlv_hdr->tlv_vlength - 1;
            break;
        case P67_WS_TLV_TAG_PASSWORD:
            password = (p67_pckt_t *)p67_tlv_get_cstr(tlv_hdr, tlv_value);
            if(!password) goto end;
            passwordl = tlv_hdr->tlv_vlength - 1;
            break;
        }
    }

    if(err != p67_err_eot || !username || !password) {
        goto end;
    }

    status = p67_web_status_unauthorized;

    if((err = p67_db_user_validate_pass(
            sess->db, (char *)username, usernamel, password, passwordl)) != 0) {
        err = 0;
        goto end;
    }

    if(sess->username) {
        if(sess->usernamel == usernamel && 
                (memcmp(sess->username, username, usernamel) == 0)) {
            status = p67_web_status_not_modified;
            goto end;
        }

        err = p67_hashcntl_remove_and_free(
                    sess->server_ctx->user_nchix, username, usernamel);

        if(err) {
            status = p67_web_status_server_fault;
            goto end;
        }

        free(sess->username);
    }

    if((err = p67_ws_user_nchix_add(
                sess->server_ctx->user_nchix, 
                (char *)username, usernamel, addr)) != 0) {
        if(err == p67_err_eaconn) {
            err = 0;
            status = p67_web_status_not_modified;
        }
        else status = p67_web_status_server_fault;
        goto end;
    }

    if(!(sess->username = malloc(usernamel + 1))) {
        status = p67_web_status_server_fault;
        goto end;
    }
        
    memcpy(sess->username, username, usernamel);
    
    sess->username[usernamel] = 0;
    sess->usernamel = usernamel;

    status = p67_web_status_ok;

end:
    if(err != 0) {
        p67_err_print_err("handle login terminated with error/s: ", err);
    }
    return p67_web_tlv_respond_with_status((p67_pdp_urg_hdr_t *)msg, addr, status);
}

p67_err
p67_ws_cb(p67_addr_t * addr, p67_pckt_t * msg, int msgl, void * args)
{
    if(!args) return p67_err_einval;

    const p67_dml_hdr_store_t * h;
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
        case 0:
            /* respond with empty ack */
            return p67_dml_handle_msg(addr, msg, msgl, NULL);
        default:
            /* respond with ack + p67_web_status_not_found */
            return p67_web_tlv_respond_with_status(
                &h->urg, addr, p67_web_status_not_found);
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

p67_err
p67_ws_user_nchix_create(p67_hashcntl_t ** c, size_t capacity)
{
    assert(c);

    if(capacity <= 0)
        capacity = P67_WS_DEFAULT_USER_NCHIX_CAPACITY;
    
    p67_err err;

    if(!(*c = p67_hashcntl_new(capacity, p67_ws_user_nchix_entry_free, &err)))
        return err;
    
    return 0;
}
