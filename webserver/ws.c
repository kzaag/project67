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
            p67_hashcntl_remove_and_free(
                sess->server_ctx->user_nchix, 
                (unsigned char *)sess->username, sess->usernamel);
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

/*
   call proxy specification:
   all structures are tlv-encoded and encapsulated in DML-PDP messages

    A                         WEBSERVER                        B

    --------------------------->
    URG = { 
        * p  uint16_t  A port
          U  char[]    B username
        * m  char[]    message to B
    }


                                --------------------------->
                                URG = {
                                    p uint16_t A port
                                    a char[]   A address
                                  * m char[]   message to B
                                  * u char[]   A username
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
        s  uint16_t  call response status
        P  uint16_t  B port
        A  char[]    B address
    }

*/
void *
p67_ws_handle_call(void * args)
{
    //p67_handle_call_ctx_t * ctx = (p67_handle_call_ctx_t *)args;

    p67_handle_call_ctx_t * ctx = (p67_handle_call_ctx_t *)args;
    p67_err err = 0;
    p67_web_status status;
    const p67_tlv_header_t * tlv_hdr;
    const p67_pckt_t * tlv_value;
    const p67_pdp_urg_hdr_t * urg_hdr = (p67_pdp_urg_hdr_t *)args;
    const p67_pckt_t * payload = ctx->msg + sizeof(p67_pdp_urg_hdr_t);
    int payload_len = ctx->msgl - sizeof(p67_pdp_urg_hdr_t);
    int tlv_state;

    uint16_t src_user_port, requested_user_port;
    p67_pckt_t * src_user_message;
    p67_hashcntl_entry_t * requested_user;
    p67_addr_t * requested_user_address;
    char * requested_username;
    uint8_t requested_usernamel, src_user_message_l;

    tlv_state = 0;
    int moved_fwc_entry_address = 0;

    status = p67_web_status_bad_request;

    while((err = p67_tlv_next(
                &payload, &payload_len, &tlv_hdr, &tlv_value)) == 0) {
        switch(tlv_hdr->tlv_key[0]) {
        case 'p':
            if(tlv_hdr->tlv_vlength != 2)
                break;
            src_user_port = p67_cmn_ntohs(*(uint16_t *)tlv_value);
            tlv_state |= 1;
            break;
        case 'U':
            if(tlv_hdr->tlv_vlength == 0 || 
                    tlv_hdr->tlv_vlength > P67_WS_MAX_CREDENTIAL_LENGTH)
                break;
            requested_username = (char *)tlv_value;
            requested_usernamel = tlv_hdr->tlv_vlength;
            tlv_state |= 2;
            break;
        case 'm':
            src_user_message = tlv_value;
            src_user_message_l = tlv_hdr->tlv_vlength;
            tlv_state |= 4;
            break;
        }
        if(tlv_state & (1 | 2 | 4))
            break;
    }

    if(err != p67_err_eot)
        goto end;

    if(!(tlv_state  & 2)) {
        goto end;
    }

    /* find requested username in logged in users */
    requested_user = p67_hashcntl_lookup(
        ctx->session->server_ctx->user_nchix, 
        requested_username, 
        requested_usernamel);
    if(!requested_user) {
        status = p67_web_status_not_found;
        goto end;
    }

    status = p67_web_status_server_fault;

    if(!(tlv_state & 1)) {
        src_user_port = p67_addr_get_port(ctx->addr);
    }

    requested_user_address = (p67_addr_t *)requested_user->value;

    /* generate proxy request */

    p67_pckt_t msgbuf[P67_DML_SAFE_PAYLOAD_SIZE];
    const int msgbufl = P67_DML_SAFE_PAYLOAD_SIZE;
    int msgbufix = 0;

    if(!p67_pdp_generate_urg_for_msg(
                NULL, 0, msgbuf, msgbufl, urg_hdr->urg_utp)) {
        goto end;
    }

    msgbufix+=sizeof(p67_pdp_urg_hdr_t);

    if((err = p67_tlv_add_fragment(
            msgbuf+msgbufix, 
            msgbufl-msgbufix, 
            "p", 
            (p67_pckt_t *)&src_user_port,
            2)) < 0) {
        err -=err;
        goto end;
    }

    msgbufix+=err;


    if(ctx->addr->socklen > UINT8_MAX) {
        goto end;
    }

    if((err = p67_tlv_add_fragment(
            msgbuf+msgbufix, 
            msgbufl-msgbufix, 
            "a", 
            (p67_pckt_t *)&ctx->addr->sock,
            ctx->addr->socklen)) < 0) {
        err -=err;
        goto end;
    }

    msgbufix+=err;

    if(tlv_state & 4) {
        if((err = p67_tlv_add_fragment(
                msgbuf+msgbufix, 
                msgbufl-msgbufix, 
                "m", 
                src_user_message,
                ctx->addr->socklen)) < 0) {
            err -=err;
            goto end;
        }
        msgbufix+=err;
    }

    if(ctx->session->username) {
        if((err = p67_tlv_add_fragment(
                msgbuf+msgbufix, 
                msgbufl-msgbufix, 
                "n", 
                ctx->session->username,
                ctx->session->usernamel)) < 0) {
            err -=err;
            goto end;
        }
        msgbufix+=err;
    }

    p67_async_t flip = P67_PDP_EVT_NONE;

    /*
        proxy call request to B 
    */

    if((err = p67_pdp_write_urg(
            requested_user_address,
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
            ctx->addr, &pack_hdr, sizeof(pack_hdr))) != 0)
        goto end;

    /*
        wait for response from B
    */

    if((err = p67_mutex_wait_for_change(&flip, P67_PDP_EVT_NONE, -1)) != 0)
        goto end;

    if(flip != P67_PDP_EVT_GOT_ACK) {
        status = p67_web_status_not_found;
        goto end;
    }

    /*
        deserialize B's response
    */

    p67_pckt_t * msgbufptr = msgbuf;
    int msgbufptrix = 0;
    p67_web_status dst_status;

    tlv_state = 0;
    status = p67_web_status_not_found;

    while((err = p67_tlv_next(
            &msgbufptr, &msgbufptrix, &tlv_hdr, &tlv_value)) == 0) {
        switch(tlv_hdr->tlv_key[0]) {
        case 's':
            if(tlv_hdr->tlv_vlength != sizeof(dst_status))
                break;
            dst_status = p67_cmn_ntohs(*(uint16_t *)tlv_value);
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


        if(tlv_state & 1) {
            break;
        }
    }

    if(err != p67_err_eot) goto end;
    if((tlv_state & 1)) goto end;

    /* create ACK for A based on B's ACK */
    
    status = p67_web_status_server_fault;

    p67_pdp_generate_ack_from_hdr(urg_hdr, NULL, 0, msgbuf, msgbufl);

    msgbufix = sizeof(p67_pdp_ack_hdr_t);

    if((err = p67_tlv_add_fragment(
            msgbuf+msgbufix,
            msgbufl-msgbufix,
            "s", 
            (p67_pckt_t *)&dst_status,
            sizeof(dst_status))) < 0) {
        err=-err;
        goto end;
    }

    msgbufix+=err;

    /* 
        if remote said ok then append to their response address.
    */
    if(dst_status == p67_web_status_ok) {

        if(requested_user_address->socklen > UINT8_MAX) {
            status = p67_web_status_server_fault;
            goto end;
        }

        if((err = p67_tlv_add_fragment(
                msgbuf+msgbufix,
                msgbufl-msgbufix,
                "A", 
                (p67_pckt_t *)&requested_user_address->sock,
                requested_user_address->socklen)) < 0) {
            err=-err;
            goto end;
        }

        msgbufix+=err;

        requested_user_port = p67_addr_get_port(requested_user_address);

        if((err = p67_tlv_add_fragment(
                msgbuf+msgbufix,
                msgbufl-msgbufix,
                "P", 
                (p67_pckt_t *)&requested_user_port,
                sizeof(requested_user_port))) != 0) {
            err=-err;
            goto end;
        }
        
        msgbufix+=err;
    }

    if((err = p67_conn_write_once(ctx->addr, msgbuf, msgbufix)) != 0)
        goto end;

    return 0;

end:
    err |= p67_hashcntl_remove_and_free(
        ctx->session->fwc, 
        (p67_pckt_t *)&requested_user_address->sock, 
        requested_user_address->socklen);
    if(err != 0) p67_err_print_err(
        "Terminating call handler with error/s: ", err);
    p67_ws_session_free(ctx->session);
    p67_addr_free(ctx->addr);
    free(ctx);
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
    ctx->msg = (p67_pckt_t *)((char *)ctx + sizeof(p67_handle_call_ctx_t));
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
    const p67_tlv_header_t * tlv_hdr;
    p67_err err = 0;
    const p67_pckt_t * payload = msg + sizeof(p67_pdp_urg_hdr_t);
    int payload_len = msgl - sizeof(p67_pdp_urg_hdr_t);
    const p67_pckt_t * tlv_value;
    p67_web_status status;
    char * username;
    size_t usernamel, passwordl;
    unsigned char * password;
    int state;

    status = p67_web_status_bad_request;
    state = 0;

    while((err = p67_tlv_next(
            &payload, &payload_len, &tlv_hdr, &tlv_value)) == 0) {

        switch(tlv_hdr->tlv_key[0]) {
        case P67_WS_TLV_TAG_USERNAME:
            if(tlv_hdr->tlv_vlength < 1 || 
                        tlv_hdr->tlv_vlength > P67_WS_MAX_CREDENTIAL_LENGTH) {
                goto end;
            }
            username = (char *)tlv_value;
            usernamel = tlv_hdr->tlv_vlength;
            state |= 1;
            break;
        case P67_WS_TLV_TAG_PASSWORD:
            if(tlv_hdr->tlv_vlength < 1 || 
                        tlv_hdr->tlv_vlength > P67_WS_MAX_CREDENTIAL_LENGTH) {
                goto end;
            }
            password = (unsigned char *)tlv_value;
            passwordl = tlv_hdr->tlv_vlength;
            state |= 2;
            break;
        }
    }

    if(err != p67_err_eot) {
        goto end;
    }

    if(state != (1 | 2)) {
        goto end;
    }

    status = p67_web_status_unauthorized;

    if((err = p67_db_user_validate_pass(
            sess->server_ctx->db, username, usernamel, password, passwordl)) != 0) {
        goto end;
    }

    if((err = p67_ws_user_nchix_add(
                sess->server_ctx->user_nchix, username, usernamel, addr)) != 0) {
        if(err == p67_err_eaconn) status = p67_web_status_not_modified;
        else status = p67_web_status_server_fault;
        goto end;
    }

    if(sess->username == NULL || 
            ( ( strlen(sess->username) != usernamel) && 
                memcmp(sess->username, username, usernamel)) ) {
        char * susername;
        if((susername = malloc(usernamel+1)) == NULL) {
            status = p67_web_status_server_fault;
            goto end;
        }

        memcpy(susername, username, usernamel);
        susername[usernamel] = 0;

        free(sess->username);
        sess->username = susername;
    }

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
