

#include <server/redirect.h>
#include <server/session.h>
#include <p67/net.h>
#include <p67/tlv.h>
#include <p67/web/tlv.h>
#include <p67/dml/pdp.h>

#define P67_WS_REDIRECT_ENTRY_STATE_REQUEST 1
#define P67_WS_REDIRECT_ENTRY_STATE_WAITING 2
#define P67_WS_REDIRECT_ENTRY_STATE_RESPONDING 2

#define SECOND 1000

typedef struct p67_ws_redirect_entry {
    p67_addr_t * src_addr;
    p67_addr_t * dst_addr;
    p67_async_t state_lock;
    p67_pdp_urg_hdr_t request_hdr;
    int state;
} p67_ws_redirect_entry_t;


p67_hashcntl_t * __redirect_buf;
p67_async_t redirect_buf_inilock;
p67_hashcntl_t * __redirect_buf_ix;
p67_async_t redirect_buf_ix_inilock;


p67_hashcntl_t *
redirect_buf(void)
{
    p67_hashcntl_getter_fn(
        redirect_buf_inilock,
        __redirect_buf,
        0,
        p67_ws_redirect_entry_free,
        "Couldnt initialize redirect buffer\n");
}

p67_hashcntl_t *
redirect_buf_ix(void)
{
    p67_hashcntl_getter_fn(
        redirect_buf_ix_inilock,
        __redirect_buf_ix,
        0,
        p67_ws_redirect_entry_free,
        "Couldnt initialize redirect buffer index\n");
}

void
p67_ws_redirect_entry_free(p67_hashcntl_entry_t * e)
{
    if(!e) return;
    p67_ws_redirect_entry_t * re = 
        (p67_ws_redirect_entry_t *)e->value;
    if(re) {
        p67_addr_free(re->dst_addr);
        p67_addr_free(re->src_addr);
        #if defined(DEBUG)
        p67_err err = p67_hashcntl_remove_and_free(
            redirect_buf_ix,
            &re->msg_id,
            sizeof(re->msg_id));
        if(err) 
            p67_err_print_err("Couldnt remove entry from redirect index: ", err)
        #else
        p67_hashcntl_remove_and_free(
            redirect_buf_ix,
            &re->request_hdr.urg_mid,
            sizeof(re->msg_id));
        #endif
    }
    free(e);
}

p67_err
p67_ws_redirect_entry_add(
    p67_pdp_urg_hdr_t * req_msghdr, p67_addr_t * src, p67_addr_t * dst)
{
    p67_err err;

    p67_ws_redirect_entry_t * e = malloc(sizeof(p67_ws_redirect_entry_t));
    if(!e) return p67_err_eerrno;

    e->src_addr = p67_addr_ref_cpy(src);
    e->dst_addr = p67_addr_ref_cpy(dst);
    e->request_hdr = *req_msghdr;
    e->state = 0;
    e->state_lock = P67_XLOCK_STATE_UNLOCKED;

    p67_hashcntl_entry_t * entry = malloc(
        sizeof(p67_hashcntl_entry_t) + src->socklen + dst->socklen);
    if(!entry) {
        free(e);
        return p67_err_eerrno;
    }

    /* 
        both entry and entry index use composite key
        so access time is O(1) for both dst and src.  
    */
    entry->key = (unsigned char *)entry + sizeof(p67_hashcntl_entry_t);
    entry->keyl = src->socklen + dst->socklen;
    entry->next = NULL;
    entry->value = (unsigned char)e;
    entry->valuel = sizeof(p67_ws_redirect_entry_t);

    memcpy(entry->key, src->sock, src->socklen);
    memcpy(entry->key+src->socklen, dst->sock, dst->socklen);

    if((err = p67_hashcntl_add(redirect_buf, entry))) {
        free(e);
        return err;
    }
    
    free(entry);
    entry = malloc(
        sizeof(p67_hashcntl_entry_t) + sizeof(req_msghdr->urg_mid) + dst->socklen);
    if(!entry) {
        err = p67_err_eerrno;
        /* todo finish it */
        //err |= p67_hashcntl_remove(redirect_buf,)
        free(e);
        return err;
    }

    entry->key = (unsigned char *)entry + sizeof(p67_hashcntl_entry_t);
    entry->keyl = src->socklen + dst->socklen;
    entry->next = NULL;
    entry->value = (unsigned char)e;
    entry->valuel = sizeof(p67_ws_redirect_entry_t);

    memcpy(entry->key, &req_msghdr->urg_mid, sizeof(req_msghdr->urg_mid));
    memcpy(entry->key+sizeof(req_msghdr->urg_mid), dst->sock, dst->socklen);

    if((err = p67_hashcntl_add(redirect_buf_ix, entry))) {
        /* todo finish it */
        //err |= p67_hashcntl_remove(redirect_buf,)
        free(e);
        return err;
    }

    return 0;
}

typedef struct p67_ws_redirect_request_ctx {
    const char * src_svc;
    const char * dst_username;
    const char * src_message;
    uint8_t src_svc_l;
    uint8_t dst_username_l;
    uint8_t src_message_l;
} p67_ws_redirect_request_ctx_t;

p67_err
p67_ws_redirect_parse_request(
    const p67_pckt_t * msg, int msgl, 
    p67_ws_redirect_request_ctx_t * outval)
{
    if(!outval)
        return p67_err_einval;
    const int hdr_offset = sizeof(p67_pdp_urg_hdr_t);
    const p67_pckt_t * payload = msg + hdr_offset;
    int payload_len = msgl - hdr_offset;
    const p67_pckt_t * tlv_value;
    const p67_tlv_header_t * tlv_hdr;
    p67_ws_redirect_request_ctx_t ctx = {0};
    p67_err err;

    while((err = p67_tlv_next(
                &payload, &payload_len, &tlv_hdr, &tlv_value)) == 0) {
        switch(tlv_hdr->tlv_key[0]) {
        case 'p':
            if(!(ctx.src_svc = (char *)p67_tlv_get_cstr(tlv_hdr, tlv_value)))
                return p67_err_etlvf;
            ctx.src_svc_l = tlv_hdr->tlv_vlength - 1;
            break;
        case 'U':
            ctx.dst_username = (p67_pckt_t *)p67_tlv_get_cstr(tlv_hdr, tlv_value);
            if(!ctx.dst_username)
                return p67_err_etlvf;
            ctx.dst_username = tlv_value;
            ctx.dst_username_l = tlv_hdr->tlv_vlength - 1;
            break;
        case 'm':
            ctx.src_message = (p67_pckt_t *)p67_tlv_get_cstr(tlv_hdr, tlv_value);
            if(!ctx.src_message){
                return p67_err_etlvf;
            }
            ctx.src_message_l = tlv_hdr->tlv_vlength - 1;
            break;
        }
    }

    if(err != p67_err_eot || !ctx.dst_username)
        return err;

    *outval = ctx;
    return 0;
}

typedef struct p67_ws_redirect_response_ctx {
    p67_web_status status;
} p67_ws_redirect_response_ctx_t;

p67_err
p67_ws_redirect_parse_response(
    const p67_pckt_t * msg, int msgl, 
    p67_ws_redirect_response_ctx_t * outval)
{
    if(!outval)
        return p67_err_einval;
    const int hdr_offset = sizeof(p67_pdp_ack_hdr_t);
    const p67_pckt_t * payload = msg + hdr_offset;
    int payload_len = msgl - hdr_offset;
    const p67_pckt_t * tlv_value;
    const p67_tlv_header_t * tlv_hdr;
    p67_ws_redirect_response_ctx_t ctx = {0};
    int tlv_state = 0;
    p67_err err;

    while((err = p67_tlv_next(
            &payload, &payload_len, &tlv_hdr, &tlv_value)) == 0) {
        switch(tlv_hdr->tlv_key[0]) {
        case 's':
            if(tlv_hdr->tlv_vlength != sizeof(ctx.status))
                break;
            ctx.status = *(uint16_t *)tlv_value;
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
    }

    if(tlv_state != 0 || err != p67_err_eot)
        return err;

    *outval = ctx;
    return 0;
}

p67_err
p67_ws_redirect_create_request_msg(
    const p67_ws_session_t * session,
    const p67_ws_redirect_request_ctx_t * request,
    p67_addr_t * src_addr,
    p67_pdp_urg_hdr_t * src_msg_hdr,
    p67_pckt_t ** outmsg, int * outmsgl)
{
    if(!outmsg || !outmsgl)
        return p67_err_einval;

    p67_pckt_t * src_svc = request->src_svc ? 
                (p67_pckt_t *)request->src_svc : 
                (p67_pckt_t *)src_addr->service;
    uint8_t src_svc_l = request->src_svc ? 
                (uint8_t)(request->src_svc_l + 1) : 
                strlen(src_addr->service) + 1;
    p67_pckt_t * src_hostname = (p67_pckt_t *)src_addr->hostname;
    uint8_t src_hostname_l = strlen(src_addr->hostname) + 1;
    p67_pckt_t * src_message = request->src_message;
    uint8_t src_message_l = src_message ? request->src_message_l + 1 : 0;
    p67_pckt_t * src_username = session->username;
    p67_pckt_t src_username_l = session->username ? session->usernamel + 1 : 0; 

    int tlvres;
    int msglen = 
        sizeof(p67_pdp_urg_hdr_t) +
        src_hostname_l + P67_TLV_HEADER_LENGTH +
        src_svc_l + P67_TLV_HEADER_LENGTH +
        src_message_l + P67_TLV_HEADER_LENGTH +
        src_username_l + P67_TLV_HEADER_LENGTH;
    if(msglen > P67_DML_SAFE_PAYLOAD_SIZE) {
        return p67_err_enomem;
    }
    p67_pckt_t * msg = malloc(msglen);
    int msgix = 0;

    if(!p67_pdp_generate_urg_for_msg(
                NULL, 0, msg, sizeof(p67_pdp_urg_hdr_t), src_msg_hdr->urg_utp)) {
        free(msg);
        return p67_err_einval;
    }

    msgix+=sizeof(p67_pdp_urg_hdr_t);

    if((tlvres = p67_tlv_add_fragment(
            msg+msgix, 
            msglen-msgix, 
            (unsigned char *) "p", 
            src_svc,
            src_svc_l)) < 0) {
        free(msg);
        return (p67_err)-tlvres;
    }

    msgix+=tlvres;

    if((tlvres = p67_tlv_add_fragment(
            msg+msgix,
            msglen-msgix,
            (unsigned char *) "a", 
            src_hostname,
            src_hostname_l)) < 0) {
        free(msg);
        return (p67_err)-tlvres;
    }

    msgix+=tlvres;

    if(src_message) {
        if((tlvres = p67_tlv_add_fragment(
                msg+msgix, 
                msglen-msgix, 
                (unsigned char *) "m",
                src_message,
                src_message_l)) < 0) {
            free(msg);
            return (p67_err)-tlvres;
        }
        msgix+=tlvres;
    }

    if(session->username) {
        if((tlvres = p67_tlv_add_fragment(
                msg+msgix, 
                msglen-msgix, 
                (unsigned char *) "u", 
                session->username,
                session->usernamel)) < 0) {
            free(msg);
            return (p67_err)-tlvres;
        }
        msgix+=tlvres;
    }

    /* 
        at the end we should have written data 
        into exactly all of the buffer. 
    */
    assert(msgix == msglen);

    *outmsg = msg;
    *outmsgl = msglen;
}

p67_err
p67_ws_redirect_create_response_msg(
    const p67_ws_session_t * session,
    const p67_ws_redirect_response_ctx_t * response,
    const p67_ws_redirect_entry_t * request_entry,
    p67_pckt_t ** outmsg, int * outmsgl)
{
    if(!outmsg || !outmsgl)
        return p67_err_einval;

    int isok = response->status == p67_web_status_ok;

    p67_pckt_t * svc = isok ? (p67_pckt_t *)request_entry->dst_addr->service : NULL;
    p67_pckt_t * hst = isok ? (p67_pckt_t *)request_entry->dst_addr->hostname : NULL;

    int hstl = isok ? strlen(request_entry->dst_addr->hostname) + 1 : 0;
    int svcl = isok ? strlen(request_entry->dst_addr->service) + 1 : 0;

    int tlvres;
    int msglen = 
        sizeof(p67_pdp_ack_hdr_t) +
        sizeof(response->status) + P67_TLV_HEADER_LENGTH +
        hstl + P67_TLV_HEADER_LENGTH +
        svcl + P67_TLV_HEADER_LENGTH;
    if(msglen > P67_DML_SAFE_PAYLOAD_SIZE) {
        return p67_err_enomem;
    }
    p67_pckt_t * msg = malloc(msglen);
    p67_err err;
    int msgix = 0;
    

    if((err = p67_pdp_generate_ack_from_hdr(
                &request_entry->request_hdr, NULL, 0, msg, msglen))) {
        free(msg);
        return p67_err_einval;
    }

    msgix+=sizeof(p67_pdp_ack_hdr_t);

    if((tlvres = p67_tlv_add_fragment(
            msg+msgix,
            msglen-msgix, 
            (unsigned char *) "s", 
            (p67_pckt_t *)&response->status,
            sizeof(response->status))) < 0) {
        free(msg);
        return (p67_err)-tlvres;
    }

    msgix+=tlvres;

    if(isok) {
        if((tlvres = p67_tlv_add_fragment(
                msg+msgix,
                msglen-msgix,
                (unsigned char *) "A", 
                hst,
                hstl)) < 0) {
            free(msg);
            return (p67_err)-tlvres;
        }

        msgix+=tlvres;

        if((tlvres = p67_tlv_add_fragment(
                msg+msgix, 
                msglen-msgix, 
                (unsigned char *) "P",
                svc,
                svcl)) < 0) {
            free(msg);
            return (p67_err)-tlvres;
        }
        msgix+=tlvres;
    }

    /* 
        at the end we should have written data 
        into exactly all of the buffer. 
    */
    assert(msgix == msglen);

    *outmsg = msg;
    *outmsgl = msglen;
}

p67_err
p67_ws_redirect_handle_urg(
    p67_ws_session_t * session,
    p67_addr_t * src_addr,
    const p67_pckt_t * msg, int msgl)
{
    p67_hashcntl_entry_t * dst_user, * src_user;
    p67_pckt_t * request_msg;
    int request_msg_l;
    p67_err err;
    p67_ws_redirect_request_ctx_t rctx;

    if((err = p67_ws_redirect_parse_request(msg, msgl, &rctx))) {
        return err;
    }

    dst_user = p67_hashcntl_lookup(
        session->login_user_cache, 
        rctx.dst_username, 
        rctx.dst_username_l);

    if(!dst_user) {
        return p67_web_tlv_respond_with_status(
            (p67_pdp_urg_hdr_t *)msg, 
            src_addr, p67_web_status_not_found);
    }

    p67_addr_t * dst_addr = (p67_addr_t*)dst_user->value;
    
    err = p67_ws_redirect_create_request_msg(
        session, &rctx, 
        src_addr, 
        (p67_pdp_urg_hdr_t *)msg, 
        &request_msg, &request_msg_l);

    if(err) {
        p67_err_print_err_dbg("Couldnt create redirect_request message: ", err);
        return p67_web_tlv_respond_with_status(
            (p67_pdp_urg_hdr_t *)msg, 
            src_addr, p67_web_status_server_fault);
    }

    if((err = p67_ws_redirect_entry_add(
            (p67_pdp_urg_hdr_t *)msg,
            src_addr,
            dst_addr))) {
        p67_err_print_err_dbg("Couldnt add redirect entry: ", err);
        return p67_web_tlv_respond_with_status(
            (p67_pdp_urg_hdr_t *)msg, 
            src_addr, p67_web_status_server_fault);
    }

    err = p67_pdp_write_urg(
        dst_addr, request_msg, request_msg_l, 30 * SECOND, 
        NULL, NULL, NULL);

    if(err) {
        free(request_msg);
        p67_err_print_err_dbg("Couldnt send message: ", err);
        return p67_web_tlv_respond_with_status(
            (p67_pdp_urg_hdr_t *)msg, 
            src_addr, p67_web_status_server_fault);
    }

    return 0;
}

p67_err
p67_ws_redirect_handle_ack(
    p67_ws_session_t * session,
    p67_addr_t * addr,
    const p67_pckt_t * msg, int msgl)
{
    uint16_t mid = p67_cmn_ntohs(((p67_pdp_urg_hdr_t *)msg)->urg_mid);
    char key[sizeof(mid) + addr->socklen];
    p67_ws_redirect_response_ctx_t res;
    p67_err err;

    if((err = p67_dml_handle_msg(addr, msg, msgl, NULL))) {
        return err;
    }

    if((err = p67_ws_redirect_parse_response(msg, msgl, &res))) {
        //p67_err_print_err_dbg("Couldnt parse response: ", err);
        // return p67_web_tlv_respond_with_status(
        //     (p67_pdp_urg_hdr_t *)msg, 
        //     addr, p67_web_status_bad_request);
        return err;
    }

    #warning TODO : finish response, handle login, add ttl for hashcntl and should be ok for testing.

    return 0;
}

