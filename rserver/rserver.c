#include "rserver.h"
#include "bwt.h"

#include <stdlib.h>
#include <string.h>
#include <strings.h>

#include <p67/p67.h>

#define P67RS_SERVER_LOGIN_TAG (unsigned char *)"l"
#define P67RS_SERVER_BWT_TAG (unsigned char *)"b"

#define P67RS_SERVER_PATH_LOGIN 'l'
#define P67RS_SERVER_PATH_CALL 'c'

#define P67RS_SERVER_MAX_CREDENTIAL_LENGTH 128

#define __UC (unsigned char *)
#define __C (char *)

typedef struct p67rs_session_fwcall {
    p67_sockaddr_t * peer_saddr;
    size_t peer_saddr_l;
    char __padd[
            sizeof(char *) + // value
            sizeof(size_t) +  // value length
            sizeof(p67_hashcntl_entry_t *) ]; // next
} p67rs_session_fwcall_t;

p67_cmn_static_assert(
    sizeof(char *) == sizeof(p67_sockaddr_t *));
p67_cmn_static_assert(
    sizeof(p67rs_session_fwcall_t) == sizeof(p67_hashcntl_entry_t));

typedef struct p67rs_server_session {
    uint64_t       sessid;
    p67rs_server_t * server;
    char           * username;
    p67_hashcntl_t * fwcall;
} p67rs_server_session_t;

p67_err 
p67rs_fwcall_add(
    p67_hashcntl_t * ctx, p67_addr_t * addr)
{
    p67rs_session_fwcall_t * fc = malloc(
        sizeof(p67rs_session_fwcall_t) + sizeof(p67_sockaddr_t));
    if(!fc)
        return p67_err_eerrno;
    p67_sockaddr_t * sa = (p67_sockaddr_t *)((char *)fc + sizeof(p67rs_session_fwcall_t));
    *sa = addr->sock;
    fc->peer_saddr_l = addr->socklen;
    return p67_hashcntl_add(ctx, (p67_hashcntl_entry_t *)fc);
}

void
p67rs_fwcall_remove_and_free(p67_hashcntl_t * ctx, p67_addr_t * saddr)
{
    p67_hashcntl_entry_t * entry;
    entry = p67_hashcntl_remove(ctx, __UC &saddr->sock, saddr->socklen);
    free(entry);
}

void
p67rs_fwcall_free(p67_hashcntl_entry_t * entry)
{
    free(entry);
}

p67_err
p67rs_usermap_remove(
    p67rs_usermap_t * usermap,
    char * username,
    size_t usernamel)
{
    return p67_hashcntl_remove_and_free(
        usermap, __UC username, usernamel);
}

const p67rs_usermap_entry_t *
p67rs_usermap_lookup(
    p67rs_usermap_t * usermap,
    const char * username,
    size_t usernamel)
{
    const p67_hashcntl_entry_t * entry;
    if((entry = p67_hashcntl_lookup(
                usermap, __UC username, usernamel)) == NULL) {
        return NULL;
    }

    p67rs_usermap_entry_t * ret = (p67rs_usermap_entry_t *)entry;

    return ret;
}

p67rs_err
p67rs_usermap_add(
    p67rs_usermap_t * usermap,
    const char * username, size_t usernamel,
    const p67_sockaddr_t * saddr)
{
    unsigned char * block = malloc(sizeof(p67_hashcntl_entry_t)+usernamel+sizeof(*saddr));
    if(!block) return p67_err_eerrno;
    p67_hashcntl_entry_t * entry = (p67_hashcntl_entry_t *)block;
    unsigned char * key = block + sizeof(p67_hashcntl_entry_t);
    unsigned char * value = block + sizeof(p67_hashcntl_entry_t) + usernamel;
    memcpy(key, username, usernamel);
    memcpy(value, saddr, sizeof(*saddr));
    entry->valuel = sizeof(*saddr);
    entry->keyl = usernamel;
    entry->value = value;
    entry->key = key;
    entry->next = NULL;
    return p67_hashcntl_add(usermap, entry);
}

void
p67rs_usermap_free_item(p67_hashcntl_entry_t * entry)
{
    free(entry);
}

p67rs_err
p67rs_usermap_create(
    p67rs_usermap_t ** usermap,
    size_t usermap_capacity)
{
    *usermap = p67_hashcntl_new(
        (size_t)usermap_capacity, 
        p67rs_usermap_free_item, 
        NULL);
    if(!*usermap)
        return p67_err_eerrno;
    return 0;
}

p67rs_err
p67rs_server_respond_with_err(
    p67_conn_t * conn, p67rs_werr werr,
    const unsigned char * const msg, int msgl)
{
    uint16_t serr = p67_cmn_htons((uint16_t)werr);
    p67rs_err err;
    unsigned char ackmsg[P67_TLV_HEADER_LENGTH+sizeof(serr)];
    char ack[P67_PDP_ACK_OFFSET + sizeof(ackmsg)];

    if(p67_tlv_add_fragment(
            ackmsg, sizeof(ackmsg), 
            (unsigned char *)"s", (unsigned char *)&serr, sizeof(serr)) < 0)
        return p67_err_einval;

    if((err = p67_pdp_generate_ack(
            msg, msgl, 
            ackmsg, sizeof(ackmsg), 
            ack, sizeof(ack))) != 0)
        return err;

    if((err = p67_net_must_write_conn(conn, ack, sizeof(ack))) != 0)
        return err;

    return 0;
}

// p67rs_err
// p67rs_server_respond_with_bwt(
//     p67_conn_t * conn,
//     const unsigned char * command,
//     const unsigned char * const msg, int msgl,
//     p67rs_bwt_t * bwt)
// {
//     uint32_t serr = p67_cmn_htonl((uint32_t)0);
//     p67rs_err err;
//     const int status_offset = P67_TLV_HEADER_LENGTH + sizeof(serr);
//     const int bwt_offset = P67_TLV_HEADER_LENGTH + sizeof(*bwt);
//     unsigned char ackmsg[status_offset + bwt_offset];
//     char ack[P67_PDP_ACK_OFFSET + sizeof(ackmsg)];

//     if(p67_tlv_add_fragment(
//             ackmsg, status_offset, 
//             command, 
//             (unsigned char *)&serr, sizeof(serr)) < 0)
//         return p67_err_einval;

//     if(p67_tlv_add_fragment(
//             ackmsg+status_offset, sizeof(ackmsg)-status_offset, 
//             P67RS_SERVER_BWT_TAG, 
//             (unsigned char *)bwt, sizeof(*bwt)) < 0)
//         return p67_err_einval;

//     if((err = p67_pdp_generate_ack(
//             msg, msgl, 
//             ackmsg, sizeof(ackmsg), 
//             ack, sizeof(ack))) != 0)
//         return err;

//     if((err = p67_net_must_write_conn(conn, ack, sizeof(ack))) != 0)
//         return err;

//     return 0;
// }

typedef struct p67_handle_call_ctx {
    p67_conn_t * conn;
    p67rs_server_session_t * session;
    unsigned char * msg;
    int msgl;
    unsigned char * payload;
    int payloadl;
} p67rs_handle_call_ctx_t;

p67rs_handle_call_ctx_t * p67rs_handle_call_ctx_create(
    p67_conn_t * conn, 
    p67rs_server_session_t * session,
    const unsigned char * const msg, int msgl,
    const unsigned char * payload, int payload_len)
{
    (void)payload_len;
    p67rs_handle_call_ctx_t * ctx = malloc(
        sizeof(p67rs_handle_call_ctx_t) + msgl);
    if(!ctx)
        return NULL;
    unsigned char * _msg = 
        (unsigned char *)(((char *)ctx) + sizeof(p67rs_handle_call_ctx_t));
    memcpy(_msg, msg, msgl);
    int offset = payload - msg;
    if(offset < 0) return NULL;
    ctx->conn = conn;
    ctx->msg = _msg;
    ctx->msgl = msgl;
    ctx->payload = _msg + offset;
    if(offset > msgl)
        return NULL;
    ctx->payloadl = msgl - offset;
    ctx->session = session;

    return ctx;
}


p67rs_err
p67rs_server_handle_call(
    p67_conn_t * conn, 
    p67rs_server_session_t * session,
    const unsigned char * const msg, int msgl,
    const unsigned char * payload, int payload_len)
{
    /*
        src tries to call dst
    */

    p67rs_err err = 0;
    int added_fwcall = 0;
    uint16_t werr = 0;
    const p67rs_usermap_entry_t * entry;

    const unsigned char * tlv_value;
    const p67_tlv_header_t * tlv_header;

    struct {
        const char * username;
        size_t usernamel;
        uint16_t port;
        p67_addr_t addr;
    } src_call_peer, dst_call_peer;

    const char * hint;
    unsigned char hintl;
    p67_addr_t * tmpaddr = (p67_addr_t*)p67_conn_get_addr(conn);
    if(!tmpaddr)
        return p67_err_einval;
    src_call_peer.addr = *tmpaddr;
    
    int tlv_state = 0;

    const int fwdmsgl = 180;
    unsigned char fwdmsg[fwdmsgl];
    int fwdmsgix = 0;

    /*
        $1:
        
        src executes call request to RS with following parameters: 
            (encoded in tlv fragments)
        s = <src port>     | optional
        N = <dst name>     | name of destination object
        h = hint           | optional encouragment message passed to dst

    */

    while((err = p67_tlv_next(&payload, &payload_len, &tlv_header, &tlv_value)) == 0) {
        switch(tlv_header->key[0]) {
        case 's':
            if(tlv_header->vlength != 2)
                break;
            src_call_peer.port = p67_cmn_ntohs(*(uint16_t *)tlv_value);
            tlv_state |= 1;
            break;
        case 'N':
            if(tlv_header->vlength == 0 || 
                    tlv_header->vlength > P67RS_SERVER_MAX_CREDENTIAL_LENGTH)
                break;
            dst_call_peer.username = (char *)tlv_value;
            dst_call_peer.usernamel = tlv_header->vlength;
            tlv_state |= 2;
            break;
        case 'h':
            hint = (char *)tlv_value;
            hintl = tlv_header->vlength;
            tlv_state |= 4;
            break;
        }
        if(tlv_state & (1 | 2 | 4))
            break;
    }

    if(err == (p67rs_err)p67_err_eot) err = 0;
    if(err != 0) {
        werr = p67rs_werr_400;
        goto end;
    }
    
    if(!(tlv_state & 2)) {
        err = p67_err_einval;
        werr = p67rs_werr_400;
        goto end;
    }

    if((entry = p67rs_usermap_lookup(
            session->server->usermap, 
            dst_call_peer.username, 
            dst_call_peer.usernamel)) == NULL) {
        err = p67_err_enconn;
        werr = p67rs_werr_ecall;
        goto end;
    }

    if((err = p67_addr_set_sockaddr(
            &dst_call_peer.addr, 
            entry->saddr, 
            sizeof(entry->saddr))) != 0) {
        goto end;
    }
    
    if((entry = p67rs_usermap_lookup(
            session->server->usermap, 
            session->username, 
            strlen(session->username))) == NULL) {
        src_call_peer.username = NULL;
        // right now user is allowed to call someone even if not logged in.
        // err = p67_err_enconn;
        // goto end;
    }

    if((err = p67rs_fwcall_add(session->fwcall, &dst_call_peer.addr)) != 0) {
        werr = p67rs_werr_eacall;
        goto end;
    }
    added_fwcall = 1;

    /*
        $2:

        RS forward src's call request to dst with following parameters: 
            (encoded in tlv fragments)
        S = <src ip>       | IPv4/6 address of src
        s = <src port>     | port either currently used src port or suggested by src
        h = hint           | optional passed from $1
        N = <src username> | optional username of src
    */

    if(p67_pdp_generate_urg_for_msg(
            NULL, 0, (char *)fwdmsg+fwdmsgix, fwdmsgl-fwdmsgix, 
            P67RS_SERVER_PATH_CALL) == NULL) {
        err = p67_err_einval;
        werr = p67rs_werr_500;
    }
    fwdmsgix += sizeof(p67_pdp_urg_hdr_t);

    if((err = p67_tlv_add_fragment(
            fwdmsg+fwdmsgix, fwdmsgl+fwdmsgix, __UC "S",
            __UC src_call_peer.addr.hostname, 
            strlen(src_call_peer.addr.hostname))) < 0) {
        err=-err;
        goto end;
    } else {
        fwdmsgix+=err;
    }

    if((err = p67_tlv_add_fragment(
            fwdmsg+fwdmsgix, fwdmsgl+fwdmsgix, __UC "s",
            (tlv_state & 1) ? __UC &src_call_peer.port : __UC src_call_peer.addr.service, 
            sizeof(uint16_t))) < 0) {
        err=-err;
        goto end;
    } else {
        fwdmsgix+=err;
    }

    if(src_call_peer.username) {
        if((err = p67_tlv_add_fragment(
                fwdmsg+fwdmsgix, fwdmsgl+fwdmsgix, __UC "N",
                __UC src_call_peer.username, 
                strlen(src_call_peer.username)) <= 0)) {
            err=-err;
            goto end;
        } else {
            fwdmsgix+=err;
        }
    }

    if(tlv_state & 4) {
        if((err = p67_tlv_add_fragment(
                fwdmsg+fwdmsgix, fwdmsgl+fwdmsgix, __UC "h",
                __UC hint, hintl) <= 0)) {
            err=-err;
            goto end;
        } else {
            fwdmsgix+=err;
        }
    }

    p67_async_t fwdto = P67_ASYNC_INTIIALIZER;
    char * fwdres, * fwdresptr;
    int fwdresl;

    if((err = p67_pdp_write_urg(
            &dst_call_peer.addr, 
            fwdmsg, fwdmsgix, 
            0, 
            &fwdto, 
            (void **)&fwdres, &fwdresl)) != 0)
        goto end;

    p67_pdp_ack_hdr_t pack;
    p67_pdp_urg_hdr_t * urg = (p67_pdp_urg_hdr_t *)p67_dml_parse_hdr(msg, msgl, NULL);
    if(!urg || (urg->urg_stp != P67_DML_STP_PDP_URG)) {
        err = p67_err_einval;
        werr = p67rs_werr_500;
        goto end;
    }
    pack.ack_stp = P67_DML_STP_PDP_PACK;
    pack.ack_utp = urg->urg_utp;
    pack.ack_mid = urg->urg_mid;

    if((err = p67_net_must_write_conn(conn, &pack, sizeof(pack))) != 0)
        goto end;

    if((err = p67_mutex_wait_for_change(&fwdto, 0, -1)) != 0)
        goto end;

    if(fwdto != P67_PDP_EVT_GOT_ACK) {
        err = p67_err_einval;
        werr = p67rs_werr_ecall;
        goto end;
    }

    tlv_state = 0;

    fwdresptr = fwdres;

    while((err = p67_tlv_next(
            (const unsigned char **)&fwdresptr, 
            &fwdresl, 
            &tlv_header, 
            &tlv_value)) == 0) {
        
        switch(tlv_header->key[0]) {
        case 's':
            if(tlv_header->vlength != 2) return p67_err_einval;
            werr = p67_cmn_ntohs(*(uint16_t *)tlv_value);
            if(werr != 0) {
                werr = p67rs_werr_ecall;
                free(fwdres);
                goto end;
            }
            tlv_state |= 1;
            break;
        default:
            break;
        }

        if(tlv_state == 1){
            break;
        }
    }

    if(err == (p67rs_err)p67_err_eot) err = 0;
    if(err != 0) {
        werr = p67rs_werr_400;
        goto end;
    }
    
    if(!(tlv_state & 1)) {
        err = p67_err_einval;
        werr = p67rs_werr_ecall;
        goto end;
    }


    fwdmsgix = 0;

    if((err = p67_pdp_generate_ack(
            msg, msgl, 
            NULL, 0, 
            __C fwdmsg, fwdmsgl)) != 0) {
        werr = p67rs_werr_500;
        goto end;
    } else {
        fwdmsgix+=sizeof(p67_pdp_urg_hdr_t);
    }

    if((err = p67_tlv_add_fragment(
                fwdmsg+fwdmsgix, fwdmsgl-fwdmsgix,
                __UC "s", __UC "\0", 2)) != 0) {
        err=-err;
        goto end;
    } else {
        fwdmsgix+=err;
    }

    if((err = p67_tlv_add_fragment(
            fwdmsg+fwdmsgix, fwdmsgl+fwdmsgix, __UC "T",
            __UC dst_call_peer.addr.hostname, 
            strlen(dst_call_peer.addr.hostname))) < 0) {
        err=-err;
        goto end;
    } else {
        fwdmsgix+=err;
    }

    if((err = p67_tlv_add_fragment(
            fwdmsg+fwdmsgix, fwdmsgl+fwdmsgix, __UC"t",
            __UC dst_call_peer.addr.service, 
            sizeof(uint16_t))) < 0) {
        err=-err;
        goto end;
    } else {
        fwdmsgix+=err;
    }

    if((err = p67_net_must_write_conn(conn, fwdmsg, fwdmsgl)) != 0) 
        goto end;

    err = -1;
    werr = p67rs_werr_eacall;

end:
    if(added_fwcall)
        p67rs_fwcall_remove_and_free(session->fwcall, &dst_call_peer.addr);
    
    if(err == 0) {
        return 0;
    } else {
        p67_err_print_err("error/s occured in server handle call: ", err);
        if(!werr) werr = p67rs_werr_400;
        return p67rs_server_respond_with_err(conn, werr, msg, msgl);
    }
}

void *
p67rs_server_handle_call_wrapper(void * args)
{
    p67rs_handle_call_ctx_t * ctx = (p67rs_handle_call_ctx_t *)args;
    if(!ctx) return NULL;
    p67_err err;

    if((err = p67rs_server_handle_call(
                ctx->conn, 
                ctx->session, 
                ctx->msg, 
                ctx->msgl, 
                ctx->payload, 
                ctx->payloadl)) != 0) {
        p67rs_err_print_err("handle call returned error/s : ", err);
    }

    free(ctx);

    return NULL;
}

p67rs_err
p67rs_server_handle_login(
    p67_conn_t * conn, 
    p67rs_server_session_t * sess,
    const unsigned char * const msg, int msgl,
    const unsigned char * payload, int payload_len)
{
    p67rs_err err = 0;
    p67rs_werr werr = 0;
    const p67_addr_t * remote = p67_conn_get_addr(conn);
    if(!remote)
        return p67_err_einval;
    char * username;
    size_t usernamel, passwordl;
    unsigned char * password;
    const unsigned char * tlv_value;
    int state = 0;
    const p67_tlv_header_t * tlv_hdr;

    while((err = p67_tlv_next(
            &payload, &payload_len, &tlv_hdr, &tlv_value)) == 0) {

        switch(tlv_hdr->key[0]) {
        case 'u':
            if(tlv_hdr->vlength < 1 || tlv_hdr->vlength > P67RS_SERVER_MAX_CREDENTIAL_LENGTH) {
                werr = p67rs_werr_400;
                goto end;
            }
            username = (char *)tlv_value;
            usernamel = tlv_hdr->vlength;
            state |= 1;
            break;
        case 'p':
            if(tlv_hdr->vlength < 1 || tlv_hdr->vlength > P67RS_SERVER_MAX_CREDENTIAL_LENGTH) {
                werr = p67rs_werr_400;
                goto end;
            }
            password = (unsigned char *)tlv_value;
            passwordl = tlv_hdr->vlength;
            state |= 2;
            break;
        }
    }

    if(state != (1 | 2)) {
        werr = p67rs_werr_400;
        goto end;
    }

    if((err = p67rs_db_user_validate_pass(
                sess->server->db_ctx, 
                username, usernamel, 
                password, passwordl)) != 0) {
        werr = p67rs_werr_401;
        goto end;
    }

    if((err = p67rs_usermap_add(
            sess->server->usermap, 
            username, usernamel, 
            &remote->sock)) != 0) {
        if(err == (p67rs_err)p67_err_eaconn) {
            err = 0;
            // p67rs_usermap_entry_t * entry;
            // if((entry = (p67rs_usermap_entry_t *)p67rs_usermap_lookup(
            //             server->usermap, username)) == NULL) {
            //     werr = p67rs_werr_500;
            //     goto end;
            // }
            // entry->saddr = remote->sock;
        } else {
            werr = p67rs_werr_500;
            goto end;
        }
    }

    if(sess->username == NULL || 
            ( ( strlen(sess->username) != usernamel) && 
                memcmp(sess->username, username, usernamel)) ) {
        char * susername;
        if((susername = malloc(usernamel+1)) == NULL) {
            werr = p67rs_werr_500;
            goto end;
        }

        memcpy(susername, username, usernamel);
        susername[usernamel] = 0;

        free(sess->username);
        sess->username = susername;
    }


end:
    return p67rs_server_respond_with_err(conn, werr, msg, msgl);
}

p67_err
p67rs_server_cb(
    p67_conn_t * conn, 
    const char * const msg, const int msgl, 
    void * args)
{
    p67rs_server_session_t * sess = (p67rs_server_session_t *)args;
    if(sess == NULL)
        return p67_err_einval;
    const p67_addr_t * peer = p67_conn_get_addr(conn);
    p67rs_err err = 0;
    const p67_dml_hdr_store_t * hdr;
    p67rs_handle_call_ctx_t * cctx;
    p67_thread_t thr;
    int handled = 0;

    if((hdr = p67_dml_parse_hdr((unsigned char *)msg, msgl, NULL)) == NULL) {
        printf("Couldnt parse dml header\n");
        return p67_err_epdpf;
    }
 
    switch(hdr->cmn.cmn_stp) {
    // case P67_DML_STP_PDP_ACK:
    //     break;
    case P67_DML_STP_PDP_URG:
    
        switch(hdr->cmn.cmn_utp) {
        case 0:
            return p67_dml_handle_msg(conn, msg, msgl, NULL);
        case P67RS_SERVER_PATH_LOGIN:
            err = p67rs_server_handle_login(
                    conn, sess,
                    (const unsigned char *)msg, msgl, 
                    (unsigned char *)msg+sizeof(hdr->urg), 
                    msgl-sizeof(hdr->urg));
            break;
        case P67RS_SERVER_PATH_CALL:
            handled = 1;
            cctx = p67rs_handle_call_ctx_create(
                conn, sess,
                __UC msg, msgl, 
                __UC msg + sizeof(hdr->urg),
                msgl - sizeof(hdr->urg));
            if(!cctx) {
                err = p67_err_eerrno;
                break;
            }
            err = p67_cmn_thread_create(
                &thr, p67rs_server_handle_call_wrapper, cctx);
            // if((err = p67rs_server_handle_call(
            //         conn, sess,
            //         (const unsigned char *)msg, msgl, 
            //         (unsigned char *)msg+sizeof(hdr->urg), 
            //         msgl-sizeof(hdr->urg))) != 0) {
            //     p67rs_err_print_err("handle call returned error/s: ", err);
            // }
            // if(err != (p67rs_err)p67_err_eagain)
            //     handled = 1;
            break;
        default:
            printf(
                "handler %s:%s: 404 for utp=%u\n", 
                peer->hostname, peer->service, hdr->cmn.cmn_utp);
            return p67_err_einval;
        }
        
        break;
    default:
        break;
    }

    if(err != (p67rs_err)p67_err_eagain)
        handled = 1;
    if(err != 0)
        p67rs_err_print_err("error/s in server cb: ", err);

    if(handled) {
        return 0;
    } else {
        if((err = p67_dml_handle_msg(conn, msg, msgl, NULL)) != 0 && err != (p67rs_err)p67_err_eagain) {
            p67rs_err_print_err("handle dml returned error/s: ", err);
        }
    }
    return 0;
}

p67_async_t sesslock = P67_ASYNC_INTIIALIZER;
volatile uint64_t sessid = 0;

void * p67rs_server_session_create(void * args)
{
    if(!args) return NULL;

    p67rs_server_t * server = (p67rs_server_t *)args;
    
    p67rs_server_session_t * p = calloc(1, sizeof(p67rs_server_session_t));
    if(p == NULL) {
        p67_err_print_err("ERR in create client session: ", p67_err_eerrno);
        return NULL;
    }

    p->fwcall = p67_hashcntl_new(10, p67rs_fwcall_free, NULL);
    if(!p->fwcall) {
        p67_err_print_err("ERR in create client session: ", p67_err_eerrno);
        return NULL;
    }

    p67_spinlock_lock(&sesslock);
    
    p->sessid=(sessid++);

    p67_spinlock_unlock(&sesslock);

    p->server = server;

    return p;
}

void p67rs_server_session_free(void * s)
{
    if(!s) return;
    p67rs_server_session_t * sess = (p67rs_server_session_t *)s;
    if(sess->username) {
        p67rs_usermap_remove(
            sess->server->usermap, 
            sess->username, 
            strlen(sess->username));
        free(sess->username);
    }
    p67_hashcntl_free(sess->fwcall);
    free(sess);
}

void
p67rs_server_setup_pass(p67_conn_pass_t * pass, p67rs_server_t * server)
{
    pass->handler = p67rs_server_cb;
    pass->gen_args = p67rs_server_session_create;
    pass->free_args = p67rs_server_session_free;
    pass->args = server;
}
