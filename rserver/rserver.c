#include "rserver.h"
#include "bwt.h"

#include <stdlib.h>
#include <string.h>

#include <p67/p67.h>

#define P67RS_SERVER_LOGIN_TAG (unsigned char *)"l"
#define P67RS_SERVER_BWT_TAG (unsigned char *)"b"

#define P67RS_SERVER_PATH_LOGIN 'l'

#define P67RS_SERVER_MAX_CREDENTIAL_LENGTH 128


typedef struct p67rs_server_session {
    uint64_t       sessid;
    p67rs_server_t * server;
    char           * username;
} p67rs_server_session_t;


/*****/

p67rs_err
p67rs_usermap_add(
    p67rs_usermap_t * usermap,
    const char * username, size_t usernamel,
     const p67_sockaddr_t * saddr);

const p67rs_usermap_entry_t *
p67rs_usermap_lookup(
    p67rs_usermap_t * usermap,
    const char * username);

p67_err
p67rs_usermap_remove(
    p67rs_usermap_t * usermap,
    char * username);

p67rs_err
p67rs_respond_with_err(
    p67_conn_t * conn, p67rs_werr err,
    const unsigned char * command,
    const unsigned char * const msg, int msgl);
    
p67rs_err
p67rs_server_handle_command(
    p67_conn_t * conn, 
    p67rs_server_t * server,
    const unsigned char * const msg, const int msgl,
    const unsigned char * payload, int payloadl);

p67rs_err
p67rs_server_handle_login(
    p67_conn_t * conn, 
    p67rs_server_t * server,
    const unsigned char * const msg, int msgl,
    const unsigned char * payload, int payload_len);

p67_err
p67rs_server_cb(
    p67_conn_t * conn, 
    const char * const msg, const int msgl, 
    void * args);

/*****/

p67_err
p67rs_usermap_remove(
    p67rs_usermap_t * usermap,
    char * username)
{
    size_t usernamel = strlen(username);
    p67_hash_t hash = p67_hash_fn(
        (unsigned char *)username, usernamel, usermap->buffer_capacity);
    p67rs_usermap_entry_t * prev_entry = NULL, * entry;

    p67_spinlock_lock(&usermap->rwlock);

    for(entry = usermap->buffer[hash]; entry != NULL; entry=entry->next) {
        if(strlen(entry->username) == usernamel 
                    && (memcmp(username, entry->username, usernamel) == 0))
            break;
        prev_entry = entry;
    }

    if(entry == NULL) {
        p67_spinlock_unlock(&usermap->rwlock);
        return p67_err_enconn;
    }

    if(prev_entry == NULL) {
        usermap->buffer[hash] = NULL;
    } else {
        prev_entry->next = entry->next;
    }

    free(entry->username);
    free(entry);

    return 0;
}

const p67rs_usermap_entry_t *
p67rs_usermap_lookup(
    p67rs_usermap_t * usermap,
    const char * username)
{
    size_t usernamel = strlen(username);
    p67_hash_t hash = p67_hash_fn(
        (unsigned char *)username, usernamel, usermap->buffer_capacity);
    p67rs_usermap_entry_t ** prev_entry, * entry;

    p67_spinlock_lock(&usermap->rwlock);

    for(prev_entry = usermap->buffer + hash; (entry = *prev_entry); prev_entry=&entry->next) {
        if(strlen(entry->username) == usernamel 
                    && (memcmp(username, entry->username, usernamel) == 0)) {
            p67_spinlock_unlock(&usermap->rwlock);
            return entry;
        }
    }
    
    p67_spinlock_unlock(&usermap->rwlock);
    return NULL;
}

p67rs_err
p67rs_usermap_add(
    p67rs_usermap_t * usermap,
    const char * username, size_t usernamel,
     const p67_sockaddr_t * saddr)
{
    if(usermap == NULL || usermap->buffer == NULL)
        return p67_err_einval;
    
    p67rs_usermap_entry_t ** prev_entry, * entry;

    p67_hash_t hash = p67_hash_fn(
        (unsigned char *)username, usernamel, usermap->buffer_capacity);

    p67_spinlock_lock(&usermap->rwlock);

    for(prev_entry = usermap->buffer + hash; (entry = *prev_entry); prev_entry=&entry->next) {
        if(strlen(entry->username) == usernamel 
                    && (memcmp(username, entry->username, usernamel) == 0)) {
            p67_spinlock_unlock(&usermap->rwlock);
            return p67_err_eaconn;
        }
    }
    
    if((*prev_entry = calloc(1, sizeof(**prev_entry))) == NULL) {
        p67_spinlock_unlock(&usermap->rwlock);
        return p67_err_eerrno;
    }

    entry = *prev_entry;

    if((entry->username = strdup(username)) == NULL) {
        free(*prev_entry);
        *prev_entry = NULL;
        p67_spinlock_unlock(&usermap->rwlock);
        return p67_err_eerrno;
    }

    entry->saddr = *saddr;
    entry->next = NULL;

    p67_spinlock_unlock(&usermap->rwlock);
    return 0;
}

void
p67rs_usermap_free(p67rs_usermap_t * usermap)
{
    if(usermap == NULL) return;

    free(usermap->buffer);
    free(usermap);
}

p67rs_err
p67rs_usermap_create(
    p67rs_usermap_t ** usermap,
    int usermap_capacity)
{
    p67rs_usermap_t * up;

    if(usermap == NULL)
        return p67_err_einval;

    if((up = calloc(1, sizeof(*up))) == NULL)
        return p67_err_eerrno;

    if(usermap_capacity <= 0)
        usermap_capacity = P67RS_DEFAULT_USERMAP_CAPACITY;

    up->buffer_capacity = usermap_capacity;

    if((up->buffer = calloc(
                usermap_capacity, 
                sizeof(*up->buffer))) == NULL) {
        free(up);
        return p67_err_eerrno;
    }

    *usermap = up;

    return 0;
}

p67rs_err
p67rs_server_respond_with_err(
    p67_conn_t * conn, p67rs_werr err,
    const unsigned char * command,
    const unsigned char * const msg, int msgl)
{
    uint32_t serr = p67_cmn_htonl((uint32_t)err);
    unsigned char ackmsg[P67_TLV_HEADER_LENGTH+sizeof(serr)];
    char ack[P67_PDP_ACK_OFFSET + sizeof(ackmsg)];

    if(p67_tlv_add_fragment(
            ackmsg, sizeof(ackmsg), 
            command, (unsigned char *)&serr, sizeof(serr)) < 0)
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

p67rs_err
p67rs_server_respond_with_bwt(
    p67_conn_t * conn,
    const unsigned char * command,
    const unsigned char * const msg, int msgl,
    p67rs_bwt_t * bwt)
{
    uint32_t serr = p67_cmn_htonl((uint32_t)0);
    p67rs_err err;
    const int status_offset = P67_TLV_HEADER_LENGTH + sizeof(serr);
    const int bwt_offset = P67_TLV_HEADER_LENGTH + sizeof(*bwt);
    unsigned char ackmsg[status_offset + bwt_offset];
    char ack[P67_PDP_ACK_OFFSET + sizeof(ackmsg)];

    if(p67_tlv_add_fragment(
            ackmsg, status_offset, 
            command, 
            (unsigned char *)&serr, sizeof(serr)) < 0)
        return p67_err_einval;

    if(p67_tlv_add_fragment(
            ackmsg+status_offset, sizeof(ackmsg)-status_offset, 
            P67RS_SERVER_BWT_TAG, 
            (unsigned char *)bwt, sizeof(*bwt)) < 0)
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
// p67rs_server_handle_call(
//     p67_conn_t * conn, 
//     p67rs_server_t * server,
//     const unsigned char * const msg, int msgl,
//     const unsigned char * payload, int payload_len)
// {
//     /*
//         src tries to call dst
//     */

//     p67rs_err err = 0;
//     uint16_t werr = 0;
//     const p67rs_usermap_entry_t * entry;
//     const p67_addr_t * call_src_addr = p67_conn_get_addr(conn);
//     if(!call_src_addr)
//         return p67_err_einval;
//     unsigned char 
//                 val[P67_TLV_VALUE_MAX_LENGTH],
//                 key[P67_TLV_KEY_LENGTH],
//                 vlength;
//     char dst[P67RS_SERVER_MAX_CREDENTIAL_LENGTH+1];
//     p67_addr_t dst_addr;
//     const char * username = NULL;
//     int state = 0;

//     while(1) {
//         vlength = P67_TLV_VALUE_MAX_LENGTH;
//         if((err = p67_tlv_get_next_fragment(
//                     &payload, &payload_len, key, val, &vlength)) != 0) {
//             err=-err;
//             goto end;
//         }

//         switch(key[0]) {
//         case 't':
//             memcpy(dst, val, vlength);
//             dst[vlength] = 0;
//             state++;
//             break;
//         default:
//             break;
//         }

//     }

//     if(state < 1) {
//         err = p67_err_einval;
//         goto end;
//     }

//     if((entry = p67rs_usermap_lookup(server->usermap, dst)) == NULL) {
//         err = p67_err_enconn;
//         goto end;
//     }

//     if((err = p67_addr_set_sockaddr(
//                 &dst_addr, &entry->saddr, sizeof(entry->saddr))) != 0) {
//         goto end;
//     }
    
//     if((entry = p67rs_usermap_lookup(server->usermap, username)) == NULL) {
//         // right now user is allowed to call someone even if not logged in.
//         // err = p67_err_enconn;
//         // goto end;
//     }

//     unsigned char callbuf[180];
//     const int callbuf_size = 180;
//     int call_rq_ix = 0;
//     p67_async_t crt = P67_PDP_EVT_NONE;
    
//     /* add 'call' command tag */
//     if((err = p67_tlv_add_fragment(
//                 callbuf+call_rq_ix, callbuf_size-call_rq_ix,
//                 "c", "c", 1)) != 0) {
//         err=-err;
//         goto end;
//     } else {
//         call_rq_ix+=err;
//     }

//     /* 
//         if src is logged in then add username tag.
//     */
//     if(username) {
//         if((err = p67_tlv_add_fragment(
//                     callbuf+call_rq_ix, callbuf_size-call_rq_ix, 
//                     "u", 
//                     username, strlen(username)) <= 0)) {
//             err=-err;
//             goto end;
//         } else {
//             call_rq_ix+=err;
//         }
//     }

//     /*
//         add target about src address
//     */
//     if((err = p67_tlv_add_fragment(
//                 callbuf+call_rq_ix, callbuf_size-call_rq_ix,
//                 "a",
//                 (unsigned char *)&call_src_addr->sock, call_src_addr->socklen)) != 0) {
//         err=-err;
//         goto end;
//     } else {
//         call_rq_ix+=err;
//     }

//     if((err = p67_pdp_write_urg(
//                 &dst_addr, 
//                 callbuf, call_rq_ix, 
//                 2000, 
//                 &crt, 
//                 (void **)&callbuf, &callbuf_size)) != 0)
//         goto end;

//     if((err = p67_mutex_wait_for_change(&crt, 0, -1)) != 0)
//         goto end;

//     state = 0;

//     // read peer response
//     while(1) {
//         vlength = P67_TLV_VALUE_MAX_LENGTH;
//         if((err = p67_tlv_get_next_fragment(
//                     &payload, &payload_len, key, val, &vlength)) != 0) {
//             err=-err;
//             goto end;
//         }

//         switch(key[0]) {
//         case 'c':
//             if(vlength != 2) return p67_err_einval;
//             werr = p67_cmn_ntohs(val);
//             if(werr != 0) {
//                 werr = p67rs_werr_400;
//                 goto end;
//             }
//             state += 1;
//             break;
//         default:
//             break;
//         }
//     }

//     if(state != 1) {
//         err = p67_err_einval;
//         goto end;
//     }

//     // respond with dst address.

//     call_rq_ix = 0;

//     call_rq_ix += sizeof(p67_pdp_ack_hdr_t);

//     if((err = p67_tlv_add_fragment(
//                 callbuf+call_rq_ix, callbuf_size-call_rq_ix,
//                 "c", &(uint16_t){p67_cmn_htons(0)}, 2)) != 0) {
//         err=-err;
//         goto end;
//     } else {
//         call_rq_ix+=err;
//     }

//     if((err = p67_tlv_add_fragment(
//                 callbuf+call_rq_ix, callbuf_size-call_rq_ix,
//                 "a",
//                 (unsigned char *)&dst_addr.sock, dst_addr.socklen)) != 0) {
//         err=-err;
//         goto end;
//     } else {
//         call_rq_ix+=err;
//     }

//     if((err = p67_dmp_pdp_generate_ack(
//             msg, msgl, 
//             NULL, 0, 
//             callbuf, sizeof(p67_pdp_ack_hdr_t))) != 0)
//         return err;


//     if((err = p67_net_must_write_conn(conn, callbuf, call_rq_ix)) != 0) 
//         goto end;

// end:
//     if(err == 0) {
//         return p67_err_einval;
//     } else {
//         if(!werr) werr = p67rs_werr_400;
//         return p67rs_server_respond_with_err(
//                 conn, werr, P67RS_SERVER_LOGIN_TAG, msg, msgl);
//     }

// }

p67rs_err
p67rs_server_handle_login(
    p67_conn_t * conn, 
    p67rs_server_t * server,
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
            if(tlv_hdr->vlength > P67RS_SERVER_MAX_CREDENTIAL_LENGTH) {
                werr = p67rs_werr_400;
                goto end;
            }
            username = (char *)tlv_value;
            usernamel = tlv_hdr->vlength;
            state |= 1;
            break;
        case 'p':
            if(tlv_hdr->vlength > P67RS_SERVER_MAX_CREDENTIAL_LENGTH) {
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
                server->db_ctx, 
                username, usernamel, 
                password, passwordl)) != 0) {
        werr = p67rs_werr_401;
        goto end;
    }

    if((err = p67rs_usermap_add(
            server->usermap, 
            username, usernamel, 
            &remote->sock)) != 0) {
        if(err == (p67rs_err)p67_err_eaconn) {
            // p67rs_usermap_entry_t * entry;
            // if((entry = (p67rs_usermap_entry_t *)p67rs_usermap_lookup(
            //             server->usermap, username)) == NULL) {
            //     werr = p67rs_werr_500;
            //     goto end;
            // }
            // entry->saddr = remote->sock;
            err = 0;
            goto end;
        }
        werr = p67rs_werr_500;
        goto end;
    }

end:
    return p67rs_server_respond_with_err(
                conn, werr, P67RS_SERVER_LOGIN_TAG, msg, msgl);
}

p67_err
p67rs_server_cb(
    p67_conn_t * conn, 
    const char * const msg, const int msgl, 
    void * args)
{
    p67rs_server_t * server = (p67rs_server_t *)args;
    if(server == NULL)
        return p67_err_einval;
    p67rs_err err;
    const p67_dml_hdr_store_t * hdr;
    int handled = 0;

    if((hdr = p67_dml_parse_hdr((unsigned char *)msg, msgl, NULL)) == NULL)
        return p67_err_epdpf;
 
    switch(hdr->cmn.cmn_stp) {
    // case P67_DML_STP_PDP_ACK:
    //     break;
    case P67_DML_STP_PDP_URG:
    
        switch(hdr->cmn.cmn_utp) {
        case P67RS_SERVER_PATH_LOGIN:
            if((err = p67rs_server_handle_login(
                    conn, server,
                    (const unsigned char *)msg, msgl, 
                    (unsigned char *)msg+sizeof(hdr->urg), 
                    msgl-sizeof(hdr->urg))) != 0) {
                p67rs_err_print_err("handle login returned error/s: ", err);
            }
            if(err != (p67rs_err)p67_err_eagain)
                handled = 1;
            break;
        default:
            break;
        }
        
        break;
    default:
        break;
    }

    if(handled)
        return 0;
    else
        if((err = p67_dml_handle_msg(conn, msg, msgl, NULL)) != 0) {
            p67rs_err_print_err("handle dml returned error/s: ", err);
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

    p67_spinlock_lock(&sesslock);
    
    p->sessid=(sessid++);

    p67_spinlock_unlock(&sesslock);

    p->server = server;

    return p;
}

void p67rs_server_session_free(void * s)
{
    if(!s) return;
    p67rs_server_session_t * server = (p67rs_server_session_t *)s;
    free(server->username);
    free(server);
}

void
p67rs_server_setup_pass(p67_conn_pass_t * pass, p67rs_server_t * server)
{
    pass->handler = p67rs_server_cb;
    pass->gen_args = p67rs_server_session_create;
    pass->free_args = p67rs_server_session_free;
    pass->args = server;
}
