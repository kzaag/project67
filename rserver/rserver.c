#include "rserver.h"
#include "bwt.h"

#include <stdlib.h>
#include <string.h>

#include <p67/p67.h>

#define P67RS_SERVER_LOGIN_TAG (unsigned char *)"l\0"
#define P67RS_SERVER_BWT_TAG (unsigned char *)"bwt"

/*****/

p67rs_err
p67rs_usermap_add(
    p67rs_usermap_t * usermap,
    const char * username, const p67_sockaddr_t * saddr);

const p67rs_usermap_entry_t *
p67rs_usermap_lookup(
    p67rs_usermap_t * usermap,
    char * username);

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
    char * username)
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
    const char * username, const p67_sockaddr_t * saddr)
{
    if(usermap == NULL || usermap->buffer == NULL)
        return p67_err_einval;
    
    size_t usernamel = strlen(username);
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
    if(usermap == NULL)
        free(usermap);

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
    char ack[P67_DMP_PDP_ACK_OFFSET + sizeof(ackmsg)];

    if(p67_tlv_add_fragment(
            ackmsg, sizeof(ackmsg), 
            command, (unsigned char *)&serr, sizeof(serr)) < 0)
        return p67_err_einval;

    if((err = p67_dmp_pdp_generate_ack_from_msg(
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
    char ack[P67_DMP_PDP_ACK_OFFSET + sizeof(ackmsg)];

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

    if((err = p67_dmp_pdp_generate_ack_from_msg(
            msg, msgl, 
            ackmsg, sizeof(ackmsg), 
            ack, sizeof(ack))) != 0)
        return err;

    if((err = p67_net_must_write_conn(conn, ack, sizeof(ack))) != 0)
        return err;

    return 0;
}

p67rs_err
p67rs_server_handle_login(
    p67_conn_t * conn, 
    p67rs_server_t * server,
    const unsigned char * const msg, int msgl,
    const unsigned char * payload, int payload_len)
{
    p67rs_err err = 0;
    p67rs_bwt_t bwt;
    p67rs_werr werr = 0;
    const p67_addr_t * remote = p67_conn_get_addr(conn);
    if(!remote)
        return p67_err_einval;
    const unsigned char max_credential_length = 128;
    char 
        username[max_credential_length+1], 
        password[max_credential_length+1];
    unsigned char 
                tmp[max_credential_length],
                key[P67_TLV_KEY_LENGTH],
                cbufl;
    int state = 0;

    while(1) {

        cbufl = max_credential_length;

        if((err = p67_tlv_get_next_fragment(
                    &payload, &payload_len, key, tmp, &cbufl)) < 0) {
            err=-err;
            goto end;
        }

        switch(key[0]) {
        case 'u':
            memcpy(username, tmp, cbufl);
            username[cbufl] = 0;
            state++;
            break;
        case 'p':
            memcpy(password, tmp, cbufl);
            password[cbufl] = 0;
            state++;
            break;
        default:
            err = p67_err_etlvf;
            goto end;
        }

        if(state == 2)
            break;
    }

    if((err = p67rs_bwt_login_user(
                server->db_ctx, username, password, &bwt)) != 0) {
        werr = p67rs_werr_401;
        goto end;
    }

    if((err = p67rs_usermap_add(
            server->usermap, username, &remote->sock)) != 0) {
        if(err == (p67rs_err)p67_err_eaconn) {
            // already was added. just update address
            p67rs_usermap_entry_t * entry;
            if((entry = (p67rs_usermap_entry_t *)p67rs_usermap_lookup(
                        server->usermap, username)) == NULL) {
                werr = p67rs_werr_500;
                goto end;
            }
            entry->saddr = remote->sock;
            err = 0;
            goto end;
        }
        werr = p67rs_werr_500;
        goto end;
    }

end:
    if(err == 0) {
        return p67rs_server_respond_with_bwt(
                conn, P67RS_SERVER_LOGIN_TAG, msg, msgl, &bwt);
    } else {
        if(!werr) werr = p67rs_werr_400;
        return p67rs_server_respond_with_err(
                conn, werr, P67RS_SERVER_LOGIN_TAG, msg, msgl);
    }
}

p67rs_err
p67rs_server_handle_command(
    p67_conn_t * conn, 
    p67rs_server_t * server,
    const unsigned char * const msg, const int msgl,
    const unsigned char * payload, int payloadl)
{
    p67rs_err err;
    unsigned char command_key[P67_TLV_KEY_LENGTH], nobytes = payloadl;

    if((err = p67_tlv_get_next_fragment(
                &payload, 
                &payloadl, 
                command_key, 
                NULL, 
                &nobytes)) != 0)
        return err;

    if(nobytes != 0) {
        printf(
            "WARN in handle message, "\
                "expected path specifier to be 0 bytes long. Got: %d.\n",
            nobytes);
    }

    switch(command_key[0]) {
    case 'l':
        return p67rs_server_handle_login(
            conn, server, msg, msgl, payload, payloadl);
    case 'r':
    default:
        return p67_err_einval;
    }
}

p67_err
p67rs_server_cb(
    p67_conn_t * conn, 
    const char * const msg, const int msgl, 
    void * args)
{
    // const p67_addr_t * addr = p67_conn_get_addr(conn);
    // (void)addr;
    p67rs_server_t * server = (p67rs_server_t *)args;
    if(server == NULL)
        return p67_err_einval;
    p67rs_err err;
    const p67_dmp_hdr_store_t * hdr;

    if((hdr = p67_dmp_parse_hdr((unsigned char *)msg, msgl, NULL)) == NULL)
        return p67_err_epdpf;
 
    switch(p67_cmn_ntohs(hdr->cmn.cmn_stp)) {
    case P67_DMP_STP_PDP_ACK:
        break;
    case P67_DMP_STP_PDP_URG:
        if((err = p67rs_server_handle_command(
                    conn, server,
                    (const unsigned char *)msg, msgl, 
                    (unsigned char *)msg+sizeof(hdr->urg), 
                    msgl-sizeof(hdr->urg))) != 0)
            p67rs_err_print_err("Handle message returned error/s: ", err);
        break;
    default:
        break;
    }

    return 0;
}

void
p67rs_server_setup_pass(p67_conn_pass_t * pass, p67rs_server_t * server)
{
    pass->handler = p67rs_server_cb;
    pass->args = server;
}
