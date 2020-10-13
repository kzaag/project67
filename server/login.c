#include <string.h>

#include <p67/dml/pdp.h>
#include <p67/tlv.h>
#include <server/login.h>
#include <p67/web/tlv.h>

#define P67_WS_TLV_TAG_USERNAME 'u'
#define P67_WS_TLV_TAG_PASSWORD 'p'
#define P67_WS_TLV_TAG_REGISTER_SWITCH 'r'

p67_err
p67_ws_login_cache_create(p67_hashcntl_t ** c)
{
    assert(c);

    p67_err err;

    if(!(*c = p67_hashcntl_new(
            P67_WS_DEFAULT_LOGIN_USER_CAPACITY, 
            p67_ws_login_entry_entry_free, &err)))
        return err;
    
    return 0;
}

p67_err
p67_ws_login_user_add(
    p67_hashcntl_t * h, 
    const char * username, int usernamel, p67_addr_t * addr)
{
    if(!addr || !username || 
            usernamel < 1 || usernamel > P67_WS_MAX_CREDENTIAL_LENGTH) 
        return p67_err_einval;

    p67_ws_login_user_entry_t * entry = malloc(
        sizeof(p67_ws_login_user_entry_t) + usernamel + 1);
    if(!entry) return p67_err_eerrno;

    p67_addr_t * addrcpy = p67_addr_ref_cpy(addr);
    if(!addrcpy) return p67_err_einval;

    entry->username = (char *)entry + sizeof(p67_ws_login_user_entry_t);
    entry->usernamel = usernamel;
    entry->addr = addrcpy;

    memcpy(entry->username, username, usernamel);
    entry->username[usernamel] = 0;

    return p67_hashcntl_add(h, (p67_hashcntl_entry_t *)entry);
}

void
p67_ws_login_entry_entry_free(p67_hashcntl_entry_t * e)
{
    p67_addr_t * addr = ((p67_ws_login_user_entry_t *)e)->addr;
    p67_addr_free(addr);
    free(e);
}

p67_err
p67_ws_login_handle_urg(
    p67_addr_t * addr, 
    p67_ws_session_t * sess, 
    p67_pckt_t * msg, int msgl)
{
    const p67_tlv_header_t * tlv_hdr;
    p67_err err = 0;
    const p67_pckt_t * payload = msg + sizeof(p67_pdp_urg_hdr_t);
    int payload_len = msgl - sizeof(p67_pdp_urg_hdr_t);
    const p67_pckt_t * tlv_value;
    p67_web_status status;
    const p67_pckt_t * username = NULL, * password = NULL;
    int usernamel, passwordl, regsw = 0;

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
        case P67_WS_TLV_TAG_REGISTER_SWITCH:
            regsw = 1;
            break;
        }
    }

    if(err != p67_err_eot || !username || !password) {
        goto end;
    }

    status = p67_web_status_unauthorized;

    if(regsw) {
        p67_db_user_t user;
        user.u_name = (char *)username;
        user.pass_cstr = (char *)password;
        if((err = p67_db_user_create(sess->db, &user))) {
            p67_ws_err_print_err("login regsw: ", err);
            status = p67_web_status_bad_request;
            goto end;
        }
    }

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
                    sess->login_user_cache, username, usernamel);

        if(err) {
            status = p67_web_status_server_fault;
            goto end;
        }

        free(sess->username);
    }

    if((err = p67_ws_login_user_add(
                sess->login_user_cache, 
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
