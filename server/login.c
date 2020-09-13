#include <server/login.h>

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
