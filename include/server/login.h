#if !defined(P67_WS_LOGIN_H)
#define P67_WS_LOGIN_H 1

/*
    server side logged in users cache
*/
#include <p67/hashcntl.h>
#include <p67/net.h>
#include <server/session.h>

#define P67_WS_DEFAULT_LOGIN_USER_CAPACITY 1009
#define P67_WS_MAX_CREDENTIAL_LENGTH 128

/*
    server logged in users.
    it is nonclustered hash index 
        {username : user_addr}
    for conn_cache
        {user_addr: ssl_connection_ctx}
*/
typedef struct p67_ws_login_user_entry {
    char * username; /* cstr */
    size_t usernamel; /* = strlen(username) */
    p67_addr_t * addr;
    char __padd[sizeof(size_t)+sizeof(p67_hashcntl_entry_t *)];
} p67_ws_login_user_entry_t;

p67_cmn_static_assert_size(p67_ws_login_user_entry_t, p67_hashcntl_entry_t);
p67_cmn_static_assert(
    pointers_must_have_the_same_size, 
    sizeof(p67_addr_t *) == sizeof(unsigned char *));

p67_err
p67_ws_login_user_add(
    p67_hashcntl_t * h, 
    const char * username, int usernamel, p67_addr_t * addr);

void
p67_ws_login_entry_entry_free(p67_hashcntl_entry_t * e);

p67_err
p67_ws_login_handle_urg(
    p67_addr_t * addr, 
    p67_ws_session_t * sess, 
    p67_pckt_t * msg, int msgl);

p67_err
p67_ws_login_cache_create(p67_hashcntl_t ** c);

#endif
