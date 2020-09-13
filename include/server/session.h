#if !defined(P67_SESSION_H)
#define P67_SESSION_H 1

#include <p67/hashcntl.h>
#include <p67/net.h>
#include "db.h"

typedef struct p67_ws_session {

    p67_db_ctx_t * db;

    p67_hashcntl_t * login_user_cache;
    unsigned char * username;

    int usernamel;
    
} p67_ws_session_t;

void *
p67_ws_session_create_arg_fn(void * args);

void 
p67_ws_session_free_arg_fn(void * arg);

#endif