
#include <server/session.h>

void *
p67_ws_session_create_arg_fn(void * args)
{
    if(!args) return NULL;

    p67_ws_err err;
    p67_hashcntl_t * login_user_cache = (p67_hashcntl_t *)args;
    p67_ws_session_t * p = calloc(1, sizeof(p67_ws_session_t));
    
    if(p == NULL) {
        p67_err_print_err("Couldnt create client session: ", p67_err_eerrno);
        return NULL;
    }
    
    if((err = p67_db_ctx_create_from_dp_config(&p->db, NULL)) != 0) {
        free(p);
        p67_ws_err_print_err("Couldnt create db connection for client: ", err);
        return NULL;
    }

    p->login_user_cache = p67_hashcntl_refcpy(login_user_cache);

    return p;
}

void 
p67_ws_session_free_arg_fn(void * arg)
{
    if(!arg) return;
    p67_ws_session_t * sess = (p67_ws_session_t *)arg;

    p67_db_ctx_free(sess->db);
    if(sess->username) {
        p67_hashcntl_remove_and_free(
            sess->login_user_cache, 
            sess->username, sess->usernamel);
        free(sess->username);
    }
    p67_hashcntl_free(sess->login_user_cache);
    free(sess);
}
