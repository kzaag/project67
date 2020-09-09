#if !defined(p67_db)
#define p67_db 1

#include "err.h"

#define P67_DB_PASS_HASH_SIZE 32
#define P67_DB_ID_SIZE 16

typedef struct p67_db_user {
    unsigned char u_id[P67_DB_ID_SIZE];
    char * u_name;
    char * pass_cstr;
    unsigned char u_pwd_hash[P67_DB_PASS_HASH_SIZE];
} p67_db_user_t;

typedef struct p67_db_user_hint {
    const unsigned char * u_id;
    
    const char * u_name;
    int u_name_l;

    const unsigned char * u_pwd_hash;
} p67_db_user_hint_t;

typedef struct p67_db_ctx p67_db_ctx_t;

p67_ws_err
p67_db_ctx_create_from_dp_config(
    p67_db_ctx_t ** ctx, const char * config_path);

void
p67_db_free(void);

void
p67_db_ctx_free(p67_db_ctx_t * ctx);

char *
p67_db_err_get(void);

p67_err
p67_db_hash_pass(
    const char * password, int passwordl, unsigned char * hash);

p67_ws_err
p67_db_user_create(
    p67_db_ctx_t * ctx, p67_db_user_t * user);

p67_ws_err
p67_db_user_delete(
    p67_db_ctx_t * ctx, const p67_db_user_hint_t * hint);

p67_ws_err
p67_db_user_read(
    p67_db_ctx_t * ctx, 
    p67_db_user_hint_t * hint, 
    p67_db_user_t ** users, 
    int * usersl);

p67_ws_err
p67_db_user_validate_pass(
    p67_db_ctx_t * ctx,
    const char * username, int usernamel,
    const unsigned char * password, int passwordl);

#endif
