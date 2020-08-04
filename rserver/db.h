#if !defined(P67RS_DB)
#define P67RS_DB 1

#include "err.h"

#define P67RS_DB_PASS_HASH_SIZE 32
#define P67RS_DB_ID_SIZE 16

typedef struct p67rs_db_user {
    unsigned char u_id[P67RS_DB_ID_SIZE];
    char * u_name;
    char * pass_cstr;
    unsigned char u_pwd_hash[P67RS_DB_PASS_HASH_SIZE];
} p67rs_db_user_t;

typedef struct p67rs_db_user_hint {
    unsigned char * u_id;
    
    char * u_name;
    int u_name_l;

    unsigned char * u_pwd_hash;
} p67rs_db_user_hint_t;

typedef struct p67rs_db_ctx p67rs_db_ctx_t;

p67rs_err
p67rs_db_ctx_create_from_dp_config(
    p67rs_db_ctx_t ** ctx, const char * config_path);

void
p67rs_db_ctx_free(p67rs_db_ctx_t * ctx);

char *
p67rs_db_err_get(void);

p67_err
p67rs_db_hash_pass(
    const char * password, int passwordl, unsigned char * hash);

p67rs_err
p67rs_db_user_create(
    p67rs_db_ctx_t * ctx, p67rs_db_user_t * user);

p67rs_err
p67rs_db_user_delete(
    p67rs_db_ctx_t * ctx, const p67rs_db_user_hint_t * hint);

p67rs_err
p67rs_db_user_read(
    p67rs_db_ctx_t * ctx, 
    p67rs_db_user_hint_t * hint, 
    p67rs_db_user_t ** users, 
    int * usersl);

p67rs_err
p67rs_db_user_validate_pass(
    p67rs_db_ctx_t * ctx,
    char * username, int usernamel,
    unsigned char * password, int passwordl);

#endif
