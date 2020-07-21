#if !defined(P67RS_DB)
#define P67RS_DB 1

#include "err.h"

typedef struct p67rs_db_ctx p67rs_db_ctx_t;

p67rs_err
p67rs_db_ctx_create_from_dp_config(
    p67rs_db_ctx_t ** ctx, const char * config_path);

char *
p67rs_db_err_get(void);

p67_err
p67rs_db_create_user(
    p67rs_db_ctx_t * ctx, const char * username, const char * password);

void
p67rs_db_ctx_free(p67rs_db_ctx_t * ctx);

#endif