#if !defined(P67_WC_H)
#define P67_WC_H

#include <p67/hashcntl.h>
#include <p67/conn_ctx.h>
#include "db.h"

/*
    main webserver context
*/
typedef struct p67_ws_ctx {
    p67_hashcntl_t * user_nchix;
    /* 
        apparently each client need his own connection object 
        since libq connection is not multithreaded...
    */
    //p67_db_ctx_t * db;
} p67_ws_ctx_t;

void
p67_ws_setup_conn_ctx(p67_conn_ctx_t * conn, p67_ws_ctx_t * server);

p67_err
p67_ws_user_nchix_create(p67_hashcntl_t ** c, size_t capacity);

#endif
