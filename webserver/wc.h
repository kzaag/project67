#if !defined(P67_WC_H)
#define P67_WC_H

#include <p67/hashcntl.h>
#include "db.h"

#define P67_WS_DEFAULT_USER_NCHIX_CAPACITY 1009

/*
    main webserver context
*/
typedef struct p67_ws_ctx {
    p67_hashcntl_t * user_nchix;
    p67_db_ctx_t * db;
} p67_ws_ctx_t;


#endif
