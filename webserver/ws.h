#if !defined(P67_WC_H)
#define P67_WC_H

#include <p67/hashcntl.h>
#include <p67/net.h>
#include "db.h"

/*
    main webserver context
*/
typedef struct p67_ws_ctx {
    p67_hashcntl_t * user_nchix;
} p67_ws_ctx_t;

p67_net_cb_ctx_t
p67_ws_get_cb_ctx(p67_ws_ctx_t * server);

p67_err
p67_ws_user_nchix_create(p67_hashcntl_t ** c, size_t capacity);

#endif
