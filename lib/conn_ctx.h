#if !defined(P67_CONN_CTX_H)
#define P67_CONN_CTX_H 1

#include "sfd.h"
#include "conn.h"
#include "dml.h"
#include "buffer.h"

struct p67_conn_ctx {

    p67_pdp_keepalive_ctx_t keepalive_ctx;

    p67_timeout_t * conn_timeout_ctx;

    p67_addr_t * local_addr;
    p67_addr_t * remote_addr;

    p67_conn_gen_args_cb gen_args;
    p67_conn_free_args_cb free_args;
    void * args;
    p67_conn_callback_t cb;

    char * certpath;
    char * keypath;

    p67_thread_sm_t listen_tsm;
    p67_thread_sm_t connect_tsm;

};

#define p67_conn_ctx_set_cb_with_args(ctx, _cb, gen, _free, _args) \
    { \
        (ctx)->cb = _cb; \
        (ctx)->gen_args = gen; \
        (ctx)->free_args = _free; \
        (ctx)->args = _args; \
    }

#define p67_conn_ctx_set_addr(ctx, local, remote) \
    { \
        (ctx)->local_addr = local; \
        (ctx)->remote_addr = remote; \
        (ctx)->keepalive_ctx.addr = (ctx)->remote_addr; \
    }

#define p67_conn_ctx_create_timeout_ctx(ctx) \
    { \
        (ctx)->conn_timeout_ctx = p67_timeout_create(0, NULL); \
    }

#define p67_conn_ctx_start_keepalive_loop(ctx) \
    { \
        p67_pdp_start_keepalive_loop(&(ctx)->keepalive_ctx); \
    }

#define P67_CONN_CNT_DEF P67_CONN_CNT_PASS 
#define P67_CONN_CNT_PASS 1
#define P67_CONN_CNT_ACT 2
#define P67_CONN_CNT_PERSIST 3

#define P67_CONN_CTX_INITIALIZER {0}

typedef struct p67_conn_ctx p67_conn_ctx_t;

p67_err
p67_conn_ctx_start_listen(p67_conn_ctx_t * ctx);

p67_err
p67_conn_ctx_connect(p67_conn_ctx_t * ctx);

p67_err
p67_conn_ctx_nat_connect(
    p67_conn_ctx_t * ctx, int p67_conn_cn_t);

p67_err
p67_conn_ctx_start_connect(p67_conn_ctx_t * ctx);

void
p67_conn_ctx_free_fields(p67_conn_ctx_t * ctx);

p67_err
p67_conn_ctx_set_credentials(
    p67_conn_ctx_t * ctx, 
    const char * certpath,
    const char * keypath);

p67_err
p67_conn_ctx_start_connect_and_listen(p67_conn_ctx_t * ctx);


#endif
