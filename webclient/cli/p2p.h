#if !defined(P67_P2P_H)
#define P67_P2P_H 1

#include <p67/conn_ctx.h>
#include <p67/dml.h>

typedef struct p67_p2p_ctx p67_p2p_ctx_t;

struct p67_p2p_ctx {
    p67_conn_ctx_t conn_ctx;
    p67_pdp_keepalive_ctx_t keepalive_ctx;
    int state;
};

p67_hashcntl_t ** 
p2p_cache_location(void);

#define p2p_cache (*p2p_cache_location())

p67_p2p_ctx_t *
p67_p2p_cache_add(p67_conn_ctx_t * ctx);

p67_p2p_ctx_t *
p67_p2p_lookup(p67_addr_t * addr);

p67_err
p67_p2p_start_connect(p67_p2p_ctx_t * ctx);

#endif