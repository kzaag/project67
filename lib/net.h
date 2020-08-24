#if !defined(P67_CONN_H)
#define P67_CONN_H 1

#include "err.h"
#include "sfd.h"
#include "hashcntl.h"
#include "timeout.h"

#define P67_NET_CRED_INITIALIZER {0}

typedef struct p67_net_cred {
    const char * certpath;
    const char * keypath;
} p67_net_cred_t;

void 
p67_net_cred_free(p67_net_cred_t * cred);

void
p67_net_cred_create(
    p67_net_cred_t * cred,
    const char * certpath,
    const char * keypath);

typedef p67_err (* p67_net_callback_t)(
    p67_addr_t * peer, p67_pckt_t *, int, void *); 
typedef void * (* p67_net_gen_args_cb)(void *);
typedef void (* p67_net_free_args_cb)(void *);

typedef struct p67_net_cb_ctx {
    p67_net_callback_t cb;
    p67_net_gen_args_cb gen_args;
    p67_net_free_args_cb free_args;
    void * args;
} p67_net_cb_ctx_t;

#define P67_NET_CB_CTX_INITIALIZER {0}

typedef struct p67_node p67_node_t;

#define P67_NODE_STATE_NODE 0
#define P67_NODE_STATE_QUEUE 1
#define P67_NODE_STATE_ALL 1

#define P67_DEFAULT_TIMEOUT_MS 200

typedef struct p67_net_globals p67_conn_globals_t;

typedef uint16_t p67_node_state_t;

/*
    Structure representing known ( not nessesarily connected ) peers.
    newly arrived requests are kept in the queue state until user accepts them.
*/
struct p67_node {
    p67_addr_t * trusted_addr;
    /* heap allocated null terminated string */
    char * trusted_pub_key;
    p67_node_state_t state;
    unsigned int heap_alloc : 1;
};

#define P67_CONN_AUTH_DONT_TRUST_UNKOWN   1
#define P67_CONN_AUTH_TRUST_UNKOWN 2
#define P67_CONN_AUTH_LIMIT_TRUST_UNKNOWN 3

typedef struct p67_conn_config {
    int conn_auth;
    p67_cmn_epoch_t timeout_duration_ms;
} p67_net_config_t;

p67_net_config_t *
p67_net_config_location(void);

#define p67_conn_config (*p67_conn_config_location())

p67_conn_globals_t *
p67_net_globals_location(void);

p67_hashcntl_t *
p67_node_cache(void);

p67_node_t *
p67_node_insert(
    p67_addr_t * addr,
    const char * trusted_key,
    int trusted_key_l,
    int node_state);

p67_hashcntl_t *
p67_conn_cache(void);

p67_err
p67_conn_shutdown(p67_addr_t * addr);

p67_node_t *
p67_node_lookup(p67_addr_t * addr);

p67_err
p67_net_get_peer_pk(p67_addr_t * addr, char ** pk);

p67_err
p67_net_get_peer_pk(p67_addr_t * addr, char ** pk);

p67_err
p67_net_connect(
    p67_addr_t * local, p67_addr_t * remote,
    p67_net_cred_t cred,
    p67_net_cb_ctx_t cb_ctx,
    p67_timeout_t * conn_timeout_ctx);

p67_err
p67_net_listen(
    p67_thread_sm_t * thread_ctx,
    p67_addr_t * local_addr,
    p67_net_cred_t cred,
    p67_net_cb_ctx_t cb_ctx,
    p67_timeout_t * conn_timeout_ctx);

/*
    keep writing until whole message passes
*/
p67_err
p67_net_write_stream(
    const p67_addr_t * addr, const p67_pckt_t * msg, int msgl);

/*
    write as much as you can
*/
p67_err
p67_net_write(
    const p67_addr_t * addr, const void * msg, int * msgl);

/*
    must write msgl in one call or fail
*/
p67_err
p67_net_write_msg(
    const p67_addr_t * addr, const p67_pckt_t * msg, int msgl);

void
p67_conn_shutdown_all(void);

void
p67_net_init(void);

typedef struct p67_net_listen_ctx {
    p67_thread_sm_t thread_ctx;
    p67_addr_t * local_addr;
    p67_net_cred_t cred;
    p67_net_cb_ctx_t cbctx;
    p67_timeout_t * conn_timeout_ctx;
} p67_net_listen_ctx_t;

#define p67_net_listen_ctx_free(ctx) \
    { \
        p67_thread_sm_terminate(&(ctx)->thread_ctx, 500); \
        p67_timeout_free((ctx)->conn_timeout_ctx); \
        p67_addr_free((ctx)->local_addr); \
    }

#define P67_NET_LISTEN_CTX_INITIALIZER \
    { \
        .thread_ctx = P67_THREAD_SM_INITIALIZER, \
        .local_addr = NULL, \
        .cred = {0}, \
        .cbctx = {0}, \
        .conn_timeout_ctx = NULL \
    }

p67_err
p67_net_start_listen(p67_net_listen_ctx_t * ctx);

#define P67_NET_CONNECT_SIG_UNSPEC    0
#define P67_NET_CONNECT_SIG_CONNECTED 1

typedef struct p67_net_connect_ctx {
    p67_thread_sm_t thread_ctx;
    p67_async_t * sig;
    p67_addr_t * local_addr;
    p67_addr_t * remote_addr;
    p67_net_cred_t cred;
    p67_net_cb_ctx_t cb_ctx;
    p67_timeout_t * conn_timeout_ctx;
} p67_net_connect_ctx_t;

#define p67_net_connect_ctx_free(ctx) \
    { \
        p67_thread_sm_terminate(&(ctx)->thread_ctx, 500); \
        p67_timeout_free((ctx)->conn_timeout_ctx); \
        p67_addr_free((ctx)->local_addr); \
        p67_addr_free((ctx)->remote_addr); \
    }

#define P67_NET_CONNECT_CTX_INITIALIZER \
    { \
        .thread_ctx = P67_THREAD_SM_INITIALIZER, \
        .sig = P67_NET_CONNECT_SIG_UNSPEC, \
        .local_addr = NULL, \
        .remote_addr = NULL, \
        .cred = {0}, \
        .cb_ctx = {0}, \
        .conn_timeout_ctx = NULL \
    }

p67_err
p67_net_start_connect(p67_net_connect_ctx_t * ctx);

#endif
