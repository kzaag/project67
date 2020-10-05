#if !defined(P67_CONN_H)
#define P67_CONN_H 1

#include "err.h"
#include "sfd.h"
#include "hashcntl.h"
#include "timeout.h"

#define P67_NET_CRED_INITIALIZER {0}

typedef struct p67_net_cred p67_net_cred_t;

p67_net_cred_t *
p67_net_cred_create(const char * keypath, const char * certpath);

void
p67_net_cred_free(p67_net_cred_t * cred);

p67_net_cred_t *
p67_net_cred_ref_cpy(p67_net_cred_t * cred);

typedef p67_err (* p67_net_callback_t)(
    p67_addr_t * peer, p67_pckt_t *, int, void *); 
typedef void * (* p67_net_gen_args_cb)(void *);
typedef void (* p67_net_free_args_cb)(void *);

typedef void (* p67_net_shutdown_cb)(p67_addr_t *);

typedef struct p67_net_cb_ctx {
    p67_net_callback_t cb;
    p67_net_gen_args_cb gen_args;
    p67_net_free_args_cb free_args;
    void * args;
    p67_net_shutdown_cb on_shutdown;
} p67_net_cb_ctx_t;

#define p67_net_cb_ctx_initializer(__cb) \
    { .cb = __cb, .gen_args = NULL, .free_args = NULL, .args = NULL }

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

#define P67_NET_AUTH_LIMIT_TRUST_UNKNOWN   1
#define P67_NET_AUTH_TRUST_UNKOWN 2
#define P67_NET_AUTH_DONT_TRUST_UNKOWN 3

#define P67_NET_DEF_TIMEOUT_DURATION_MS (10*1000)

#define P67_NET_DEF_SHUTDOWN_AFTER_INACTIVE 1

typedef struct p67_net_config {
    /*
        type of of authorization used during validating PK / nodes
    */
    int conn_auth_type;
    /*
        on callback error how long peer should be timeouted.
        for this value to be used conn_timeout_ctx must be provided.
        defaults to P67_NET_DEF_TIMEOUT_DURATION_MS.
        if no conn_timeout_ctx is provided then peers will be timeouted indefinetely.
    */
    p67_cmn_epoch_t timeout_duration_ms;
    
    unsigned long 
        /*
            should peer connection be closed afer inactive?
            defaults to P67_NET_DEF_SHUTDOWN_AFTER_INACTIVE
        */
        shutdown_after_inactive : 1;
} p67_net_config_t;

p67_net_config_t *
p67_net_config_location(void);

#define p67_net_config (*p67_net_config_location())

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
p67_net_shutdown(p67_addr_t * addr);

p67_node_t *
p67_node_lookup(p67_addr_t * addr);

p67_err
p67_net_get_peer_pk(p67_addr_t * addr, char ** pk);

p67_err
p67_net_get_peer_pk(p67_addr_t * addr, char ** pk);

p67_err
p67_net_connect(
    p67_addr_t * local, p67_addr_t * remote,
    p67_net_cred_t * cred,
    p67_net_cb_ctx_t cb_ctx,
    p67_timeout_t * conn_timeout_ctx);

p67_err
p67_net_listen(
    p67_thread_sm_t * thread_ctx,
    p67_addr_t * local_addr,
    p67_net_cred_t * cred,
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

#define P67_NET_LISTEN_SAFE_EXIT_TIME_MS (P67_DEFAULT_TIMEOUT_MS + 50)

#define p67_net_listen_terminate(tsm) \
    p67_thread_sm_terminate(tsm, P67_NET_LISTEN_SAFE_EXIT_TIME_MS)

/*
    if provided tsm or cb_ctx.args cannot be freed before loop exists.
    the rest of fields can be freed instantly after this function returns.
*/
p67_err
p67_net_start_listen(
    p67_thread_sm_t * tsm,

    p67_addr_t * local_addr,
    p67_net_cred_t * cred,
    p67_net_cb_ctx_t cb_ctx,
    p67_timeout_t * conn_timeout_ctx);

#define P67_NET_CONNECT_SIG_UNSPEC    0
#define P67_NET_CONNECT_SIG_CONNECTED 1

#define p67_net_connect_sig_wait_for_connect(sig) \
    p67_mutex_wait_for_change(&(sig), P67_NET_CONNECT_SIG_UNSPEC, -1);

#define P67_NET_CONNECT_SAFE_EXIT_TIME_MS (P67_DEFAULT_TIMEOUT_MS + 50)

#define p67_net_connect_terminate(tsm) \
    p67_thread_sm_terminate(tsm, P67_NET_CONNECT_SAFE_EXIT_TIME_MS)

/*
    if provided tsm or sig or cb_ctx.args cannot be freed before loop exists.
    the rest of fields can be freed instantly after this function returns.
*/
p67_err
p67_net_start_connect(
    p67_thread_sm_t * tsm,
    p67_async_t * sig,

    p67_addr_t * local_addr,
    p67_addr_t * remote_addr,
    p67_net_cred_t * cred,
    p67_net_cb_ctx_t cb_ctx,
    p67_timeout_t * conn_timeout_ctx);

// p67_err
// p67_net_start_connect_slim(
//     p67_thread_sm_t * tsm,
//     p67_async_t * sig,
//     p67_addr_t * local_addr,
//     p67_addr_t * remote_addr,
//     p67_net_cred_t * cred,
//     p67_net_cb_ctx_t cb_ctx,
//     p67_timeout_t * conn_timeout_ctx,
//     int timeout_ms);

#endif
