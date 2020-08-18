#if !defined(P67_CONN_H)
#define P67_CONN_H 1

#include "err.h"
#include "sfd.h"
#include "hashcntl.h"
#include "timeout.h"

typedef struct p67_node p67_node_t;

#define P67_NODE_STATE_NODE 0
#define P67_NODE_STATE_QUEUE 1
#define P67_NODE_STATE_ALL 1

#define P67_DEFAULT_TIMEOUT_MS 200

typedef struct p67_conn_globals p67_conn_globals_t;

typedef p67_err (* p67_conn_callback_t)(
    p67_addr_t * peer, p67_pckt_t *, int, void *); 
typedef void * (* p67_conn_gen_args_cb)(void *);
typedef void (* p67_conn_free_args_cb)(void *);

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
} p67_conn_config_t;

p67_conn_config_t *
p67_conn_config_location(void);

#define p67_conn_config (*p67_conn_config_location())

p67_conn_globals_t *
p67_conn_globals_location(void);

p67_hashcntl_t *
p67_conn_node_cache(void);

p67_node_t *
p67_conn_node_insert(
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
p67_conn_get_peer_pk(p67_addr_t * addr, char ** pk);

p67_err
p67_conn_get_peer_pk(p67_addr_t * addr, char ** pk);

p67_err
p67_conn_connect(
    p67_addr_t * local, p67_addr_t * remote,
    char * certpath, char * keypath,
    p67_conn_gen_args_cb gen_args, 
    void * const args, 
    p67_conn_free_args_cb free_args,
    p67_conn_callback_t read_cb,
    p67_timeout_t * conn_timeout_ctx);

p67_err
p67_conn_listen(
    p67_addr_t * laddr,
    const char * certpath, const char * keypath,
    p67_conn_gen_args_cb gen_args, 
    void * const args, 
    p67_conn_free_args_cb free_args,
    p67_conn_callback_t cb,
    p67_async_t * thread_sm_state,
    p67_timeout_t * conn_timeout_ctx);

/*
    keep writing until whole message passes
*/
p67_err
p67_conn_write_stream(
    const p67_addr_t * addr, const p67_pckt_t * msg, int msgl);

/*
    write as much as you can
*/
p67_err
p67_conn_write(
    const p67_addr_t * addr, const void * msg, int * msgl);

/*
    must write msgl in one call or fail
*/
p67_err
p67_conn_write_once(
    const p67_addr_t * addr, const p67_pckt_t * msg, int msgl);

void
p67_conn_shutdown_all(void);

void
p67_conn_init(void);

#endif
