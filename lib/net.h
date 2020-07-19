#if !defined NET_H
#define NET_H

#include "err.h"
#include "sfd.h"
#include "cmn.h"
#include "async.h"
#include <openssl/ssl.h>

typedef struct p67_conn p67_conn_t;
typedef struct p67_node p67_node_t;

typedef struct p67_p2p_hndl p67_p2p_hndl_t;

typedef struct p67_liitem p67_liitem_t;

typedef p67_err (* p67_conn_callback_t)(p67_conn_t * conn, const char *, int, void *); 

#define P67_CONN_PASS_INITIALIZER {0}

typedef struct p67_conn_pass {
    p67_addr_t local;
    p67_addr_t remote;
    p67_conn_callback_t handler;
    void * args;
    char * keypath;
    char * certpath;
    p67_thread_sm_t hconnect;
    p67_thread_sm_t hlisten;
} p67_conn_pass_t;

typedef __uint16_t p67_state_t;

/*
    Structure representing known ( not nessesarily connected ) peers.
    newly arrived requests are kept in the queue state until user accepts them.
*/
struct p67_node {
    p67_node_t * next;
    p67_addr_t trusted_addr;
    /* heap allocated null terminated string */
    char * trusted_pub_key;
    p67_state_t state;
};

#define P67_NODE_STATE_QUEUE 1
#define P67_NODE_STATE_ALL 1

#define P67_CONN_CNT_DEF     0 /* equal to 1 unless specified otherwise by the function */
#define P67_CONN_CNT_PASS    1
#define P67_CONN_CNT_ACT     2
#define P67_CONN_CNT_PERSIST 3

/* cache types for nodes */
#define P67_CT_NODE 1
#define P67_CT_CONN 2

void
p67_node_free(void * ptr, int also_free_ptr);

#define p67_conn_lookup(addr) \
    ((p67_conn_t *)p67_hash_lookup(P67_CT_CONN, (addr)))

#define p67_node_lookup(addr) \
    ((p67_node_t *)p67_hash_lookup(P67_CT_NODE, (addr)))

p67_liitem_t * 
p67_hash_lookup(int p67_ct, const p67_addr_t * key);

#define p67_conn_is_already_connected(addr) \
    (p67_conn_lookup((addr)) != NULL)

p67_err
p67_hash_insert(
    int p67_ct, 
    const p67_addr_t * key, 
    p67_liitem_t ** ret, 
    p67_liitem_t * prealloc)
__nonnull((2));

void
p67_conn_remove_all(void);

void
p67_net_free(void);

p67_err
p67_node_insert(
    const p67_addr_t * addr,
    const char * trusted_key,
    int strdup_key,
    int node_state,
    p67_node_t ** ret);

typedef void (* dispose_callback_t)(void * p, int);

/*
    removes ptr from hash tbl and places it in * out so user can free it.
    If callback is provided then item will be disposed and nothing will be placed in *out
*/
p67_err
p67_hash_remove(
        int p67_ct, 
        p67_addr_t * addr, 
        p67_liitem_t ** out, 
        dispose_callback_t callback);

#define p67_node_remove(addr) \
    p67_hash_remove(P67_CT_NODE, addr, NULL, p67_node_free)

p67_err
p67_net_get_peer_pk(p67_addr_t * addr, char ** pk);

p67_err
p67_net_start_read_loop
            (p67_addr_t * addr, 
            p67_conn_callback_t cb, 
            void * args)
    __nonnull((1));

p67_err
p67_net_start_read_loop_conn(p67_conn_t * conn)
    __nonnull((1));

p67_err
p67_net_connect(p67_conn_pass_t * __restrict__ pass)
    __nonnull((1));

p67_err
p67_net_nat_connect(p67_conn_pass_t * __restrict__ pass, int p67_conn_cn_t)
    __nonnull((1));

p67_err
p67_net_start_persist_connect(p67_conn_pass_t * __restrict__ pass)
    __nonnull((1));

p67_err
p67_net_must_write_conn(
        p67_conn_t * __restrict__ conn, 
        const void * __restrict__ msg, 
        int msgl)
    __nonnull((1, 2));

p67_err
p67_net_write_conn(
                p67_conn_t * __restrict__ conn, 
                const void * __restrict__ msg, 
                int * __restrict__ msgl)
    __nonnull((1, 2, 3));

p67_err
p67_net_write(
            const p67_addr_t * __restrict__ addr, 
            const void * __restrict__ msg, 
            int * __restrict__ msgl)
    __nonnull((1, 2, 3));

/*
    local address must point to ANY IP address( ::1 or 0.0.0.0) 
    Otherwise user will experience timeouts on SSL_Accept. 
*/
p67_err
p67_net_write_connect(
            p67_conn_pass_t * pass,
            const void * __restrict__ msg,
            int * msgl)
    __nonnull((1, 2, 3));

/*
    local address must point to ANY IP address( ::1 or 0.0.0.0) 
    Otherwise user will experience timeouts on SSL_Accept. 
*/
p67_err
p67_net_listen(p67_conn_pass_t * pass)
    __nonnull((1));

void
p67_net_init(void);

p67_err
p67_net_create_cert_from_key(
            const char * __restrict__ path, 
            const char * __restrict__ address)
    __nonnull((1, 2));

p67_err
p67_net_new_cert(
            const char * __restrict__ path, 
            const char * __restrict__ address)
    __nonnull((1, 2));

p67_err
p67_net_new_key(char * __restrict__ path)
    __nonnull((1));

/*
    local address must point to ANY IP address( :: or 0.0.0.0) 
    Otherwise user will experience timeouts on SSL_Accept. 
*/
p67_err
p67_net_start_listen(p67_conn_pass_t * pass)
    __nonnull((1));

p67_err
p67_net_start_connect_and_listen(p67_conn_pass_t * pass)
    __nonnull((1));

p67_err
p67_net_async_terminate(p67_conn_pass_t * pass);

const p67_addr_t *
p67_conn_get_addr(p67_conn_t * conn);

p67_err
p67_net_must_write(
            const p67_addr_t * __restrict__ addr, 
            const void * __restrict__ msg, 
            int msgl);

p67_err
p67_net_must_write_connect(
            p67_conn_pass_t * __restrict__ pass, 
            const void * __restrict__ msg, 
            int msgl);

typedef struct p67_mux_cb_arg {
    p67_conn_callback_t * cb_arr;
    void                ** cb_arr_arg;
    size_t              cb_arr_l;
    p67_async_t         lock;
} p67_mux_cb_arg_t;

p67_err
p67_net_mux_cb_arg_init(
        p67_mux_cb_arg_t * v, size_t cblen);

void
p67_net_mux_cb_arg_free(
        p67_mux_cb_arg_t * v);

p67_err
p67_net_mux_callback(
        p67_conn_t * conn, const char * msg, int msgl, void * args);

#endif