#if !defined NET_H
#define NET_H

#include "err.h"
#include "sfd.h"
#include "cmn.h"
#include <openssl/ssl.h>

typedef struct p67_conn p67_conn_t;
typedef struct p67_node p67_node_t;

typedef struct p67_liitem p67_liitem_t;

typedef p67_err (* p67_conn_callback_t)(p67_conn_t * conn, char *, int); 

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

p67_err
p67_node_insert(
    const p67_addr_t * addr,
    const char * trusted_key,
    int strdup_key,
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
p67_net_start_read_loop(p67_addr_t * addr, p67_conn_callback_t cb);

p67_err
p67_net_connect(
            p67_addr_t * __restrict__ local, 
            p67_addr_t * __restrict__ remote, 
            p67_conn_callback_t handler, 
            const char * __restrict__ keypath,
            const char * __restrict__ certpath)
    __nonnull((1, 2, 4, 5));

p67_err
p67_net_nat_connect(
                p67_addr_t * __restrict__ local, 
                p67_addr_t * __restrict__ remote, 
                p67_conn_callback_t handler, 
                const char * __restrict__ keypath,
                const char * __restrict__ certpath, 
                int p67_conn_cn_t)
    __nonnull((1, 2, 4, 5));

p67_err
p67_net_start_persist_connect(
                    p67_thread_t * __restrict__ thr,
                    p67_addr_t * __restrict__ local,
                    p67_addr_t * __restrict__ remote,
                    p67_conn_callback_t handler,
                    const char * __restrict__ keypath,
                    const char * __restrict__ certpath)
    __nonnull((1, 2, 3, 5, 6));

p67_err
p67_net_write(
            p67_addr_t * __restrict__ addr, 
            const char * __restrict__ msg, 
            int * __restrict__ msgl)
    __nonnull((1, 2, 3));

p67_err
p67_net_write_connect(
            const char * __restrict__ msg,
            int * msgl,
            p67_addr_t * __restrict__ local, 
            p67_addr_t * __restrict__ remote, 
            p67_conn_callback_t handler, 
            const char * __restrict__ keypath,
            const char * __restrict__ certpath)
    __nonnull((1, 2, 3, 4, 6, 7));

void
p67_conn_remove_all(void);

p67_err
p67_net_listen(
            p67_addr_t * __restrict__ local, 
            p67_conn_callback_t handler, 
            const char * __restrict__ keypath,
            const char * __restrict__ certpath)
    __nonnull((1, 3, 4));

void
p67_net_init(void);

p67_err
p67_net_create_cert_from_key(
            const char * __restrict__ path, 
            const char * __restrict__ address)
    __nonnull((1, 2));

p67_err
p67_net_new_cert(
            char * __restrict__ path, 
            char * __restrict__ address)
    __nonnull((1, 2));

p67_err
p67_net_new_key(char * __restrict__ path)
    __nonnull((1));

#endif