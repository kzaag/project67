#if !defined(P67_P2P_H)
#define P67_P2P_H 1

#include <p67/hashcntl.h>
#include <p67/sfd.h>
#include <p67/net.h>

// #include <p67/conn_ctx.h>
// #include <p67/dml.h>

typedef struct p67_p2p_ctx p67_p2p_ctx_t;

void
p67_p2p_cache_free(void);

p67_p2p_ctx_t *
p67_p2p_cache_add(
    p67_addr_t * remote_addr, 
    const unsigned char * peer_username, 
    int peer_usernamel);

void
p67_p2p_cache_entry_free(p67_hashcntl_entry_t * e);

p67_err
p67_p2p_cache_accept_by_name(
    p67_addr_t * local_addr, 
    p67_net_cred_t * cred,
    p67_net_cb_ctx_t cb_ctx,
    const char * name);

#endif