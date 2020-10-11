#if !defined(P67_P2P_H)
#define P67_P2P_H 1

#include <p67/dml/pdp.h>
#include <p67/hashcntl.h>
#include <p67/sfd.h>
#include <p67/net.h>
#include <p67/audio.h>

// #include <p67/conn_ctx.h>
// #include <p67/dml.h>

typedef struct p67_p2p p67_p2p_t;

#define P67_P2P_STATE_INCOMING 1
#define P67_P2P_STATE_ESTABL   2

typedef struct p67_p2p_audio {
    p67_audio_t * i;
    p67_audio_t * o;
    p67_qdp_ctx_t * qdp;
    p67_thread_sm_t i_sm;
    p67_thread_sm_t o_sm;
} p67_p2p_audio_t;

#define p67_p2p_audio_init(audio_val) \
    { \
        (audio_val).i = NULL; \
        (audio_val).o = NULL; \
        (audio_val).qdp = NULL; \
        p67_thread_sm_init((audio_val).i_sm); \
        p67_thread_sm_init((audio_val).o_sm); \
    }

struct p67_p2p {
    p67_p2p_audio_t audio;

    //p67_conn_ctx_t conn_ctx;
    //p67_pdp_keepalive_ctx_t keepalive_ctx;
    p67_addr_t * peer_addr;
    char * peer_username;
    int peer_usernamel;

    p67_thread_sm_t connect_sm;
    p67_pdp_keepalive_ctx_t keepalive_ctx;

    p67_pdp_urg_hdr_t req;
    unsigned int should_respond;
};

p67_p2p_t *
p67_p2p_add(
    p67_addr_t * remote_addr, 
    const unsigned char * peer_username, 
    int peer_usernamel,
    p67_pdp_urg_hdr_t * urg);

p67_err
p67_p2p_cache_accept_by_name(
    p67_addr_t * local_addr, 
    p67_addr_t * server_addr,
    p67_net_cred_t * cred,
    const char * name,
    p67_async_t * conn_sig);

// O(1)
p67_p2p_t *
p67_p2p_cache_lookup(p67_addr_t * addr);

// O(N)
// index is not neccessary since N is small
p67_p2p_t *
p67_p2p_cache_find_by_name(const char * name);

p67_err
p67_p2p_callback(
    p67_addr_t * addr, 
    p67_pckt_t * msg, 
    int msgl, void * args);

p67_err 
p67_p2p_shutdown(p67_addr_t * addr);

void
p67_p2p_shutdown_cb(p67_addr_t * addr);

#endif