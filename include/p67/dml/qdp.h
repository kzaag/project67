#if !defined(P67_QDP_H)
#define P67_QDP_H 1

#include "../err.h"
#include "../net.h"
#include "base.h"

#include <string.h>

#define P67_QDP_HDR_ALIGN_SIZE 2

extern char p67_qdp_hdr_align[P67_QDP_HDR_ALIGN_SIZE];

#define p67_qdp_hdr_align_validate(h) \
    (memcmp(p67_qdp_hdr_align, h, P67_QDP_HDR_ALIGN_SIZE) == 0)

#define p67_qdp_hdr_align_zero(h) bzero(h, P67_QDP_HDR_ALIGN_SIZE)

typedef struct p67_qdp_hdr {
    __p67_dml_hdr_common(qdp_)
    char __align[P67_QDP_HDR_ALIGN_SIZE];
    uint32_t qdp_seq;
} p67_qdp_hdr_t;

p67_cmn_static_assert(p67_qdp_hdr_t, sizeof(p67_qdp_hdr_t) == 8);

typedef struct p67_qdp_ctx p67_qdp_ctx_t;

typedef struct p67_qdp_inode {
    uint32_t seq;
    int      state;
    int      is_zero;
    int      size;
} p67_qdp_inode_t;

struct p67_qdp_ctx {
    
    // queue indexes
    volatile int q_head;
    volatile int q_tail;
    
    // last known sequence number
    uint32_t q_lseq;

    size_t          q_size;
    size_t          q_chunk_size;
    p67_qdp_inode_t * q_inodes; // [q_size]
    p67_pckt_t      * q_chunks; // [q_size][q_chunk_size]

    p67_cmn_refcount_fields(q_)
};

p67_qdp_ctx_t *
p67_qdp_refcpy(p67_qdp_ctx_t * c);

int
p67_qdp_space_taken(p67_qdp_ctx_t * s);

p67_err
p67_qdp_deque(
    p67_qdp_ctx_t * s, p67_pckt_t * chunk, int * chunkl);

void
p67_qdp_free(p67_qdp_ctx_t * s); 

p67_err
p67_qdp_create(p67_qdp_ctx_t ** s);

p67_err
p67_qdp_handle_data(
    p67_addr_t * addr, p67_pckt_t * msg, int msgl, void * args);

#endif
