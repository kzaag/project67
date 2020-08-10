/*
    queued datagrams protocol

    datagrams are being queued in ring (jitter) buffer.
*/

#include <stdint.h>
#include <stdlib.h>
#include <strings.h>

#include "../cmn.h"
#include "../async.h"
#include "qdp.h"


char p67_qdp_hdr_align[P67_QDP_HDR_ALIGN_SIZE] = {0, 0};

/*
    try insert packet which came out of order into buffer
*/
P67_CMN_NO_PROTO_ENTER
p67_err
p67_qdp_backward_enque(
P67_CMN_NO_PROTO_EXIT
        p67_qdp_ctx_t * ctx, 
        uint32_t seq, 
        const p67_pckt_t * chunk, 
        int chunkl)
{
    int ix = ctx->q_head, f = 0;

    while(ix < ctx->q_tail) {
        // too late, already read frame with this seq
        if(ctx->q_inodes[ix].seq > seq)
            return p67_err_enconn;
        else if(ctx->q_inodes[ix].seq == seq) {
            f = 1;
            break;
        }
    }

    for(ix = ctx->q_head; ix < ctx->q_tail; ix++) {
        if(ctx->q_inodes[ix].seq == seq) {
            f = 1;
            break;
        }
    }

    // too late, already read frame with this seq
    if(!f)
        return p67_err_enconn;

    // already got this packet
    if(!ctx->q_inodes[ix].is_zero)
        return 0;

    if(!p67_spinlock_lock_once(&ctx->q_inodes[ix].state))
        // we are a little too late, 
        // reading thread already booked this frame for reading so pass
        return p67_err_enconn;

    // check if sequence number is still the same. ( after issuing lock )
    if(ctx->q_inodes[ix].seq != seq) {
        p67_spinlock_unlock(&ctx->q_inodes[ix].state);
        return p67_err_easync;
    }

    memcpy(ctx->q_chunks+(ix*ctx->q_chunk_size), chunk, chunkl);

    ctx->q_inodes[ix].is_zero = 0;
    ctx->q_inodes[ix].size = chunkl;

    p67_spinlock_unlock(&ctx->q_inodes[ix].state);

    return 0;
}

P67_CMN_NO_PROTO_ENTER
p67_err
p67_qdp_enque(
P67_CMN_NO_PROTO_EXIT
        p67_qdp_ctx_t * s, 
        uint32_t seq, 
        const p67_pckt_t * chunk, 
        size_t chunkl, 
        int is_zero)
{
    int h = s->q_head;
    int e = (s->q_tail+1)%s->q_size;
    p67_qdp_inode_t hdr;
    hdr.state = 0;
    hdr.seq = seq;
    hdr.is_zero = is_zero;
    hdr.size = chunkl;

    if(e == h)
        return p67_err_enomem;

    if(chunkl > s->q_chunk_size)
        return p67_err_einval;

    memcpy(s->q_chunks + (s->q_tail * s->q_chunk_size), chunk, chunkl);
    s->q_inodes[s->q_tail] = hdr;

    s->q_tail = e;

    return 0;
}

int
p67_qdp_space_taken(
    p67_qdp_ctx_t * s)
{
    int t = s->q_tail;
    int h = s->q_head;
    if(t == h) {
        return 0;
    } else if(t > h) {
        return (t - h)*s->q_chunk_size;
    } else {
        return (s->q_size - h + t)*s->q_chunk_size;
    }
}

p67_err
p67_qdp_deque(
P67_CMN_NO_PROTO_EXIT
    p67_qdp_ctx_t * s, p67_pckt_t * chunk, int * chunkl)
{
    int t = s->q_tail;
    p67_qdp_inode_t * iptr;

    if(t == s->q_head) return p67_err_enconn;

    iptr = &s->q_inodes[s->q_head];

    int is_zero = s->q_inodes[s->q_head].is_zero;
    p67_spinlock_lock(&iptr->state);

    if(iptr->size > *chunkl)
        return p67_err_enomem;

    *chunkl = iptr->size;
    
    memcpy(chunk, s->q_chunks + (s->q_head*s->q_chunk_size), *chunkl);

    s->q_head = (s->q_head+1)%(s->q_size);

    if(is_zero)
        return p67_err_eagain;

    return 0;
}

void
p67_qdp_free(p67_qdp_ctx_t * s) 
{
    if(s == NULL) return;
    free(s->q_inodes);
    free(s->q_chunks);
    free(s);
}

p67_err
p67_qdp_create(p67_qdp_ctx_t ** s)
{
    p67_err err = 0;

    if(s == NULL)
        return p67_err_einval;

    if((*s = calloc(sizeof(p67_qdp_ctx_t), 1)) == NULL) {
        err = p67_err_eerrno;
        goto end;
    }

    (*s)->q_tail = 0;
    (*s)->q_head = 0;
    (*s)->q_lseq = 0;

    /* max amount of frames allowed to be kept in jitter buffer */
    (*s)->q_size = 400;
    /* compressed frame size. */
    (*s)->q_chunk_size = 160;

    if(((*s)->q_inodes = calloc(
                (*s)->q_size, sizeof(p67_qdp_inode_t))) == NULL) {
        err = p67_err_eerrno;
        goto end;
    }

    if(((*s)->q_chunks = malloc(
                (*s)->q_chunk_size*(*s)->q_size)) == NULL) {
        err = p67_err_eerrno;
        goto end;
    }

    err = 0;

end:
    if(err != 0) {
        free((*s)->q_inodes);
        free((*s)->q_chunks);
        free(*s);
        *s = NULL;
    }

    return err;
}

p67_err
p67_qdp_handle_data(
    p67_addr_t * addr, const p67_pckt_t * msg, int msgl, void * args)
{
    if(!args)
        return p67_err_einval;
    p67_err err;
    uint32_t seq, pd;
    (void)addr;
    p67_qdp_ctx_t * s = (p67_qdp_ctx_t *)args;
    p67_qdp_hdr_t * h;

    if(msgl < 1)
        return 0;

    h = (p67_qdp_hdr_t *)msg;


    if(h->qdp_stp != P67_DML_STP_QDP_DAT || !p67_qdp_hdr_align_validate(h->__align))
        return 0;

    seq = ntohl(h->qdp_seq);

    //printf("%d - %d\n", seq, lseq);

    if(s->q_lseq == seq) {
        // already got this frame
        return 0;
    } else if(s->q_lseq > seq) {
        // this packet came out of order, 
        //      but still, there may be time to insert it into the queue.
        err = p67_qdp_backward_enque(s, seq, msg+sizeof(*h), msgl-sizeof(*h));
    } else { // seq > lseq
        // lost some packets on the way.
        //      but they still may come out of order later
        if((seq - s->q_lseq) > 1) {
            pd = s->q_lseq;
            p67_pckt_t empty[s->q_chunk_size];
            bzero(empty, s->q_chunk_size);
            while((++pd) < seq)
                err = p67_qdp_enque(s, pd, empty, s->q_chunk_size, 1);
            err = p67_qdp_enque(s, seq, msg+sizeof(*h), msgl-sizeof(*h), 0);
            s->q_lseq = seq;
        } else { // seq - lseq = 1
            // perfect sequence
            err = p67_qdp_enque(s, seq, msg+sizeof(*h), msgl-sizeof(*h), 0);
            s->q_lseq = seq;
        }
    }

    if(err != 0) {
        p67_err_print_err("in packet handler: ", err);
        return err;
    }
    return 0;
}
