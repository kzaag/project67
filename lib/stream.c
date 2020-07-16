#include <stdlib.h>
#include <string.h>


#include "err.h"
#include "net.h"
#include "audio.h"


typedef struct q_inode {
    uint32_t seq;
    int      state;
    int      is_zero;
} q_inode_t;

typedef struct p67_audio_stream {
    volatile int  q_head;
    volatile int  q_tail;
    uint32_t      q_lseq;
    size_t        q_size;
    size_t        q_chunk_size;
    q_inode_t     * q_inodes; // [q_size]
    unsigned char * q_chunks; // [q_size][q_chunk_size]

    p67_audio_t input;
    p67_audio_t output;
    p67_audio_codecs_t encoder;
    p67_audio_codecs_t decoder;

    p67_conn_pass_t * pass;
} p67_audio_stream_t;

struct __attribute__((packed)) p67_stream_hdr {
    uint32_t seq;
};

#define P67_STREAM_HDRSZ sizeof(struct p67_stream_hdr)


/***** begin private prototypes *****/

p67_err
queue_backward_enque(p67_audio_stream_t * s, uint32_t seq, const char * chunk, int chunkl);

p67_err
queue_enque(p67_audio_stream_t * s, uint32_t seq, const char * chunk, size_t chunkl, int is_zero);

int
queue_space_taken(p67_audio_stream_t * s);

p67_err
queue_deque(p67_audio_stream_t * s, char *chunk, int chunkl);

p67_err
p67_audio_stream_create(p67_audio_stream_t * s);

p67_err
p67_audio_stream_start(p67_audio_stream_t * s, p67_conn_pass_t * pass);

/***** end private prototypes *****/


/*
    try insert packet which came out of order into buffer
*/
p67_err
queue_backward_enque(p67_audio_stream_t * s, uint32_t seq, const char * chunk, int chunkl)
{
    int ix = s->q_head, f = 0;

    while(ix < s->q_tail) {
        // too late, already read frame with this seq
        if(s->q_inodes[ix].seq > seq)
            return p67_err_enconn;
        else if(s->q_inodes[ix].seq == seq) {
            f = 1;
            break;
        }
    }

    for(ix = s->q_head; ix < s->q_tail; ix++) {
        if(s->q_inodes[ix].seq == seq) {
            f = 1;
            break;
        }
    }

    // too late, already read frame with this seq
    if(!f)
        return p67_err_enconn;

    // already got this packet
    if(!s->q_inodes[ix].is_zero)
        return 0;

    if(!p67_sm_update(&s->q_inodes[ix].state, &(int){0}, 1))
        return p67_err_enconn; // a wee bit too late, reading thread already booked this frame for reading

    // check if sequence number is still the same. ( after issuing lock )
    if(s->q_inodes[ix].seq != seq)
        return p67_err_easync;

    memcpy(s->q_chunks+(ix*s->q_chunk_size), chunk, chunkl);

    s->q_inodes[ix].is_zero = 0;

    if(!p67_sm_update(&s->q_inodes[ix].state, &(int){1}, 0))
        return p67_err_easync;

    return 0;
}

p67_err
queue_enque(p67_audio_stream_t * s, uint32_t seq, const char * chunk, size_t chunkl, int is_zero)
{
    int h = s->q_head;
    int e = (s->q_tail+1)%s->q_size;
    q_inode_t hdr;
    hdr.state = 0;
    hdr.seq = seq;
    hdr.is_zero = is_zero;

    if(e == h)
        return p67_err_einval;

    if(chunkl > s->q_chunk_size)
        return p67_err_einval;
    
    memcpy(&s->q_chunks + (s->q_tail * s->q_chunk_size), chunk, chunkl);
    s->q_inodes[s->q_tail] = hdr;

    s->q_tail = e;

    return 0;
}

int
queue_space_taken(p67_audio_stream_t * s)
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
queue_deque(p67_audio_stream_t * s, char *chunk, int chunkl)
{
    int t = s->q_tail;
    q_inode_t * iptr;

    if(t == s->q_head) return p67_err_einval;

    iptr = &s->q_inodes[s->q_head];

    int is_zero = s->q_inodes[s->q_head].is_zero;

    do {
        if(iptr->state != 0)
            continue;

        if(p67_sm_update(&iptr->state, &(int){0}, 1))
            break;
    } while(1);
    
    memcpy(chunk, s->q_chunks + (s->q_head*s->q_chunk_size), chunkl);

    s->q_head = (s->q_head+1)%(s->q_size);

    if(is_zero)
        return p67_err_eagain;

    return 0;
}

p67_err
p67_audio_stream_create(p67_audio_stream_t * s)
{
    p67_err err;

    p67_audio_t in = P67_AUDIO_INITIALIZER_I;
    p67_audio_t out = P67_AUDIO_INITIALIZER_O;
    p67_audio_codecs_t encoder = P67_AUDIO_CODECS_INITIALIZER_AUDIO(in);
    p67_audio_codecs_t decoder = P67_AUDIO_CODECS_INITIALIZER_AUDIO(out);

    s->q_tail = 0;
    s->q_head = 0;
    s->q_lseq = 0;

    /* max amount of frames allowed to be kept in jitter buffer */
    s->q_size = 400;
    /* compressed frame size. */
    s->q_chunk_size = 160;

    if((err = p67_audio_codecs_create(&encoder)) != 0)
        return err;

    if((err = p67_audio_codecs_create(&decoder)) != 0)
        return err;

    if((s->q_inodes = malloc(s->q_size)) == NULL) {
        p67_audio_codecs_destroy(&encoder);
        p67_audio_codecs_destroy(&decoder);
        return p67_err_eerrno;
    }

    if((s->q_chunks = malloc(s->q_chunk_size*s->q_size)) == NULL) {
        free(s->q_inodes);
        p67_audio_codecs_destroy(&encoder);
        p67_audio_codecs_destroy(&decoder);
        return p67_err_eerrno;
    }

    s->encoder = encoder;
    s->decoder = decoder;
    s->input = in;
    s->output = out;

    return 0;
}

p67_err
p67_audio_stream_run(p67_audio_stream_t * s, p67_conn_pass_t * pass)
{
    struct p67_stream_hdr hdr;
    p67_err err = 0;
    unsigned char compressed_frame[P67_STREAM_HDRSZ+P67_AUDIO_MAX_CFRAME_SZ];
    unsigned char decompressed_frame[P67_AUDIO_BUFFER_SIZE(s->input)];
    int cb;
    register int seq;

    if(s->input.__hw != NULL) {
        // TODO: resume
        return p67_err_einval;
    } else {
        if((err = p67_audio_create_io(&s->input)) != 0)
            goto end;
    }

    while(1) {
        if((err = p67_audio_read(
                &s->input, decompressed_frame, sizeof(decompressed_frame))) != 0) 
            goto end;

        cb = P67_AUDIO_MAX_CFRAME_SZ;
        
        if((err = p67_audio_codecs_encode(
                &s->encoder, decompressed_frame, compressed_frame+P67_STREAM_HDRSZ, &cb)) != 0)
           goto end;

        hdr.seq = htonl(seq++);
        memcpy(compressed_frame, &hdr, P67_STREAM_HDRSZ);

        if((err = p67_net_must_write(
                &pass->remote, compressed_frame, cb+P67_STREAM_HDRSZ)) != 0) 
            goto end;
        if((err = p67_net_must_write(
                &pass->remote, compressed_frame, cb+P67_STREAM_HDRSZ)) != 0) 
            goto end;
    }

end:
    p67_audio_free_hw(s->input);
    p67_audio_codecs_destroy(&s->encoder);
    return err;
}
