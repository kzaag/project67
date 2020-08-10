#include <stdlib.h>
#include <string.h>
#include <strings.h>

#include "err.h"
#include "audio.h"
#include "stream.h"

#error finish it

typedef struct q_inode {
    uint32_t seq;
    int      state;
    int      is_zero;
    int      size;
} q_inode_t;

struct p67_audio_stream {
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
};

struct __attribute__((packed)) p67_stream_data_hdr {
    struct p67_proto_hdr hdr;
    uint32_t seq;
};

#define P67_STREAM_HDRSZ sizeof(struct p67_stream_data_hdr)


/***** begin private prototypes *****/

p67_err
queue_backward_enque(
        p67_audio_stream_t * s, 
        uint32_t seq, 
        const char * chunk, 
        int chunkl);

p67_err
queue_enque(
        p67_audio_stream_t * s, 
        uint32_t seq, 
        const char * chunk, 
        size_t chunkl, 
        int is_zero);

int
queue_space_taken(p67_audio_stream_t * s);

p67_err
queue_deque(
        p67_audio_stream_t * s, 
        unsigned char *chunk, 
        int * chunkl);

/***** end private prototypes *****/

/*
    try insert packet which came out of order into buffer
*/
p67_err
queue_backward_enque(
        p67_audio_stream_t * s, 
        uint32_t seq, 
        const char * chunk, 
        int chunkl)
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

    if(!p67_spinlock_lock_once(&s->q_inodes[ix].state))
        // we are a little too late, reading thread already booked this frame for reading so pass
        return p67_err_enconn;

    // check if sequence number is still the same. ( after issuing lock )
    if(s->q_inodes[ix].seq != seq) {
        p67_spinlock_unlock(&s->q_inodes[ix].state);
        return p67_err_easync;
    }

    memcpy(s->q_chunks+(ix*s->q_chunk_size), chunk, chunkl);

    s->q_inodes[ix].is_zero = 0;
    s->q_inodes[ix].size = chunkl;

    p67_spinlock_unlock(&s->q_inodes[ix].state);

    return 0;
}

p67_err
queue_enque(
        p67_audio_stream_t * s, 
        uint32_t seq, 
        const char * chunk, 
        size_t chunkl, 
        int is_zero)
{
    int h = s->q_head;
    int e = (s->q_tail+1)%s->q_size;
    q_inode_t hdr;
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
queue_deque(p67_audio_stream_t * s, unsigned char *chunk, int * chunkl)
{
    int t = s->q_tail;
    q_inode_t * iptr;

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
p67_audio_stream_free(p67_audio_stream_t * s) 
{
    if(s == NULL) return;
    p67_audio_codecs_destroy(&s->encoder);
    p67_audio_codecs_destroy(&s->decoder);
    free(s->q_inodes);
    free(s->q_chunks);
    free(s);
}

p67_err
p67_audio_stream_create(p67_audio_stream_t ** s)
{
    p67_err err = 0;

    if(s == NULL)
        return p67_err_einval;

    if((*s = calloc(sizeof(p67_audio_stream_t), 1)) == NULL) {
        err = p67_err_eerrno;
        goto end;
    }
            
    p67_audio_t in = P67_AUDIO_INITIALIZER_I;
    p67_audio_t out = P67_AUDIO_INITIALIZER_O;
    p67_audio_codecs_t encoder = P67_AUDIO_CODECS_INITIALIZER_AUDIO(in);
    p67_audio_codecs_t decoder = P67_AUDIO_CODECS_INITIALIZER_AUDIO(out);

    (*s)->q_tail = 0;
    (*s)->q_head = 0;
    (*s)->q_lseq = 0;

    /* max amount of frames allowed to be kept in jitter buffer */
    (*s)->q_size = 400;
    /* compressed frame size. */
    (*s)->q_chunk_size = 160;

    if((err = p67_audio_codecs_create(&encoder)) != 0)
        goto end;

    if((err = p67_audio_codecs_create(&decoder)) != 0)
        goto end;

    if(((*s)->q_inodes = calloc((*s)->q_size, sizeof(q_inode_t))) == NULL) {
        err = p67_err_eerrno;
        goto end;
    }

    if(((*s)->q_chunks = malloc((*s)->q_chunk_size*(*s)->q_size)) == NULL) {
        err = p67_err_eerrno;
        goto end;
    }

    (*s)->encoder = encoder;
    (*s)->decoder = decoder;
    (*s)->input = in;
    (*s)->output = out;

    err = 0;

end:
    if(err != 0) {
        p67_audio_codecs_destroy(&encoder);
        p67_audio_codecs_destroy(&decoder);
        free((*s)->q_inodes);
        free((*s)->q_chunks);
        free(*s);
        *s = NULL;
    }

    return err;
}

p67_err
stream_read_callback(p67_conn_t * conn, const char * msg, int msgl, void * args)
{
    (void)conn;
    p67_err err;
    uint32_t seq, pd;
    p67_audio_stream_t * s = (p67_audio_stream_t *)args;
    struct p67_stream_data_hdr * h;

    if(msgl < 1)
        return 0;

    h = (struct p67_stream_data_hdr *)msg;

    if(h->hdr.h_val != P67_PROTO_STREAM_DATA)
        return 0;

    seq = ntohl(h->seq);

    //printf("%d - %d\n", seq, lseq);

    if(s->q_lseq == seq) {
        // already got this frame
        return 0;
    } else if(s->q_lseq > seq) {
        // this packet came out of order, 
        //      but still, there may be time to insert it into the queue.
        err = queue_backward_enque(s, seq, msg+sizeof(*h), msgl-sizeof(*h));
    } else { // seq > lseq
        // lost some packets on the way.
        //      but they still may come out of order later
        if((seq - s->q_lseq) > 1) {
            pd = s->q_lseq;
            char empty[s->q_chunk_size];
            bzero(empty, s->q_chunk_size);
            while((++pd) < seq)
                err = queue_enque(s, pd, empty, s->q_chunk_size, 1);
            err = queue_enque(s, seq, msg+sizeof(*h), msgl-sizeof(*h), 0);
            s->q_lseq = seq;
        } else { // seq - lseq = 1
            // perfect sequence
            err = queue_enque(s, seq, msg+sizeof(*h), msgl-sizeof(*h), 0);
            s->q_lseq = seq;
        }
    }

    if(err != 0) {
        p67_err_print_err("in packet handler: ", err);
        return err;
    }
    return 0;
}

/*
    accept incoming stream and play it back
*/
p67_err
p67_audio_stream_read(p67_audio_stream_t * s)
{
    p67_err err = 0;
    unsigned char compressed_frame[P67_AUDIO_MAX_CFRAME_SZ];
    int dsz = P67_AUDIO_BUFFER_SIZE(s->output);
    unsigned char decompressed_frame[dsz];
    int st;

    int interval = ((s->output.frame_size * 1e6) / s->output.rate) / 2;
    int q_min_len = 20 * s->q_chunk_size;
    int size;

    if(s->output.__hw != NULL) {
        // TODO: if hardware is already allocated, flush or drain buffer and reenter loop
        return p67_err_einval;
    } else {
        if((err = p67_audio_create_io(&s->output)) != 0)
            goto end;
    }

    /*
        wait up until stream arrives.
        temp solution
    */
    while(1) {
        st = queue_space_taken(s);
        if(st >= q_min_len) {
            break;
        }
        p67_cmn_sleep_micro(interval);
    }
    
    while(1) {
        st = queue_space_taken(s);
        if(st < q_min_len) {
            p67_cmn_sleep_micro(interval);
            continue;
        }

        size = s->q_chunk_size;

        err = queue_deque(s, compressed_frame, &size);
        if(err != 0 && err != p67_err_eagain) {
            p67_cmn_sleep_micro(interval);
            continue;
        }

        if((err = p67_audio_codecs_decode(
                &s->decoder, 
                err == p67_err_eagain ? NULL : compressed_frame, 
                size,  
                decompressed_frame)) != 0) goto end;

        if((err = p67_audio_write(
                &s->output, decompressed_frame, dsz)) != 0) goto end;
    }

end:
    return err;
}

/*
    stream audio to the remote
*/
p67_err
p67_audio_stream_write(p67_audio_stream_t * s, p67_conn_pass_t * pass)
{
    struct p67_stream_data_hdr hdr;
    hdr.hdr.h_val = P67_PROTO_STREAM_DATA;
    p67_err err = 0;
    unsigned char compressed_frame[P67_STREAM_HDRSZ+P67_AUDIO_MAX_CFRAME_SZ];
    unsigned char decompressed_frame[P67_AUDIO_BUFFER_SIZE(s->input)];
    int cb;
    // it would take around 8 years of stereo streaming with 48k sampling to overflow this variable
    // so we should be ok with using 32bits
    // proof: 
    // lseq/second = 400 (400 frames per second)
    // uint32 limit = 4294967295
    // amount of seconds to overflow = 4294967295 / 400
    register uint32_t seq = 1;

    if(s->input.__hw != NULL) {
        // if hardware is already allocated, flush or drain buffer and reenter loop
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
    return err;
}
