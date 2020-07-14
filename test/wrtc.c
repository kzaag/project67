#include <p67/p67.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <opus/opus.h>
#include <rnnoise.h>
#include <errno.h>

#include "wav.h"

const int OPUS_INT_SIZE=2;
const int FRAME_SIZE=120;
const int MAX_FRAME_SIZE=1276;
const int CHANNELS=2;
#define CFRAME_SIZE 160
const unsigned int SAMPLING=48000;
const unsigned int SLOW_SAMPLING=SAMPLING-10;
const unsigned int FAST_SAMPLING=SAMPLING+10;
const int FRAME_LENGTH_MICRO = FRAME_SIZE * 1e6 / SAMPLING;
/* compressed frames of total length = 1 second */
#define QUEUE_SIZE 64000 //(1e6/FRAME_LENGTH_MICRO)*CFRAME_SIZE;
/* total amount of frames  */
#define QUEUE_IX_SIZE 400

static volatile int head = 0;
static volatile int tail = 0;

// it would take around 8 years of stereo streaming with 48k sampling to overflow this variable
// so we should be ok with using 32bits
// proof: 
// lseq/second = 400 (400 frames per second)
// uint32 limit = 4294967295
// amount of seconds to overflow = 4294967295 / 400
static uint32_t lseq;

struct queue_inode {
    uint32_t seq;
    int state;
    /* is this empty buffer compensating for packet loss? */
    int is_zero;
    /* one could add here data chunk length if frames can have variable length */
} queue_inodes[QUEUE_IX_SIZE];

char queue_chunks[QUEUE_IX_SIZE][CFRAME_SIZE];

/* delay in bytes = amount of frames * frame size = amount of frames * 2.5milisecond*/
const int QUEUE_PREFFERED_LENGTH_MIN = 20*CFRAME_SIZE;
/* max delay in bytes */
const int QUEUE_PREFFERED_LENGTH_MAX = 50*CFRAME_SIZE;

const int INITIAL_INTERVAL=FRAME_LENGTH_MICRO-1000;

struct __attribute__((packed)) p67_wrtc_hdr {
    uint32_t seq;
};

#define TC_YELLOW "\033[33m"
#define TC_GREEN "\033[32m"
#define TC_DEFAULT "\033[0m"

#define T_HIDE_CURSOR() printf("\e[?25l")
#define T_SHOW_CURSOR() printf("\e[?25h")

#define T_CLEAN_RET "\e[2K"

char empty[CFRAME_SIZE] = {0};

uint32_t
queue_last_seq()
{
    if(head == tail)    
        return 0;
    return queue_inodes[tail-1].seq;
}

/*
    try insert packet which came out of order into buffer
*/
p67_err
queue_backward_enque(uint32_t seq, const char * chunk, int chunkl)
{
    int ix = head, f = 0;

    while(ix < tail) {
        // too late, already read frame with this seq
        if(queue_inodes[ix].seq > seq)
            return p67_err_enconn;
        else if(queue_inodes[ix].seq == seq) {
            f = 1;
            break;
        }
    }

    for(ix = head; ix < tail; ix++) {
        if(queue_inodes[ix].seq == seq) {
            f = 1;
            break;
        }
    }

    // too late, already read frame with this seq
    if(!f)
        return p67_err_enconn;

    // already got this packet
    if(!queue_inodes[ix].is_zero)
        return 0;

    if(!p67_sm_update(&queue_inodes[ix].state, &(int){0}, 1))
        return p67_err_enconn; // a wee bit too late, reading thread already booked this frame for reading

    // check if sequence number is still the same. ( after issuing lock )
    if(queue_inodes[ix].seq != seq)
        return p67_err_easync;

    memcpy(queue_chunks[ix], chunk, chunkl);

    queue_inodes[ix].is_zero = 0;

    if(!p67_sm_update(&queue_inodes[ix].state, &(int){1}, 0))
        return p67_err_easync;

    return 0;
}

p67_err
queue_enque(uint32_t seq, const char * chunk, int chunkl, int is_zero)
{
    int h = head;
    int e = (tail+1)%QUEUE_IX_SIZE;
    struct queue_inode hdr;
    hdr.state = 0;
    hdr.seq = seq;
    hdr.is_zero = is_zero;

    if(e == h)
        return p67_err_einval;
    
    memcpy(&queue_chunks[tail], chunk, chunkl);
    queue_inodes[tail] = hdr;

    tail = e;

    return 0;
}

int
queue_space_taken()
{
    int t = tail;
    int h = head;
    if(t == h) {
        return 0;
    } else if(t > h) {
        return (t - h)*CFRAME_SIZE;
    } else {
        return (QUEUE_IX_SIZE - h + t)*CFRAME_SIZE;
    }
}

p67_err
queue_dequeue(char *chunk, int chunkl)
{
    int t = tail;
    struct queue_inode * iptr;

    if(t == head) return p67_err_einval;

    iptr = (struct queue_inode *)&queue_inodes[head];

    do {
        if(iptr->state != 0)
            continue;

        if(p67_sm_update(&iptr->state, &(int){0}, 1))
            break;
    } while(1);

    memcpy(chunk, queue_chunks[head], chunkl);

    head = (head+1)%QUEUE_IX_SIZE;

    return 0;
}

p67_err
receiver_callback(p67_conn_t * conn, const char * msg, int msgl, void * args)
{
    p67_err err;
    uint32_t seq, pd;
    struct p67_wrtc_hdr * h;

    if((unsigned long)msgl < (CFRAME_SIZE + sizeof(*h)))
        return 0;        

    h = (struct p67_wrtc_hdr *)msg;
    seq = ntohl(h->seq);

    //printf("%d - %d\n", seq, lseq);

    if(lseq == seq) {
        // already got this frame
        return 0;
    } else if(lseq > seq) {
        // this packet came out of order, 
        //      but still, there may be time to insert it into the queue.
        err = queue_backward_enque(seq, msg+sizeof(*h), msgl-sizeof(*h));
    } else { // seq > lseq
        // lost some packets on the way.
        //      but they still may come out of order later
        if((seq - lseq) > 1) {
            pd = lseq;
            while((++pd) < seq)
                err = queue_enque(pd, empty, CFRAME_SIZE, 1);
            err = queue_enque(seq, msg+sizeof(*h), msgl-sizeof(*h), 0);
            lseq = seq;
        } else { // seq - lseq = 1
            // perfect sequence
            err = queue_enque(seq, msg+sizeof(*h), msgl-sizeof(*h), 0);
            lseq = seq;
        }
    }

    if(err != 0) {
        p67_err_print_err("in packet handler: ", err);
        return err;
    }
    return 0;
}

static volatile int interval = 0;

static volatile unsigned long __wrote = 0;

void *
stream_kbs_print_loop(void * args)
{
    while(1) {
        printf("streaming %03lu kbytes / second.\r", __wrote  / 1024);\
        fflush(stdout);
        __wrote = 0;
        p67_cmn_sleep_s(1);
    }
}

void * 
stream_control_loop(void * args)
{
    int qs, factor = 10;
    p67_pcm_t * out = (p67_pcm_t *)args;
    //int ls = 0;

    while(1) {
        qs = queue_space_taken();
        if(qs > QUEUE_PREFFERED_LENGTH_MAX) {
            if(out->sampling != FAST_SAMPLING) {
                printf("speed up\n");
                out->sampling = FAST_SAMPLING; 
                p67_pcm_update(out);
            }
        } else if(qs > QUEUE_PREFFERED_LENGTH_MIN) {
            if(out->sampling != SAMPLING) {
                out->sampling = SAMPLING;
                p67_pcm_update(out);
            }
        }
        // if(qs != 0) {
        //     if(qs < QUEUE_PREFFERED_LENGTH_MIN) {
        //         if(interval+factor < FRAME_LENGTH_MICRO) {
        //             interval+=factor;
        //         }
        //     } else if(qs > QUEUE_PREFFERED_LENGTH_MAX) {
        //         interval-=factor;
        //     }
        // }
        // if(qs > QUEUE_PREFFERED_LENGTH_MAX) {
        //     if(out->sampling != FAST_SAMPLING) {
        //         printf("speed up\n");
        //         out->sampling = FAST_SAMPLING; 
        //         p67_pcm_update(out);
        //     }
        // } else if(qs < QUEUE_PREFFERED_LENGTH_MIN) {
        //     if(out->sampling != SLOW_SAMPLING) {
        //         printf("slow down\n");
        //         out->sampling = SLOW_SAMPLING; 
        //         p67_pcm_update(out);
        //     }
        // } else {
        //     if(out->sampling != SAMPLING) {
        //         printf("recover\n");
        //         out->sampling = SAMPLING; 
        //         p67_pcm_update(out);
        //     }
        // }
        
        printf(
           "buffer_size=%07d bytes. interval=%04d microsec sampling=%-5d\n", 
           qs, interval, out->sampling);


        // printf("%u\n", lseq - ls);
        // ls = lseq;

        p67_cmn_sleep_ms(100);
    }
}

p67_err
recv_stream(p67_conn_pass_t * pass)
{
    opus_int16 output_frame[FRAME_SIZE*CHANNELS];
    unsigned char compressed_frame[MAX_FRAME_SIZE];
    unsigned char decompressed_frame[FRAME_SIZE*OPUS_INT_SIZE*CHANNELS];
    p67_pcm_t o = P67_PCM_INTIIALIZER_OUT;
    //o.name ="hw:0,9";
    o.frame_size = FRAME_SIZE;
    o.bits_per_sample = 16;
    o.channels = CHANNELS;
    o.sampling = SAMPLING;
    p67_err err = 0;
    int opus_err, ix, buffering = 0;
    OpusDecoder * dec;
    p67_thread_t scl;
    int st;

    pass->handler = receiver_callback;

    dec = opus_decoder_create(o.sampling, o.channels, &opus_err);
    if(opus_err != 0) goto end;
    
    if((err = p67_net_start_connect_and_listen(pass)) != 0)
        goto end;

    if((err = p67_pcm_create_io(&o)) != 0) goto end;

    p67_pcm_printf(o);

    interval = INITIAL_INTERVAL;

    if((err = p67_cmn_thread_create(&scl, stream_control_loop, &o)) != 0)
        goto end;

    while(queue_space_taken() < QUEUE_PREFFERED_LENGTH_MAX) {
        p67_cmn_sleep_micro(50);
    }

    while(1) {
        p67_cmn_sleep_micro(interval);
        st = queue_space_taken();
        if(st < QUEUE_PREFFERED_LENGTH_MIN && !buffering)
            continue;
        // if(st > QUEUE_PREFFERED_LENGTH_MAX) {
        //     if(o.sampling != FAST_SAMPLING) {
        //         printf("speed up\n");
        //         o.sampling = FAST_SAMPLING;
        //         p67_pcm_update(&o);
        //     }
        // } else if(st < QUEUE_PREFFERED_LENGTH_MIN) {
        //     if(o.sampling != SLOW_SAMPLING) {
        //         printf("slow down\n");
        //         o.sampling = SLOW_SAMPLING;
        //         p67_pcm_update(&o);
        //     }
        // } else {
        //     if(o.sampling != SAMPLING) {
        //         printf("restore\n");
        //         o.sampling = SAMPLING;
        //         p67_pcm_update(&o);
        //     }
        // }
        err = queue_dequeue(compressed_frame, CFRAME_SIZE);
        if(err != 0) {
            // if((opus_error = opus_decode(dec, NULL, 0, bb, r, 0)) != 0)
            //     goto end;
            continue;
        } else {
            if(memcmp(compressed_frame, empty, CFRAME_SIZE) == 0) {
                if((opus_err = opus_decode(
                    dec, NULL, 0, output_frame, FRAME_SIZE, 1)) < 0)
                goto end;
            } else {
                if((opus_err = opus_decode(
                    dec, compressed_frame, CFRAME_SIZE, output_frame, FRAME_SIZE, 0)) < 0)
                goto end;
            }
        }

        for(ix=0;ix<FRAME_SIZE*CHANNELS;ix++) {
            decompressed_frame[OPUS_INT_SIZE*ix]=output_frame[ix]&0xFF;
            decompressed_frame[OPUS_INT_SIZE*ix+1]=(output_frame[ix]>>8)&0xFF;
        }

        err = p67_pcm_write(&o, decompressed_frame, &(size_t){FRAME_SIZE});
        if(err == p67_err_epipe) {
            // buffering
            if(o.sampling != SLOW_SAMPLING) {
                o.sampling = SLOW_SAMPLING;
                p67_pcm_update(&o);
            }
            buffering = 1;
            printf("slow down\n");
        } else if(buffering) {
            if(o.sampling != SAMPLING) {
                o.sampling = SAMPLING;
                p67_pcm_update(&o);
            }
            buffering = 0;
            printf("recover\n");
        }
    }

end:
    p67_pcm_free(&o);
    if(opus_err != 0) fprintf(stderr, "%s\n", opus_strerror(opus_err));
    return err;
}

p67_err
send_mic(p67_conn_pass_t * pass)
{
    struct p67_wrtc_hdr hdr;
    opus_int16 output_frame[FRAME_SIZE*CHANNELS];
    unsigned char compressed_frame[sizeof(struct p67_wrtc_hdr)+CFRAME_SIZE];
    unsigned char decompressed_frame[FRAME_SIZE*OPUS_INT_SIZE*CHANNELS];
    float denoisebuff[FRAME_SIZE*OPUS_INT_SIZE*CHANNELS];
    p67_pcm_t i = P67_PCM_INTIIALIZER_IN;
    i.frame_size = FRAME_SIZE;
    i.bits_per_sample = 16;
    i.channels = CHANNELS;
    i.sampling = SAMPLING;
    opus_int32 cb;
    p67_err err;
    int opus_err, ix, buffering, init = 1, seq = 1;
    OpusEncoder * enc;
    p67_thread_t tthr;
    //DenoiseState * st = rnnoise_create(NULL);

    enc = opus_encoder_create(i.sampling, i.channels, OPUS_APPLICATION_AUDIO, &opus_err);
    if(opus_err != 0) goto end;
    opus_encoder_ctl(enc, OPUS_SET_BITRATE(i.sampling * 16 * i.channels));
    
    // if(opus_encoder_ctl(enc, OPUS_SET_PACKET_LOSS_PERC(10)) != OPUS_OK) {
    //     printf("no1\n");
    // }

    if((err = p67_net_start_connect_and_listen(pass)) != 0)
        goto end;

    if((err = p67_cmn_thread_create(&tthr, stream_kbs_print_loop, NULL)) != 0)
        goto end;

    p67_pcm_create_io(&i);
    p67_pcm_printf(i);

    while(1) {
        p67_pcm_read(&i, decompressed_frame, &(size_t){FRAME_SIZE});
        // for(ix = 0; ix < FRAME_SIZE*OPUS_INT_SIZE*CHANNELS; ix++)
        //     denoisebuff[ix] = decompressed_frame[ix];
        // rnnoise_process_frame(st, denoisebuff, denoisebuff);
        for (ix=0;ix<FRAME_SIZE*CHANNELS;ix++) 
           output_frame[ix]=decompressed_frame[OPUS_INT_SIZE*ix+1]<<8|decompressed_frame[OPUS_INT_SIZE*ix];
        cb = opus_encode(enc, output_frame, FRAME_SIZE, compressed_frame+sizeof(struct p67_wrtc_hdr), MAX_FRAME_SIZE);
        hdr.seq = htonl(seq++);
        memcpy(compressed_frame, &hdr , sizeof(struct p67_wrtc_hdr));
        if((err = p67_net_must_write_connect(pass, compressed_frame, cb+sizeof(struct p67_wrtc_hdr))) != 0) 
            goto end;
        __wrote+=cb+sizeof(struct p67_wrtc_hdr);
        if((err = p67_net_must_write_connect(pass, compressed_frame, cb+sizeof(struct p67_wrtc_hdr))) != 0) 
            goto end;
        __wrote+=cb+sizeof(struct p67_wrtc_hdr);

        if(init) {
            init = 0; 
            p67_pcm_recover(&i);
        }
    }

end:
    p67_pcm_free(&i);
    if(opus_err != 0) fprintf(stderr, "%s\n", opus_strerror(opus_err));
    return err;
}


// p67_err
// send_song(p67_conn_pass_t * pass, const char * path)
// {
//     p67_pcm_t out = P67_PCM_INTIIALIZER_OUT;
//     register p67_err err;
//     int fd, r;
//     size_t s;
//     register size_t wrote = 0;
//     char * buf = NULL;
//     long dof;
//     p67_stream_init_t si;
//     pass->handler = sender_callback;

//     // if((err = p67_net_start_connect_and_listen(pass)) != 0)
//     //     goto end;

//     if((err = p67_net_start_listen(pass)) != 0) 
//         goto end;

//     if((err = get_p67_pcm_from_wav_file(&out, &dof, NULL, NULL, path)) != 0)
//         goto end;

//     out.frame_size = 128;
//     p67_pcm_printf(out);
    
//     s = p67_pcm_buff_size(out);// + sizeof(nethdr);

//     if((buf = malloc(s)) == NULL) {
//         err = p67_err_eerrno;
//         goto end;
//     }

//     if((fd = open(path, O_RDONLY)) < 0) goto end;

//     rjmp(s>INT_MAX, err, p67_err_einval, end);

//     si.bits_per_sample = htonl(out.bits_per_sample);
//     si.channels = htonl(out.channels);
//     si.sampling = htonl(out.sampling);
//     si.frame_size = htonl(out.frame_size);

//     p67_pcm_free(&out);

//     if(lseek(fd, dof, 0) < 0) {
//         err = p67_err_eerrno;
//         goto end;
//     }

//     interval = 10000;

//     if((err = p67_net_must_write_connect(pass, &si, sizeof(si))) != 0)
//         goto end;

//     if((err = p67_sm_wait_for(&sm, STATE_STREAM, -1)) != 0)
//         goto end;

//     while((r = read(fd, buf, s)) > 0) {
//         if((err = p67_net_write_connect(pass, buf, &r)) != 0) 
//             goto end;
//         p67_cmn_sleep_micro(interval);
//         wrote += r;
//         rjmp(r < (int)s && lseek(fd, -(s-r), 1) < 0, err, p67_err_eerrno, end);
//     }
//     if(r < 0) err = p67_err_eerrno;

// end:
//     free(buf);
//     if(err != 0) p67_err_print_err(NULL, err);
//     return err;
// }

int
main(int argc, char ** argv)
{
    //T_HIDE_CURSOR();

    p67_conn_pass_t pass = P67_CONN_PASS_INITIALIZER;
    p67_err err;
    
    char keypath[] = "p2pcert";
    char certpath[] = "p2pcert.cert";

    pass.local.rdonly = 1;
    pass.remote.rdonly = 1;
    pass.certpath = certpath;
    pass.keypath = keypath;

    if(argc < 3) {
        printf("Usage: ./p67corenet [source port] [dest port]\n");
        return 2;
    }

    p67_lib_init();

    if((err = p67_addr_set_localhost4_udp(&pass.local, argv[1])) != 0)
        goto end;

    if((err = p67_addr_set_host_udp(&pass.remote, IP4_LO1, argv[2])))
        goto end;

    if(argc > 3) {
        //err = send_song(&pass, argv[3]);
        err = send_mic(&pass);
    } else {
        err = recv_stream(&pass);
    }

end:
    if(err != 0) p67_err_print_err("Main: ", err);
    p67_lib_free();
    if(err == 0) return 0; else return 2;
}
           