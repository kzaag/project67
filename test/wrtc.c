#include <p67/p67.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <opus/opus.h>
#include <errno.h>

#include "wav.h"

const int OPUS_INT_SIZE=2;
const int FRAME_SIZE=120;
const int MAX_FRAME_SIZE=1276;
const int CHANNELS=2;
#define CFRAME_SIZE 160
const int SAMPLING=48000;
const int BSAMPLING=44100;
const int FRAME_LENGTH_MICRO = FRAME_SIZE * 1e6 / SAMPLING;
/* compressed frames of total length = 1 second */
#define QUEUE_SIZE 64000 //(1e6/FRAME_LENGTH_MICRO)*CFRAME_SIZE;
static volatile int head = 0;
static volatile int tail = 0;
static char __mqueue[QUEUE_SIZE];
/* min delay in bytes */
const int QUEUE_PREFFERED_LENGTH_MIN = (15*1000/FRAME_LENGTH_MICRO)*CFRAME_SIZE;
/* max delay in bytes */
const int QUEUE_PREFFERED_LENGTH_MAX = (30*1000/FRAME_LENGTH_MICRO)*CFRAME_SIZE;

const int INITIAL_INTERVAL=FRAME_LENGTH_MICRO-150;

struct __attribute__((packed)) p67_wrtc_hdr {
    uint32_t seq;
};

static int receiver_seq = 0;

#define TC_YELLOW "\033[33m"
#define TC_GREEN "\033[32m"
#define TC_DEFAULT "\033[0m"

#define T_HIDE_CURSOR() printf("\e[?25l")
#define T_SHOW_CURSOR() printf("\e[?25h")

#define T_CLEAN_RET "\e[2K"

char empty[CFRAME_SIZE] = {0};

p67_err
queue_enqueue(const char * chunk, int chunkl)
{
    int h = head;

    p67_err err = p67_err_einval;
    int e = (tail+chunkl)%QUEUE_SIZE;
    
    if(QUEUE_SIZE < chunkl) goto end;

    if(tail == h) {
        if(e == h) goto end;
    } else if(tail > h) {
        if(e >= h && e < tail) goto end;
    } else {
        if(e >= h || e < tail) goto end;
    }

    if(chunkl > (QUEUE_SIZE-tail)) {
        // [*|*|*| |L*|*]
        //  0 1 2 3 4  5
        memcpy(__mqueue+tail, chunk, (QUEUE_SIZE-tail));
        memcpy(__mqueue,  chunk+QUEUE_SIZE-tail, chunkl - QUEUE_SIZE + tail);
    } else {
        memcpy(__mqueue+tail, chunk, chunkl);
    }

    tail=(tail+chunkl)%QUEUE_SIZE;

    err = 0;

end:
    return err;
}

p67_err
queue_enqueue_empty()
{
    return queue_enqueue(empty, CFRAME_SIZE);
}

int
queue_space_taken()
{
    int t = tail;
    int h = head;
    if(t == h) {
        return 0;
    } else if(t > h) {
        return t - h;
    } else {
        return QUEUE_SIZE - h + t;
    }
}

p67_err
queue_dequeue(char *chunk, int chunkl)
{
    p67_err err = p67_err_einval;
    int t = tail;

    if(QUEUE_SIZE < chunkl) goto end;

    if(t == head) {
        goto end;
    } else if(t > head) {
        if((t - head) < chunkl) goto end;
    } else {
        if((QUEUE_SIZE - head+t) < chunkl) goto end;
    }

    if(chunkl > (QUEUE_SIZE-head)) {
        // [*|*|*| |H*|*]
        //  0 1 2 3 4  5
        memcpy(chunk, __mqueue+head, (QUEUE_SIZE-head));
        memcpy(chunk+QUEUE_SIZE-head, __mqueue, chunkl - QUEUE_SIZE + head);
    } else {
        memcpy(chunk, __mqueue+head, chunkl);
    }

    head = (head+chunkl)%QUEUE_SIZE;

    err = 0;

end:
    return err;
}

static int lost = 0;

p67_err
receiver_callback(p67_conn_t * conn, const char * msg, int msgl, void * args)
{
    // simulate packets lost
    // if(((lost++) % 3) == 0)
    //     return 0;

    p67_err err;
    int state, seq, df;

    if((unsigned long)msgl < (CFRAME_SIZE + sizeof(struct p67_wrtc_hdr)))
        return 0;        

    struct p67_wrtc_hdr * h = (struct p67_wrtc_hdr *)msg;

    seq = ntohl(h->seq);
    df =  seq - receiver_seq;

    // already got this frame
    if(receiver_seq >= seq) {
        return 0;
    }

    receiver_seq = seq;

    // lost some frames
    while(df-->1) {
        printf("lost 1 packet\n");
        err = queue_enqueue_empty();
        if(err != 0) {
            printf("Overflow\n");
            return 0;
        }
    }

    //if(state >= seq || !p67_sm_update(&receiver_seq, &(int){state}, seq)) {
        //printf("Ignored 1 packet\n");
        //return 0;
    //}

    err = queue_enqueue(msg+sizeof(struct p67_wrtc_hdr), msgl-sizeof(struct p67_wrtc_hdr));
    if(err != 0) {
        printf("Overflow\n");
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
    int qs, factor = 1;

    while(1) {
        qs = queue_space_taken();
        if(qs != 0) {
            if(qs < QUEUE_PREFFERED_LENGTH_MIN) {
                if(interval+factor < FRAME_LENGTH_MICRO) {
                    interval+=factor;
                }
            } else if(qs > QUEUE_PREFFERED_LENGTH_MAX) {
                interval-=factor;
            }
        }
        printf("buffer_size=%07d bytes. interval=%04d microsec\r", qs, interval);
        fflush(stdout);

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
    o.frame_size = FRAME_SIZE;
    o.bits_per_sample = 16;
    o.channels = CHANNELS;
    o.sampling = SAMPLING;
    p67_err err;
    int opus_err, ix, buffering;
    OpusDecoder * dec;
    p67_thread_t scl;

    pass->handler = receiver_callback;

    dec = opus_decoder_create(o.sampling, o.channels, &opus_err);
    if(opus_err != 0) goto end;
    
    if((err = p67_net_start_connect_and_listen(pass)) != 0)
        goto end;

    p67_pcm_create_io(&o);

    p67_pcm_printf(o);

    interval = INITIAL_INTERVAL;

    if((err = p67_cmn_thread_create(&scl, stream_control_loop, NULL)) != 0)
        goto end;

    while(1) {
        err = queue_dequeue(compressed_frame, CFRAME_SIZE);
        p67_cmn_sleep_micro(interval);
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
            o.sampling = BSAMPLING;
            p67_pcm_update(&o);
            buffering = 1;
            printf("buffering\n");
        } else if(buffering) {
            o.sampling = SAMPLING;
            p67_pcm_update(&o);
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
    p67_pcm_t i = P67_PCM_INTIIALIZER_IN;
    i.frame_size = FRAME_SIZE;
    i.bits_per_sample = 16;
    i.channels = CHANNELS;
    i.sampling = SAMPLING;
    opus_int32 cb;
    p67_err err;
    int opus_err, ix, buffering, init = 1, seq = 0;
    OpusEncoder * enc;
    p67_thread_t tthr;

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

    if((err = p67_addr_set_host_udp(&pass.remote, /*"192.168.0.108"*/IP4_LO1, argv[2])))
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
           