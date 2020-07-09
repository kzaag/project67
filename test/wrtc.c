#include <p67/p67.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>

#include "wav.h"

#define STATE_BEGIN  0
#define STATE_CHANGE 1
#define STATE_STREAM 2

static volatile int cix;
static volatile int head = 0;
static volatile int tail = 0;
#define QUEUELEN 50240
static char __mqueue[QUEUELEN];

static volatile int interval;
static const int slow_delta = 10;
static const int fast_delta = 5;
static const int fast_big_delta = 100;


static volatile long __wrote = 0;
static volatile long __read = 0;


#define TC_YELLOW "\033[33m"
#define TC_GREEN "\033[32m"
#define TC_DEFAULT "\033[0m"

#define T_HIDE_CURSOR() printf("\e[?25l")
#define T_SHOW_CURSOR() printf("\e[?25h")

#define T_CLEAN_RET "\e[2K"

struct __attribute__((packed)) p67_stream_init {
    uint64_t frame_size;
    uint32_t sampling;
    uint32_t channels;
    uint32_t bits_per_sample;
};

typedef struct p67_stream_init p67_stream_init_t;

static p67_pcm_t pcm;

static int sm = 0;


p67_err
queue_enqueue(const char * chunk, int chunkl)
{
    int h = head;

    p67_err err = p67_err_einval;
    int e = (tail+chunkl)%QUEUELEN;
    
    if(QUEUELEN < chunkl) goto end;

    if(tail == h) {
        if(e == h) goto end;
    } else if(tail > h) {
        if(e >= h && e < tail) goto end;
    } else {
        if(e >= h || e < tail) goto end;
    }

    if(chunkl > (QUEUELEN-tail)) {
        // [*|*|*| |L*|*]
        //  0 1 2 3 4  5
        memcpy(__mqueue+tail, chunk, (QUEUELEN-tail));
        memcpy(__mqueue,  chunk+QUEUELEN-tail, chunkl - QUEUELEN + tail);
    } else {
        memcpy(__mqueue+tail, chunk, chunkl);
    }

    tail=(tail+chunkl)%QUEUELEN;

    err = 0;

end:
    return err;
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
        return QUEUELEN - h + t;
    }
}

p67_err
queue_dequeue(char *chunk, int chunkl)
{
    p67_err err = p67_err_einval;
    int t = tail;

    if(QUEUELEN < chunkl) goto end;

    if(t == head) {
        goto end;
    } else if(t > head) {
        if((t - head) < chunkl) goto end;
    } else {
        if((QUEUELEN - head+t) < chunkl) goto end;
    }

    if(chunkl > (QUEUELEN-head)) {
        // [*|*|*| |H*|*]
        //  0 1 2 3 4  5
        memcpy(chunk, __mqueue+head, (QUEUELEN-head));
        memcpy(chunk+QUEUELEN-head, __mqueue, chunkl - QUEUELEN + head);
    } else {
        memcpy(chunk, __mqueue+head, chunkl);
    }

    head = (head+chunkl)%QUEUELEN;

    err = 0;

end:
    return err;
}

p67_err
sender_callback(p67_conn_t * conn, const char * msg, int msgl, void * args)
{
    const p67_addr_t * remote = p67_conn_get_addr(conn);

    switch(sm) {
    case STATE_BEGIN:
        if(msgl == 1 && msg[0] == 1) {
            p67_sm_set_state(&sm, STATE_BEGIN, STATE_STREAM);
            printf("init\n");
        }
        break;
    case STATE_STREAM:
        printf(TC_YELLOW "\r%s:%s: %*.*s\n" TC_DEFAULT, remote->hostname, remote->service, msgl, msgl, msg);
        if(msgl < 7) return 0;
        if(memcmp(msg, "slower!", 7) == 0) {
            interval+=slow_delta;
            return 0;
        }
        if(memcmp(msg, "faster!", 7) == 0) {
            if(interval == 0)
                return 0;
            if(msgl > 7 && msg[7] == '!') {
                interval-=fast_big_delta;
            } else {
                interval-=fast_delta;
            }
            return 0;
        }
        break;
    default:
        return p67_err_einval;
    }

    return 0;
}

p67_err
receiver_callback(p67_conn_t * conn, const char * msg, int msgl, void * args)
{
    p67_err err;

    switch(sm) {
    case STATE_BEGIN:
    
        if(p67_sm_set_state(&sm, STATE_BEGIN, STATE_CHANGE) != 0) {
            printf("1\n");
            // err
            return 1;
        }

        const p67_stream_init_t * init;
        char ret = 1;

        if(msgl != sizeof(*init)) {
            printf("11\n");
            // err
            return 1;
        }

        init = (const p67_stream_init_t *)msg;

        pcm.sampling = ntohl(init->sampling);
        pcm.bits_per_sample = ntohl(init->bits_per_sample);
        pcm.channels = ntohl(init->channels);
        pcm.frame_size = ntohl(init->frame_size);
        pcm.pcm_tp = P67_PCM_TP_O;
        pcm.__hw = NULL;
        pcm.name = NULL;
        pcm.name_rdonly = 0;

        p67_pcm_printf(pcm);

        if((err = p67_pcm_create_io(&pcm)) != 0) {
            printf("2\n");
            // err
            return 1;
        }

        err = p67_net_must_write_conn(conn, &ret, 1);
        if(err != 0) {
            printf("3\n");
            // err
            return 1;
        }

        if(p67_sm_set_state(&sm, STATE_CHANGE, STATE_STREAM) != 0) {
            printf("4\n");
            // err
            return 1;
        }

        printf("init\n");

        break;
    case STATE_CHANGE:
        printf("5\n");
        // err
        break;
    case STATE_STREAM:
        err = queue_enqueue(msg, msgl);
        __wrote += msgl;
        if(err != 0) {
            printf("6\n");
            // err
            return 0;
        }
        break;
    default:
        return p67_err_einval;
    }

    return 0;
}

volatile int scl_clock = 0;

void * 
stream_control_loop(void * args)
{
    while(1) {
        scl_clock = 1;
        p67_cmn_sleep_ms(2000);
    }
//     double wv, rv;
//     int taken;
//     const int iv = 100;
//     p67_conn_pass_t * pass = (p67_conn_pass_t *)args;

//     while(1) {
//         wv = __wrote / iv;
//         rv = __read / iv;
//         __read = 0;
//         __wrote = 0;
//         taken = queue_space_taken();
//         printf("wv=%lf rv=%lf %05d\n", wv, rv, taken);

//         p67_cmn_sleep_ms(iv);
//     }
}

p67_err
recv_song(p67_conn_pass_t * pass)
{
    register p67_err err = 0;
    size_t read = 0, r;
    register float taken, ltaken = 0;
    int lop = 0;
    /* ataken = 0;*/
    /* register long i = 0; */
    char * b = NULL;
    pass->handler = receiver_callback;
    size_t chunksize;
    p67_thread_t scc;
    int one = 1;

    if((err = p67_net_start_connect_and_listen(pass)) != 0)
        goto end;

    if((err = p67_cmn_thread_create(&scc, stream_control_loop, pass)) != 0)
        goto end;

    if((err = p67_sm_wait_for(&sm, STATE_STREAM, -1)) != 0)
        goto end;

    chunksize = p67_pcm_buff_size(pcm);

    if((b = malloc(chunksize)) == NULL) goto end;

    interval = 500;

    while(1) {
        err = queue_dequeue(b, chunksize);
        p67_cmn_sleep_micro(interval);
        if(err != 0) continue;
        __read += chunksize;
        r = pcm.frame_size;
        err = p67_pcm_write(&pcm, b, &r);
        if(err == p67_err_epipe) {
            printf("SPEEDUP\n");
            if((err = p67_net_must_write_connect(pass, "faster!!", 8)) != 0) goto end;
        }
        read+=p67_pcm_act_size(pcm, r);
        taken = queue_space_taken();
        if(taken > 0) {
            printf("SLOWDOWN\n");
            if((err = p67_net_must_write_connect(pass, "slower!", 7)) != 0) goto end;
        }

        if(taken == 0) {
            if(scl_clock) {
                one = 1;
                p67_sm_update(&scl_clock, &one, 0);
                if((err = p67_net_must_write_connect(pass, "faster!", 7)) != 0) goto end;
            }
        }

        // if(taken == 0) {
            // if(lop == -1) {
            //     if(sync_clock) {
            //         one = 1;
            //         p67_sm_update(&sync_clock, &one, 0);
            //         if((err = p67_net_must_write_connect(pass, "faster!", 7)) != 0) goto end;
            //     }
            // } else if(lop == 1) {
            //     if(sync_clock) {
            //         one = 1;
            //         p67_sm_update(&sync_clock, &one, 0);
            //         if((err = p67_net_must_write_connect(pass, "slower!", 7)) != 0) goto end;
            //     }
            // }
        //}

        //printf("\rread: %lu. buffered: %f", read, taken);

        // ltaken = taken;
    }

end:
    free(b);
    p67_pcm_free(&pcm);
    return err;
}


p67_err
send_mic(p67_conn_pass_t * pass)
{
    p67_pcm_t in = P67_PCM_INTIIALIZER_IN;
    in.channels = P67_PCM_CHAN_STEREO;
    in.sampling = P67_PCM_SAMPLING_44_1K;
    in.bits_per_sample = P67_PCM_BPS_16;
    in.frame_size = 64;
    register p67_err err;
    size_t s, r;
    register size_t wrote = 0;
    char * buf = NULL;
    p67_stream_init_t si;
    pass->handler = sender_callback;

    if((err = p67_pcm_create_io(&in)) != 0) goto end;
    in.frame_size = 128;

    if((err = p67_net_start_connect_and_listen(pass)) != 0)
        goto end;

    p67_async_terminate(&pass->hconnect, P67_TO_DEF);

    s = p67_pcm_buff_size(in);// + sizeof(nethdr);

    si.bits_per_sample = htonl(in.bits_per_sample);
    si.channels = htonl(in.channels);
    si.sampling = htonl(in.sampling);
    si.frame_size = htonl(in.frame_size);

    if((buf = malloc(s)) == NULL) {
        err = p67_err_eerrno;
        goto end;
    }

    interval = 0;

    if((err = p67_net_must_write_connect(pass, &si, sizeof(si))) != 0)
        goto end;

    if((err = p67_sm_wait_for(&sm, STATE_STREAM, -1)) != 0)
        goto end;

    while(1) {
        r = in.frame_size;
        err = p67_pcm_read(&in, buf, &r);
        p67_cmn_sleep_micro(interval);
        r = p67_pcm_act_size(in, r);
        if((err = p67_net_write_connect(pass, buf, (int *)&r)) != 0) 
            goto end;
        wrote += r;
    }

end:
    free(buf);
    if(err != 0) p67_err_print_err(NULL, err);
    return err;
}

p67_err
send_song(p67_conn_pass_t * pass, const char * path)
{
    p67_pcm_t out = P67_PCM_INTIIALIZER_OUT;
    register p67_err err;
    int fd, r;
    size_t s;
    register size_t wrote = 0;
    char * buf = NULL;
    long dof;
    p67_stream_init_t si;
    pass->handler = sender_callback;

    // if((err = p67_net_start_connect_and_listen(pass)) != 0)
    //     goto end;

    if((err = p67_net_start_listen(pass)) != 0) 
        goto end;

    if((err = get_p67_pcm_from_wav_file(&out, &dof, NULL, NULL, path)) != 0)
        goto end;

    out.frame_size = 128;
    p67_pcm_printf(out);
    
    s = p67_pcm_buff_size(out);// + sizeof(nethdr);

    if((buf = malloc(s)) == NULL) {
        err = p67_err_eerrno;
        goto end;
    }

    if((fd = open(path, O_RDONLY)) < 0) goto end;

    rjmp(s>INT_MAX, err, p67_err_einval, end);

    si.bits_per_sample = htonl(out.bits_per_sample);
    si.channels = htonl(out.channels);
    si.sampling = htonl(out.sampling);
    si.frame_size = htonl(out.frame_size);

    p67_pcm_free(&out);

    if(lseek(fd, dof, 0) < 0) {
        err = p67_err_eerrno;
        goto end;
    }

    interval = 5000;

    if((err = p67_net_must_write_connect(pass, &si, sizeof(si))) != 0)
        goto end;

    if((err = p67_sm_wait_for(&sm, STATE_STREAM, -1)) != 0)
        goto end;

    while((r = read(fd, buf, s)) > 0) {
        if((err = p67_net_write_connect(pass, buf, &r)) != 0) 
            goto end;
        p67_cmn_sleep_micro(interval);
        wrote += r;
        rjmp(r < (int)s && lseek(fd, -(s-r), 1) < 0, err, p67_err_eerrno, end);
    }
    if(r < 0) err = p67_err_eerrno;

end:
    free(buf);
    if(err != 0) p67_err_print_err(NULL, err);
    return err;
}

int
main(int argc, char ** argv)
{
    //T_HIDE_CURSOR();

    p67_conn_pass_t pass = P67_CONN_PASS_INITIALIZER;
    p67_err err;
    
    char keypath[] = "p2pcert";
    char certpath[] = "p2pcert.cert";

    pass.local.rdonly = 1u;
    pass.remote.rdonly = 1u;
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
        err = send_song(&pass, argv[3]);
        //err = send_mic(&pass);
    } else {
        err = recv_song(&pass);
    }

end:
    if(err != 0) p67_err_print_err("Main: ", err);
    p67_lib_free();
    if(err == 0) return 0; else return 2;
}
