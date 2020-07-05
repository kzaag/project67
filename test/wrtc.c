#include <p67/p67.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>

#include "wav.h"


#define STATE_BEGIN 0
#define STATE_INIT 1
#define STATE_STREAM 3

static p67_async_t sm = {STATE_STREAM, 0};

static volatile int cix;
static volatile int head = 0;
static volatile int tail = 0;
#define QUEUELEN 502400
static char __mqueue[QUEUELEN];

#define TC_YELLOW "\033[33m"
#define TC_GREEN "\033[32m"
#define TC_DEFAULT "\033[0m"

static p67_mutex_t __lock = P67_CMN_MUTEX_INITIALIZER;

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

    memcpy(__mqueue+tail, chunk, chunkl);
    tail=(tail+chunkl)%QUEUELEN;

    err = 0;

end:
    return err;
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
    printf(TC_YELLOW "%s:%s: %*.*s\n" TC_DEFAULT, remote->hostname, remote->service, msgl, msgl, msg);
    return 0;
}

p67_err
receiver_callback(p67_conn_t * conn, const char * msg, int msgl, void * args)
{
    //p67_err err;
    //const p67_addr_t * remote = p67_conn_get_addr(conn);

    // printf(TC_YELLOW"%s:%s: %*.*s\n"TC_DEFAULT, remote->hostname, remote->service, msgl, msgl, msg);
    // err = p67_net_must_write(remote, "i love you", 10);
    // return err;

    //if(args == NULL)
    //    return p67_err_einval;

    //p67_pcm_t * pcm = (p67_pcm_t *)args;

    if(sm.state == STATE_STREAM) {
        // verify that the stream is not out of order and put it into queue?

        return queue_enqueue(msg, msgl);
    }

    return p67_err_einval;

    // if(sm.state == STATE_INIT)
    //     return p67_err_einval;

    // if(p67_async_set_state(&sm, STATE_BEGIN, STATE_INIT) != 0)
    //     return p67_err_einval;

    // // init stream properties
    // // may need some 'strict' flag for pcm to have full control over streaming properties
    // pcm->sampling = P67_PCM_SAMPLING_48K;
    // pcm->bits_per_sample = P67_PCM_PBS_16;
    // pcm->channels = P67_PCM_CHAN_MONO;
    // pcm->frame_size = 512;

    // // initialize audio device
    // p67_pcm_create_io(pcm);

    // // write to peer that init is finished and we can proceed.
    // // on error we can notify peer so he can send us different properties.
    // p67_net_must_write(remote, "ok", 2);

    // if(p67_async_set_state(&sm, STATE_INIT, STATE_STREAM) != 0)
    //     return p67_err_einval;
}

p67_err
recv_song(p67_conn_pass_t * pass)
{
    p67_pcm_t out = P67_PCM_INTIIALIZER_OUT;
    out.frame_size = 128;
    out.channels = P67_PCM_CHAN_STEREO;
    out.sampling = P67_PCM_SAMPLING_44_1K;
    out.bits_per_sample = P67_PCM_PBS_16;
    p67_err err = 0;
    size_t read = 0;
    char * b = NULL;
    pass->handler = receiver_callback;
    size_t chunksize = p67_pcm_buff_size(out);

    if((err = p67_pcm_create_io(&out)) != 0) goto end;

    if((err = p67_net_start_connect_and_listen(pass)) != 0)
        goto end;

    if((b = malloc(chunksize)) == NULL) goto end;
    
    while(1) {
        chunksize = p67_pcm_buff_size(out);
        err = queue_dequeue(b, chunksize);
        p67_cmn_sleep_micro(500);
        if(err != 0) continue; //p67_err_print_err("Dequeue: ", err);
        // else printf(TC_GREEN "%*.*s\n" TC_DEFAULT, 2, 2, b);
        // sleep(1);
        read+=chunksize;
        chunksize = out.frame_size;
        p67_pcm_write(&out, b, &chunksize);
        printf("read: %lu\n", read);
    }

end:
    free(b);
    p67_pcm_free(&out);
    return err;

}

p67_err
send_song(p67_conn_pass_t * pass, const char * path)
{
    p67_pcm_t out = P67_PCM_INTIIALIZER_OUT;
    p67_err err;
    int fd, r;
    size_t s, wrote = 0;
    char * buf = NULL;
    long dof;
    pass->handler = sender_callback;

    if((err = p67_net_start_connect_and_listen(pass)) != 0)
        goto end;

    if((err = get_p67_pcm_from_wav_file(&out, &dof, NULL, NULL, path)) != 0)
        goto end;

    out.frame_size = 128;
    
    s = p67_pcm_buff_size(out);// + sizeof(nethdr);

    if((buf = malloc(s)) == NULL) {
        err = p67_err_eerrno;
        goto end;
    }

    p67_pcm_free(&out);

    if((fd = open(path, O_RDONLY)) < 0) goto end;

    rjmp(s>INT_MAX, err, p67_err_einval, end);

    //err = p67_net_must_write_connect(pass, "i love you", 10);
    //if(err != 0) goto end;

    //printf("Sending chunks of size=%lu\n", s);
    //goto end;

    if(lseek(fd, dof, 0) < 0) {
        err = p67_err_eerrno;
        goto end;
    }

    while((r = read(fd, buf, s)) > 0) {
        if((err = p67_net_write_connect(pass, buf, &r)) != 0) 
            goto end;
        p67_cmn_sleep_micro(2500);
        wrote += r;
        printf("wrote: %lu\n", wrote);
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
    } else {
        err = recv_song(&pass);
    }

end:
    if(err != 0) p67_err_print_err("Main: ", err);
    p67_lib_free();
    if(err == 0) return 0; else return 2;
}