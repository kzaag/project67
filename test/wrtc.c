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
#define QUEUELEN 102400
static char __mqueue[QUEUELEN];

#define TC_YELLOW "\033[33m"
#define TC_GREEN "\033[32m"
#define TC_DEFAULT "\033[0m"

p67_err
queue_enqueue(const char * chunk, int chunkl)
{
    int e = (tail+chunkl)%QUEUELEN;
    
    if(QUEUELEN < chunkl)
        return p67_err_einval;

    if(tail == head) {
        if(e == head) return p67_err_einval;
    } else if(tail > head) {
        if(e >= head && e < tail) return p67_err_einval;
    } else {
        if(e >= head || e < tail) return p67_err_einval;
    }

    memcpy(__mqueue+tail, chunk, chunkl);
    tail=(tail+chunkl)%QUEUELEN;

    return 0;
}

p67_err
queue_dequeue(char *chunk, int chunkl)
{
    if(QUEUELEN < chunkl)
        return p67_err_einval;

    if(tail == head) {
        return p67_err_einval;
    } else if(tail > head) {
        if((tail - head) < chunkl) return p67_err_einval;
    } else {
        if((QUEUELEN - head+tail) < chunkl) return p67_err_einval;
    }

    memcpy(chunk, __mqueue+head, chunkl);
    head = (head+chunkl)%QUEUELEN;

    return 0;
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
    p67_err err;
    const p67_addr_t * remote = p67_conn_get_addr(conn);

    // printf(TC_YELLOW"%s:%s: %*.*s\n"TC_DEFAULT, remote->hostname, remote->service, msgl, msgl, msg);
    // err = p67_net_must_write(remote, "i love you", 10);
    // return err;

    if(args == NULL)
        return p67_err_einval;

    p67_pcm_t * pcm = (p67_pcm_t *)args;

    if(sm.state == STATE_STREAM) {
        
        // verify that the stream is not out of order and put it into queue?

        return queue_enqueue(msg, msgl);
    }

    if(sm.state == STATE_INIT)
        return p67_err_einval;

    if(p67_async_set_state(&sm, STATE_BEGIN, STATE_INIT) != 0)
        return p67_err_einval;

    // init stream properties
    // may need some 'strict' flag for pcm to have full control over streaming properties
    pcm->sampling = P67_PCM_SAMPLING_48K;
    pcm->bits_per_sample = P67_PCM_PBS_16;
    pcm->channels = P67_PCM_CHAN_MONO;
    pcm->frame_size = 1024;

    // initialize audio device
    p67_pcm_create_io(pcm);

    // write to peer that init is finished and we can proceed.
    // on error we can notify peer so he can send us different properties.
    p67_net_must_write(remote, "ok", 2);

    if(p67_async_set_state(&sm, STATE_INIT, STATE_STREAM) != 0)
        return p67_err_einval;
}

p67_err
recv_song(p67_conn_pass_t * pass)
{
    p67_pcm_t out = P67_PCM_INTIIALIZER_OUT;
    p67_err err = 0;
    pass->args = &out;
    pass->handler = receiver_callback;

    if((err = p67_net_start_connect_and_listen(pass)) != 0)
        goto end;

    char b[2];

    while(1) {
        err = queue_dequeue(b, 2);
        if(err != 0) p67_err_print_err("Dequeue: ", err);
        else printf(TC_GREEN "%*.*s\n" TC_DEFAULT, 2, 2, b);
        sleep(1);
    }

    getchar();

end:
    p67_pcm_free(&out);
    return err;

}

p67_err
send_song(p67_conn_pass_t * pass, const char * path)
{
    p67_pcm_t out = P67_PCM_INTIIALIZER_OUT;
    p67_err err;
    int fd, r;
    size_t s;
    char * buff = NULL;
    long dof;
    pass->handler = sender_callback;


    if((err = p67_net_start_connect_and_listen(pass)) != 0)
        goto end;

    if((err = get_p67_pcm_from_wav_file(&out, &dof, NULL, NULL, path)) != 0)
        goto end;
    
    s = p67_pcm_buff_size(out);// + sizeof(nethdr);

    p67_pcm_free(&out);

    if((fd = open(path, O_RDONLY)) < 0) goto end;

    rjmp(s>INT_MAX, err, p67_err_einval, end);

    err = p67_net_must_write_connect(pass, "hilo", 4);
    if(err != 0) goto end;

    // while((r = read(fd, buff, s)) > 0) {
    //     if((err = p67_net_write_connect(pass, buff, &r)) != 0) 
    //         goto end;
    //     rjmp(r < (int)s && lseek(fd, -(s-r), 1) < 0, err, p67_err_eerrno, end);
    // }
    //if(r < 0) err = p67_err_eerrno;

    getchar();

end:
    if(buff != NULL) free(buff);
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
