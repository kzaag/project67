#include <p67/p67.h>
#include <fcntl.h>
#include <unistd.h>

#include "wav.h"

static int cix;

#define STATE_BEGIN 0
#define STATE_INIT 1
#define STATE_STREAM 3

static p67_async_t sm = P67_ASYNC_INITIALIZER;

p67_err
process_message(p67_conn_t * conn, const char * msg, int msgl, void * args)
{
    p67_err err;

    if(args == NULL)
        return p67_err_einval;

    p67_pcm_t * pcm = (p67_pcm_t *)args;

    if(sm.state == STATE_STREAM) {
        
        // verify that the stream is not out of order and put it into queue?

        // poll bytes from queue and write them into audio device
        // maybe in another thread?
        if((err = p67_pcm_write(pcm, msgl, args)) != 0)
            return err; // temp. one might want to recover instead
        return 0;
    }

    if(sm.state == STATE_INIT)
        return p67_err_einval;

    if(p67_async_set_state(&sm, STATE_BEGIN, STATE_INIT) != 0)
        return p67_err_einval;

    // init stream properties
    // may need some 'strict' flag for pcm to have full control over streaming properties
    pcm->sampling = -1;
    pcm->bits_per_sample = -1;
    pcm->channels = -1;
    pcm->frame_size = -1;

    // intiialize audio device
    p67_pcm_create_io(&pcm);

    // write to peer that init is finished and we can proceed.
    // on error we can notify peer so he can send us different properties.
    p67_net_write(/*conn*/ NULL, "ok", 2);

    if(p67_async_set_state(&sm, STATE_INIT, STATE_STREAM) != 0)
        return p67_err_einval;
}

p67_err
recv_song(p67_conn_pass_t * pass)
{
    p67_pcm_t out = P67_PCM_INTIIALIZER_OUT;
    p67_err err = 0;

    pass->args = &out;

end:
    p67_pcm_free(&out);
    return err;

}

p67_err
send_song(p67_conn_pass_t * pass, const char * path)
{
    p67_pcm_t out = P67_PCM_INTIIALIZER_OUT;
    p67_err err;
    // struct __attribute__((packed)) {

    // } nethdr;
    int fd, r;
    size_t s;
    char * buff = NULL;
    long dof;

    if((err = get_p67_pcm_from_wav_file(&out, &dof, NULL, NULL, path)) != 0)
        goto end;
    
    s = p67_pcm_buff_size(out);// + sizeof(nethdr);

    p67_pcm_free(&out);

    if((fd = open(path, O_RDONLY)) < 0) goto end;

    rjmp(s>INT_MAX, err, p67_err_einval, end);

    while((r = read(fd, buff, s)) > 0) {
        if((err = p67_net_write_connect(pass, buff, &r)) != 0) 
            goto end;
        rjmp(r < (int)s && lseek(fd, -(s-r), 1) < 0, err, p67_err_eerrno, end);
    }

    if(r < 0) err = p67_err_eerrno;

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
    pass.handler = process_message;

    if(argc < 3) {
        printf("Usage: ./p67corenet [source port] [dest port]\n");
        return 2;
    }

    p67_lib_init();

    if((err = p67_addr_set_localhost4_udp(&pass.local, argv[1])) != 0)
        goto end;

    if((err = p67_addr_set_host_udp(&pass.remote, IP4_LO1, argv[2])))
        goto end;

    if((err = p67_net_start_connect_and_listen(&pass)) != 0)
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
