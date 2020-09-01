#include <stdio.h>

#include <p67/all.h>

p67_addr_t * remote_addr = NULL;
static p67_thread_sm_t 
    connect_sm = P67_THREAD_SM_INITIALIZER, 
    listen_sm = P67_THREAD_SM_INITIALIZER;
p67_async_t connect_sig = P67_NET_CONNECT_SIG_UNSPEC;
p67_qdp_ctx_t * qdp = NULL;

static void
finish(int a)
{
    printf("Graceful exit\n");
    p67_qdp_free(qdp);
    p67_net_listen_terminate(&listen_sm);
    p67_net_connect_terminate(&connect_sm);
    p67_addr_free(remote_addr);
    p67_lib_free();
    if(a != SIGINT) {
        raise(a);
    } else {
        exit(0);
    }
}

static p67_err
do_connect_and_listen(int argc, const char ** argv)
{
    if(argc < 3)
        return p67_err_einval;
    p67_addr_t * local_addr = p67_addr_new_localhost4_udp(argv[1]);
    remote_addr = p67_addr_new_parse_str_udp(argv[2]);
    p67_net_cb_ctx_t cbctx = {
        .args = qdp,
        .cb = p67_qdp_handle_data,
        .free_args = NULL,
        .gen_args = NULL
    };
    p67_net_cred_t * cred = p67_net_cred_create("p2pcert", "p2pcert.cert");
    if(!local_addr || !remote_addr || !cred) {
        p67_addr_free(local_addr);
        p67_addr_free(remote_addr);
        p67_net_cred_free(cred);
        return p67_err_eerrno | p67_err_einval;
    }
    p67_err err = 0;

    err |= p67_net_start_connect(
        &connect_sm, &connect_sig, local_addr, remote_addr, cred, cbctx, NULL);
    err |= p67_net_start_listen(&listen_sm, local_addr, cred, cbctx, NULL);
    
    p67_addr_free(local_addr);
    p67_net_cred_free(cred);

    return err;
}

int main(int argc, const char ** argv)
{
    if(argc < 3) {
        printf("Usage: %s [source port] [dest host:port]\n", argv[0]);
        return 2;
    }

    p67_lib_init();
    signal(SIGINT, finish);

    p67_err err;
    const uint8_t utp = 3;

    if((err = p67_qdp_create(&qdp)))
        goto end;

    if((err = do_connect_and_listen(argc, argv)))
        goto end;

    p67_net_connect_sig_wait_for_connect(connect_sig);

    if(argc > 3) {
        // send stream
        p67_audio_t stream = P67_AUDIO_INITIALIZER_I;
        if((err = p67_audio_create_io(&stream)) != 0) goto end;
        p67_audio_codecs_t codecs = P67_AUDIO_CODECS_INITIALIZER_AUDIO(stream);
        if((err = p67_audio_codecs_create(&codecs)) != 0) goto end;
        err = p67_audio_write_qdp(remote_addr, &stream, &codecs, utp);
    } else {
        // receive stream
        p67_audio_t stream = P67_AUDIO_INITIALIZER_O;
        if((err = p67_audio_create_io(&stream)) != 0) goto end;
        p67_audio_codecs_t codecs = P67_AUDIO_CODECS_INITIALIZER_AUDIO(stream);
        if((err = p67_audio_codecs_create(&codecs)) != 0) goto end;
        err = p67_audio_read_qdp(qdp, &stream, &codecs);
    }

end:
    if(err != 0) p67_err_print_err("Terminating main thread with error: ", err);
    //p67_net_async_terminate(&pass);
    //p67_lib_free();
    // if(err == 0) return 0; else return 2;
    raise(SIGINT);
}
