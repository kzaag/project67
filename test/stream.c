#include <p67/p67.h>
#include <stdio.h>


int main(int argc, char ** argv)
{
    if(argc < 3) {
        printf("Usage: %s [source port] [dest port]\n", argv[0]);
        return 2;
    }

    int max_connect_retries = 3;
    p67_conn_ctx_t conn = P67_CONN_CTX_INITIALIZER;
    p67_qdp_ctx_t * qdp;
    p67_err err;

    const char keypath[] = "p2pcert";
    const char certpath[] = "p2pcert.cert";
    const char remoteip[] = IP4_LO1;
    
    const uint8_t utp = 3;
    
    conn.certpath = (char *)certpath;
    conn.keypath = (char *)keypath;
    conn.local_addr = p67_addr_new();
    conn.remote_addr = p67_addr_new();

    assert(conn.local_addr && conn.remote_addr);

    p67_lib_init();

    if((err = p67_addr_set_localhost4_udp(conn.local_addr, argv[1])))
        goto end;

    if((err = p67_addr_set_host_udp(conn.remote_addr, remoteip, argv[2])))
        goto end;

    if((err = p67_qdp_create(&qdp)))
        goto end;

    conn.cb = p67_qdp_handle_data;
    conn.args = qdp;

    if((err = p67_conn_ctx_start_listen(&conn)) != 0)
        goto end;
    if((err = p67_conn_ctx_start_connect(&conn)) != 0)
        goto end;

    if(argc > 3) {
        getchar();
        // send stream
        p67_audio_t stream = P67_AUDIO_INITIALIZER_I;
        if((err = p67_audio_create_io(&stream)) != 0) goto end;
        p67_audio_codecs_t codecs = P67_AUDIO_CODECS_INITIALIZER_AUDIO(stream);
        if((err = p67_audio_codecs_create(&codecs)) != 0) goto end;
        err = p67_audio_write_qdp(conn.remote_addr, &stream, &codecs, utp);
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
