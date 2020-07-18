#include <p67/p67.h>
#include <stdio.h>


int main(int argc, char ** argv)
{
    if(argc < 3) {
        printf("Usage: ./p67corenet [source port] [dest port]\n");
        return 2;
    }

    int max_connect_retries = 3;
    p67_conn_pass_t pass = P67_CONN_PASS_INITIALIZER;
    p67_err err;
    p67_audio_stream_t * stream = NULL;
    if((err = p67_audio_stream_create(&stream)) != 0) goto end;

    const char keypath[] = "p2pcert";
    const char certpath[] = "p2pcert.cert";
    const char remoteip[] = IP4_LO1;

    pass.local.rdonly = 1;
    pass.remote.rdonly = 1;
    pass.certpath = (char *)certpath;
    pass.keypath = (char *)keypath;

    p67_lib_init();

    if((err = p67_addr_set_localhost4_udp(&pass.local, argv[1])) != 0)
        goto end;

    if((err = p67_addr_set_host_udp(&pass.remote, remoteip, argv[2])))
        goto end;

    pass.handler = stream_read_callback;
    pass.args = stream;

    if((err = p67_net_start_connect_and_listen(&pass)) != 0) goto end;

    if(argc > 3) {
        getchar();
        // send stream
        err = p67_audio_stream_write(stream, &pass);
    } else {
        // receive stream
        err = p67_audio_stream_read(stream);
    }

end:
    if(err != 0) p67_err_print_err("Terminating main thread with error: ", err);
    p67_net_async_terminate(&pass);
    p67_lib_free();
    if(err == 0) return 0; else return 2;
}



