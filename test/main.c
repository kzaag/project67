#include <p67/p67.h>
#include <stdlib.h>
#include <alloca.h>

p67_err
read_callback(p67_conn_t * conn, const char * msg, int msgl)
{
    printf("%*.*s\n", msgl, msgl, msg);
}

int
main(int argc, char ** argv)
{
    p67_conn_pass_t pass = P67_CONN_PASS_INITIALIZER;
    p67_err err;
    int len = 5;
    
    char keypath[] = "server_private_key";
    char certpath[] = "server_cert.pem";

    pass.local.rdonly = 1u;
    pass.remote.rdonly = 1u;
    pass.certpath = certpath;
    pass.keypath = keypath;

    if(argc < 3) {
        printf("Usage: ./p67test [source port] [dest port]\n");
        return 2;
    }

    p67_lib_init();

    if((err = p67_addr_set_localhost4_udp(&pass.local, argv[1])) != 0)
        goto end;

    if((err = p67_addr_set_host_udp(&pass.remote, IP4_LO1, argv[2])))
        goto end;

    while(1) {
        if((err = p67_net_start_listen(&pass)) != 0)
            goto end;

        if((err = p67_net_start_persist_connect(&pass)) != 0)
            goto end;

        getchar();

        if((err = p67_async_terminate_thread(&pass.hconnect, P67_TO_DEF)) != 0)
            goto end;
        if((err = p67_async_terminate_thread(&pass.hlisten, P67_TO_DEF)) != 0)
            goto end;

        printf("ok\n");
        getchar();
    }
end:
    if(err != 0) p67_err_print_err("Main: ", err);
    p67_lib_free();
    if(err == 0) return 0; else return 2;
}
