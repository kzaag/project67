#include <p67/p67.h>

p67_err
read_callback(p67_conn_t * conn, const char * msg, int msgl)
{
    printf("%*.*s\n", msgl, msgl, msg);
}

int
main(int argc, char ** argv)
{
    p67_addr_t local, remote;
    int linit, rinit, len;
    p67_err err;
    p67_thread_t lthr, cthr;

    p67_lib_init();

    linit = 0;
    rinit = 0;

    if(argc < 3) {
        printf("Usage: ./p67test [source port] [dest port]\n");
        return 2;
    }

    if((err = p67_addr_set_host(
            &local, "0.0.0.0", argv[1], P67_SFD_TP_DGRAM_UDP)) != 0) {
        return 2;
    }

    linit = 1;

    if((err = p67_addr_set_host(
            &remote, "127.0.0.1", argv[2], P67_SFD_TP_DGRAM_UDP)) != 0) {
        goto end;
    }

    rinit = 1;

    err = p67_net_p2p_connect(
                &local,
                read_callback,
                "p2pcert", 
                "p2pcert.cert");
    
    if(err != 0) goto end;

    getchar();

    len = 5;
    if((err = p67_net_write(&remote, "hello", &len)) != 0) goto end;

    getchar();
end:
    if(err != 0) p67_err_print_err("Main: ", err);
    if(linit) p67_addr_free(&local);
    if(rinit) p67_addr_free(&remote);
    p67_lib_free();
    if(err == 0) return 0; else return 2;
}
