#include <p67/p67.h>

p67_err
read_callback(p67_conn_t * conn, const char * msg, int msgl)
{
    printf("%*.*s\n", msgl, msgl, msg);
}

int
main()
{
    p67_addr_t local, remote;
    int linit, rinit, len;
    p67_err err;

    p67_lib_init();

    linit = 0;
    rinit = 0;

    if((err = p67_addr_set_host(
            &local, "127.0.0.1", "10000", P67_SFD_TP_DGRAM_UDP)) != 0) {
        return 1;
    }

    linit = 1;

    if((err = p67_addr_set_host(
            &remote, "127.0.0.1", "10100", P67_SFD_TP_DGRAM_UDP)) != 0) {
        goto end;
    }

    rinit = 1;

    err = p67_net_connect(
                &local, &remote, 
                read_callback, 
                "server_private_key", 
                "server_cert.pem");

    if(err != 0) goto end;

    len = 5;
    if((err = p67_net_write(&remote, "hello", &len)) != 0) goto end;

end:
    if(err != 0) p67_err_print_err("Main: ", err);
    if(linit) p67_addr_free(&local);
    if(rinit) p67_addr_free(&remote);
    p67_lib_free();
    if(err == 0) return 0; else return 2;
}
