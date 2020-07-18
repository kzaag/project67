#include <p67/p67.h>
#include <stdlib.h>
#include <alloca.h>

/*
    core networking integration testing
*/

p67_err
process_message(p67_conn_t * conn, const char * msg, int msgl, void * args)
{
    const p67_addr_t * addr = p67_conn_get_addr(conn);
    printf("%s:%s says: %*.*s\n", addr->hostname, addr->service, msgl, msgl, msg);
    return 0;
}

int
main(int argc, char ** argv)
{
    p67_conn_pass_t pass = P67_CONN_PASS_INITIALIZER;
    p67_err err;
    int len = 5;
    
    const char * keypath = "p2pcert";
    const char * certpath = "p2pcert.cert";
    const char * remote_ip = "192.168.0.108";

    pass.local.rdonly = 1;
    pass.remote.rdonly = 1;
    pass.certpath = (char *)certpath;
    pass.keypath = (char *)keypath;
    pass.handler = process_message;

    if(argc < 3) {
        printf("Usage: ./p67corenet [source port] [dest port]\n");
        return 2;
    }

    p67_lib_init();

    if((err = p67_addr_set_localhost4_udp(&pass.local, argv[1])) != 0)
        goto end;

    if((err = p67_addr_set_host_udp(&pass.remote, remote_ip, argv[2])))
        goto end;

    if((err = p67_net_start_connect_and_listen(&pass)) != 0)
        goto end;

    getchar();

    if((err = p67_net_write_connect(&pass, "hello", &len)) != 0) goto end;

    getchar();

    err = p67_net_async_terminate(&pass);

end:
    if(err != 0) p67_err_print_err("Main: ", err);
    p67_lib_free();
    if(err == 0) return 0; else return 2;
}
