#include <p67/p67.h>
#include <stdlib.h>
#include <alloca.h>
#include <unistd.h>
#include <fcntl.h>

/*
    core networking integration testing
*/

p67_err
process_message(p67_addr_t * addr, p67_pckt_t * msg, int msgl, void * args)
{
    printf("%s:%s says: %.*s\n", addr->hostname, addr->service, msgl, msg);
    return 0;
}

p67_conn_ctx_t conn_ctx = {0};

void
finish(int a)
{
    printf("Graceful exit\n");
    p67_conn_ctx_free_fields(&conn_ctx);
    p67_lib_free();
    if(a == SIGINT) exit(0);
    else raise(a);
}

int
main(int argc, char ** argv)
{
    p67_lib_init();
    signal(SIGINT, finish);

    p67_err err;
    
    if(argc < 3) {
        printf("Usage: ./%s [source port] [dest addr]\n", argv[0]);
        return 2;
    }

    p67_conn_ctx_set_addr(
        &conn_ctx,
        p67_addr_new_localhost4_udp(argv[1]),
        p67_addr_new_parse_str(argv[2], P67_SFD_TP_DGRAM_UDP));

    p67_conn_ctx_set_cb_with_args(
        &conn_ctx, process_message, NULL, NULL, NULL);

    p67_conn_ctx_set_credentials(
        &conn_ctx, "p2pcert2.cert", "p2pcert2");

    if((err = p67_conn_ctx_start_connect_and_listen(&conn_ctx)) != 0)
        goto end;

    getchar();

    char buff[64];
    int ix = 0;
    while(1) {
        do {
            write(1, "$: ", 3);
        } while((ix = read(0, buff, sizeof(buff))) <= 1);

        if((err = p67_conn_write_once(conn_ctx.remote_addr, buff, ix-1)) != 0)
            p67_err_print_err("couldnt write: ", err);
    }

    getchar();

end:
    if(err != 0) p67_err_print_err("Main: ", err);
    finish(SIGINT);
}
