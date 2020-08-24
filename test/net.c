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

p67_net_listen_ctx_t listen_ctx = P67_NET_LISTEN_CTX_INITIALIZER;
p67_net_connect_ctx_t connect_ctx = P67_NET_CONNECT_CTX_INITIALIZER;

void
finish(int a)
{
    printf("Graceful exit\n");
    p67_net_connect_ctx_free(&connect_ctx);
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

    connect_ctx.local_addr = p67_addr_new_localhost4_udp(argv[1]);
    connect_ctx.remote_addr 
        = p67_addr_new_parse_str(argv[2], P67_SFD_TP_DGRAM_UDP);
    if(!connect_ctx.local_addr || !connect_ctx.remote_addr) {
        err = p67_err_einval;
        goto end;
    }
    connect_ctx.cred.keypath = "p2pcert";
    connect_ctx.cred.certpath = "p2pcert.cert";
    connect_ctx.cb_ctx.cb = process_message;

    listen_ctx.local_addr = p67_addr_ref_cpy(connect_ctx.local_addr);
    listen_ctx.cbctx = connect_ctx.cb_ctx;
    listen_ctx.cred = connect_ctx.cred;

    err = 0;

    err |= p67_net_start_connect(&connect_ctx);
    err |= p67_net_start_listen(&listen_ctx);

    if(err) goto end;

    getchar();

    char buff[64];
    int ix = 0;
    while(1) {
        do {
            write(1, "$: ", 3);
        } while((ix = read(0, buff, sizeof(buff))) <= 1);

        if((err = p67_net_write_msg(
                connect_ctx.remote_addr, buff, ix-1)) != 0)
            p67_err_print_err("couldnt write: ", err);
    }

    getchar();

end:
    if(err != 0) p67_err_print_err("Main: ", err);
    finish(SIGINT);
}
