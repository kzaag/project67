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

p67_conn_ctx_t ctx = {
    .cb = process_message,
    .keypath = "p2pcert",
    .certpath = "p2pcert.cert",
    .local_addr = NULL,
    .remote_addr = NULL
};

void
finish(int a)
{
    p67_thread_sm_terminate(&ctx.listen_tsm, 500);
    p67_thread_sm_terminate(&ctx.connect_tsm, 500);
    p67_addr_free(ctx.local_addr);
    p67_addr_free(ctx.remote_addr);
    p67_lib_free();
    raise(a);
}

int
main(int argc, char ** argv)
{
    p67_lib_init();
    signal(SIGINT, finish);

    p67_err err;
    
    if(argc < 3) {
        printf("Usage: ./p67corenet [source port] [dest port]\n");
        return 2;
    }

    const char * remote_ip = IP4_LO1;

    ctx.local_addr = p67_addr_new();
    ctx.remote_addr = p67_addr_new();

    if(!ctx.local_addr || !ctx.remote_addr)
        return 2;

    if((err = p67_addr_set_localhost4_udp(ctx.local_addr, argv[1])) != 0)
        goto end;

    if((err = p67_addr_set_host_udp(ctx.remote_addr, remote_ip, argv[2])))
        goto end;

    if((err = p67_conn_ctx_start_listen(&ctx)) != 0)
        goto end;
    if((err = p67_conn_ctx_start_persist_connect(&ctx)) != 0)
        goto end;

    getchar();

    char buff[64];
    int ix = 0;
    while(1) {
        do {
            write(1, "$: ", 3);
        } while((ix = read(0, buff, sizeof(buff))) <= 1);

        if((err = p67_conn_write_once(ctx.remote_addr, buff, ix-1)) != 0)
            p67_err_print_err("couldnt write: ", err);
    }

    getchar();

end:
    if(err != 0) p67_err_print_err("Main: ", err);
    finish(SIGINT);
}
