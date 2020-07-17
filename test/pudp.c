#include <p67/p67.h>
#include <stdlib.h>
#include <alloca.h>
#include <string.h>

/*
    core networking integration testing 
        - [ ] crypto, 
        - [*] p2p communication
        - [ ] pudp
*/

p67_err
process_message(p67_conn_t * conn, const char * msg, int msgl, void * args)
{
    printf("%d\n", msgl);
    printf("%*.*s\n", msgl-5, msgl-5, msg+5);
    return 0;
}

void
pudp_callback(p67_conn_pass_t * pass, int evt, void * arg)
{
    printf("evt: %d\n", evt);
    if(evt == P67_PUDP_EVT_ERROR) {
        p67_err_print_err("evt: ", *(p67_err*)arg);
    }
}

int
main(int argc, char ** argv)
{
    p67_conn_pass_t pass = P67_CONN_PASS_INITIALIZER;
    p67_err err;
    p67_proto_rpass_t args;
    int len;
    int sigterm = 0;
    
    char keypath[] = "p2pcert";
    char certpath[] = "p2pcert.cert";

    pass.local.rdonly = 1u;
    pass.remote.rdonly = 1u;
    pass.certpath = certpath;
    pass.keypath = keypath;
    pass.handler = p67_proto_handle_msg;
    args.ucb = process_message;
    args.uarg = NULL;
    pass.args = &args;

    if(argc < 3) {
        printf("Usage: ./p67pudp [source port] [dest port]\n");
        return 2;
    }

    p67_lib_init();

    if((err = p67_addr_set_localhost4_udp(&pass.local, argv[1])) != 0)
        goto end;

    if((err = p67_addr_set_host_udp(&pass.remote, IP4_LO1, argv[2])))
        goto end;

    if((err = p67_net_start_connect_and_listen(&pass)) != 0)
        goto end;

    getchar();
    

    len = P67_PROTO_HDR_URG_SIZE + 5;
    const char cstr[] = "hello";

    char msg[5 + P67_PROTO_HDR_URG_SIZE];
    memcpy(msg + P67_PROTO_HDR_URG_SIZE, cstr, 5);
    p67_pudp_urg(msg);

    if((err = p67_proto_write_urg(&pass, msg, len, 0, &sigterm, pudp_callback)) != 0)
        goto end; 

    p67_sm_long_wait_for(&sigterm, 0, -1);

    printf("Main: we give up\n");

    getchar();

    err = p67_net_async_terminate(&pass);

end:
    if(err != 0) p67_err_print_err("Main: ", err);
    p67_lib_free();
    if(err == 0) return 0; else return 2;
}
