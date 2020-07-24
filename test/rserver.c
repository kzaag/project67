#include <p67/p67.h>
#include <stdlib.h>
#include <signal.h>

#define T_YELLOW "\033[33m"
#define T_WHITE "\033[0m"

p67_err
process_message(p67_conn_t * conn, const char * msg, int msgl, void * args)
{
    const p67_addr_t * addr = p67_conn_get_addr(conn);

    if(msgl < 1) return 0;

    if(p67_pudp_is_proto(msg, msgl)) {
        printf(T_YELLOW "%s:%s says: %.*s\n" T_WHITE, 
            addr->hostname, addr->service, msgl-5, msg+5);
    }

    return p67_pudp_handle_msg(conn, msg, msgl, NULL);
}

p67_err login(p67_conn_pass_t * pass)
{
    unsigned char msg[120];
    int len = 120;
    int ix = 0;

    p67_pudp_urg(msg);
    ix += sizeof(p67_pudp_hdr_t);
    
    msg[ix] = 1;
    ix += 1;

    ix+=snprintf(msg+ix, len-ix, "\nhello\nworld\n");

    printf("%d\n", ix);

    p67_err err;
    if((err = p67_pudp_write_urg(pass, msg, ix, -1, NULL, NULL)) != 0)
        return err;

    return 0;
}

void
finish(int sig)
{
    p67_lib_free();
    raise(sig);
}

int
main(int argc, char ** argv)
{
    p67_conn_pass_t pass = P67_CONN_PASS_INITIALIZER;
    p67_err err;
    const char * keypath = "p2pcert";
    const char * certpath = "p2pcert.cert";
    const char * remote_ip = IP4_LO1;
    pass.local.rdonly = 1;
    pass.remote.rdonly = 1;
    pass.certpath = (char *)certpath;
    pass.keypath = (char *)keypath;
    pass.handler = process_message;

    signal(SIGINT, finish);

    if(argc < 3) {
        printf("Usage: ./%s [source port] [dest port]\n", argv[0]);
        return 2;
    }

    p67_lib_init();

    if((err = p67_addr_set_localhost4_udp(&pass.local, argv[1])) != 0)
        goto end;

    if((err = p67_addr_set_host_udp(&pass.remote, remote_ip, argv[2])))
        goto end;

    if((err = p67_net_connect(&pass)) != 0) goto end;

    int c = 0;
    while(1) {
        if((err = login(&pass)) != 0)
            goto end;
        getchar();
    }

end:
    if(err != 0) p67_err_print_err("Main: ", err);
    p67_lib_free();
    if(err == 0) return 0; else return 2;
}
