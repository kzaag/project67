#include <p67/p67.h>
#include <stdlib.h>
#include <signal.h>

#define T_YELLOW "\033[33m"
#define T_WHITE "\033[0m"

p67_err
process_message(p67_conn_t * conn, const char * msg, int msgl, void * args)
{
    const p67_addr_t * addr = p67_conn_get_addr(conn);
    p67_proto_hdr_t * hdr = p67_proto_get_hdr_from_msg(msg, msgl);
    if(hdr == NULL) return p67_err_einval;

    switch(hdr->h_val) {
    case P67_PROTO_PUDP_ACK:
    case P67_PROTO_PUDP_URG:
    default:
        return p67_err_einval;
    }


    if(p67_pudp_is_proto(msg, msgl)) {
        printf(T_YELLOW "%s:%s says: %.*s\n" T_WHITE, 
            addr->hostname, addr->service, msgl-5, msg+5);
    }

    return p67_pudp_handle_msg(conn, msg, msgl, NULL);
}

p67_err login(p67_conn_pass_t * pass)
{
    p67_err err;
    unsigned char msg[120];
    int len = 120;

    unsigned char * msgp = msg;
    int ix = 0;

    msgp = p67_pudp_urg(msg);
    ix += sizeof(p67_pudp_hdr_t);
    
    if(ix >= len)
        return p67_err_enomem;

    if((err = p67_tlv_add_fragment(msgp, len-ix, "l", NULL, 0)) < 0)
        return -err;
    ix += err;
    msgp+=err;

    #define USER "vattd"

    if((err = p67_tlv_add_fragment(msgp, len-ix, "u", USER, sizeof(USER))) < 0)
        return -err;
    ix += err;
    msgp+=err;

    #define PASS "123" 

    if((err = p67_tlv_add_fragment(msgp, len-ix, "p", PASS, sizeof(PASS))) < 0)
        return -err;
    ix += err;
    msgp+=err;


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
