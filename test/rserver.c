#include <p67/p67.h>
#include <stdlib.h>
#include <signal.h>

#define T_YELLOW "\033[33m"
#define T_WHITE "\033[0m"

p67_err
process_message(p67_conn_t * conn, const char * const msg, const int msgl, void * args)
{
    const p67_addr_t * addr = p67_conn_get_addr(conn);
    p67_err err;
    p67_pudp_all_hdr_t allhdr;
    int hdrsize = sizeof(allhdr);
    
    if((err = p67_pudp_parse_msg_hdr(
                (unsigned char *)msg, msgl, 
                (p67_pudp_hdr_t *)&allhdr, 
                &hdrsize)) != 0)
        return err;

    const unsigned char * msgp = (unsigned char *)(msg + hdrsize);
    int msgpl = msgl-hdrsize;
    unsigned char v[P67_TLV_VALUE_MAX_LENGTH + 1], k[P67_TLV_KEY_LENGTH];
    unsigned char vlength;

    switch(allhdr.hdr.hdr_type) {
    case P67_PUDP_HDR_ACK:
        while(1) {
            vlength = P67_TLV_VALUE_MAX_LENGTH;
            err = p67_tlv_get_next_fragment(&msgp, &msgpl, k, v, &vlength);
            if(err != 0) {
                if(err == p67_err_eot) break;
                return err;
            }
            v[vlength] = 0;
            printf("response fragment from %s:%s: K=\"%.*s\" V=\"%s\"\n", 
                    addr->hostname, addr->service, P67_TLV_KEY_LENGTH, k, v);
        }     
        break;
    default:
        return p67_err_einval;
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
    ix += sizeof(p67_pudp_urg_hdr_t);
    
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
