#include <p67/p67.h>
#include <stdlib.h>
#include <signal.h>

#define T_YELLOW "\033[33m"
#define T_WHITE "\033[0m"

p67_err
print_response(unsigned char * key, unsigned char * value, int vlength)
{
    uint32_t err;

    if(vlength != sizeof(err)) {
        printf("Unkown response format\n");
        return 0;
    }

    err = p67_cmn_ntohl(*(uint32_t *)value);

    printf("response status for %.*s = %d.\n", P67_TLV_KEY_LENGTH, key, err);

    return 0;
}

p67_err
process_message(p67_conn_t * conn, const char * const msg, const int msgl, void * args)
{
    const p67_addr_t * addr = p67_conn_get_addr(conn);
    p67_err err;
    const p67_dmp_hdr_store_t * hdr;

    if((hdr = p67_dmp_parse_hdr((unsigned char *)msg, msgl, NULL)) == NULL)
        return err;

    const unsigned char * msgp = (unsigned char *)(msg + sizeof(*hdr));
    int msgpl = msgl-sizeof(*hdr);
    unsigned char 
                v[P67_TLV_VALUE_MAX_LENGTH + 1], 
                k[P67_TLV_KEY_LENGTH],
                vlength,
                ix;

    switch(p67_cmn_ntohs(hdr->cmn.cmn_stp)) {
    case P67_DMP_STP_PDP_ACK:
        while(1) {
            vlength = P67_TLV_VALUE_MAX_LENGTH;
            err = p67_tlv_get_next_fragment(&msgp, &msgpl, k, v, &vlength);
            if(err != 0) {
                if(err == p67_err_eot) break;
                return err;
            }
            v[vlength] = 0;
            print_response(k, v, vlength);
        }     
        break;
    default:
        return p67_err_einval;
    }

    return p67_dmp_handle_msg(conn, msg, msgl, NULL);
}

p67_err login(p67_conn_pass_t * pass)
{
    p67_err err;
    unsigned char msg[120];
    int len = 120;

    unsigned char * msgp = msg;
    int ix = 0;

    if(p67_dmp_pdp_generate_urg_for_msg(NULL, 0, msgp, len, 0) == NULL)
        return p67_err_einval;

    msgp += P67_DMP_PDP_URG_OFFSET;
    ix += P67_DMP_PDP_URG_OFFSET;
    
    if(ix >= len)
        return p67_err_enomem;

    if((err = p67_tlv_add_fragment(msgp, len-ix, "l\0", NULL, 0)) < 0)
        return -err;
    ix += err;
    msgp+=err;

    #define USER "vattd"

    if((err = p67_tlv_add_fragment(msgp, len-ix, "u\0", USER, sizeof(USER))) < 0)
        return -err;
    ix += err;
    msgp+=err;

    #define PASS "123" 

    if((err = p67_tlv_add_fragment(msgp, len-ix, "p\0", PASS, sizeof(PASS))) < 0)
        return -err;
    ix += err;
    msgp+=err;


    if((err = p67_dmp_pdp_write_urg(pass, msg, ix, -1, NULL, NULL)) != 0)
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
