#include <p67/p67.h>
#include <stdlib.h>
#include <signal.h>

#define T_YELLOW "\033[33m"
#define T_WHITE "\033[0m"

p67_err
print_status(const p67_tlv_header_t * header, const unsigned char * value)
{
    uint16_t err;

    if(header->key[0] != 's' || header->vlength != sizeof(err)) {
        printf("Unkown status format\n");
        return 0;
    }

    err = p67_cmn_ntohs(*(uint16_t *)value);

    printf("response status: %u.\n", err);

    return 0;
}

p67_err
process_message(p67_conn_t * conn, const char * const msg, const int msgl, void * args)
{
    const p67_addr_t * addr = p67_conn_get_addr(conn);
    p67_err err;
    const p67_dml_hdr_store_t * hdr;

    if((hdr = p67_dml_parse_hdr((unsigned char *)msg, msgl, NULL)) == NULL)
        return err;

    p67_dml_pretty_print(msg, msgl);

    const unsigned char * msgp = (unsigned char *)(msg + sizeof(*hdr));
    const unsigned char * value;
    const p67_tlv_header_t * header;
    int msgpl = msgl-sizeof(*hdr);
    uint8_t ix;

    switch(hdr->cmn.cmn_stp) {
    case P67_DML_STP_PDP_ACK:
        while((err = p67_tlv_next(&msgp, &msgpl, &header, &value)) == 0) {
        
            switch(header->key[0]) {
            case 's':
                print_status(header, value);
                break;
            case 'b':
                printf("---- begin BWT token: (%d bytes) ----\n", header->vlength);
                for(ix = 0; ix < header->vlength; ix++) {
                    printf("%02x", value[ix] & 0xff);
                    if(ix > 0 && (ix % 14) == 0)
                        printf("\n");
                }
                printf("\n----- end BWT token -----\n");
                break;
            }
        }     
        
        if(err == p67_err_eot) {
            err = 0;
            break;
        }
        err = p67_err_etlvf;
    default:
        err = p67_err_epdpf;
        return 0;
    }

    if(err != 0)
        p67_err_print_err("process message: ", err);

    return p67_dml_handle_msg(conn, msg, msgl, NULL);
}

p67_err login(p67_conn_pass_t * pass)
{
    p67_err err;
    unsigned char msg[120];
    int len = 120;

    unsigned char * msgp = msg;
    int ix = 0;

    if(p67_pdp_generate_urg_for_msg(NULL, 0, msgp, len, 'l') == NULL)
        return p67_err_einval;

    msgp += P67_PDP_URG_OFFSET;
    ix += P67_PDP_URG_OFFSET;
    
    if(ix >= len)
        return p67_err_enomem;

    if((err = p67_tlv_add_fragment(msgp, len-ix, "l\0", NULL, 0)) < 0)
        return -err;
    ix += err;
    msgp+=err;

    #define USER "test"

    if((err = p67_tlv_add_fragment(msgp, len-ix, "u\0", USER, sizeof(USER)-1)) < 0)
        return -err;
    ix += err;
    msgp+=err;

    #define PASS "test" 

    if((err = p67_tlv_add_fragment(msgp, len-ix, "p\0", PASS, sizeof(PASS)-1)) < 0)
        return -err;
    ix += err;
    msgp+=err;

    printf("attempting login with credentials: username=%s password=%s\n", USER, PASS);

    p67_async_t sig = P67_ASYNC_INTIIALIZER;

    p67_epoch_t start, end;

    p67_cmn_time_ms(&start);

    if((err = p67_pdp_write_urg(&pass->remote, msg, ix, -1, &sig, NULL, NULL)) != 0)
        return err;

    p67_mutex_wait_for_change(&sig, 0, -1);

    p67_cmn_time_ms(&end);

    char buff[64];
    printf(
        "login took %llu ms. PDP status is: %s\n",
        end-start,
        p67_pdp_evt_str(buff, sizeof(buff), sig));

    return 0;
}

void
finish(int sig)
{
    //p67_lib_free();
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

// struct p67rs_session {
//     int sessid;
//     p67_async_t state;
// };

// volatile int sessid = 0;

// void * create_rs_session(void * args);
// void * create_rs_session(void * args)
// {
//     (void)args;
    
//     struct p67rs_session * p = calloc(1, sizeof(struct p67rs_session));
//     if(p == NULL) {
//         p67_err_print_err("ERR in create client session: ", p67_err_eerrno);
//         exit(2);
//     }
//     p->sessid=(sessid++);
//     return p;
// }

// void free_rs_session(void * s);
// void free_rs_session(void * s)
// {
//     free(s);
// }

