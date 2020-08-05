#include <p67/p67.h>
#include <stdlib.h>
#include <alloca.h>
#include <string.h>

p67_err
process_message(p67_conn_t * conn, const char * msg, int msgl, void * args)
{
    p67_err err;
    const p67_dml_hdr_store_t * hdr;

    if((hdr = p67_dml_parse_hdr((const unsigned char *)msg, msgl, &err)) == NULL)
        return err;

    switch (hdr->cmn.cmn_stp) {
    case P67_DML_STP_PDP_ACK:
        break;
    case P67_DML_STP_PDP_URG:
        printf("URG received with payload (%d bytes): \"%.*s\"\n", 
            msgl-P67_PDP_URG_OFFSET, 
            msgl-P67_PDP_URG_OFFSET, 
            msg+P67_PDP_URG_OFFSET);
        break;
    default:
        printf("Unknown message received with payload (%d bytes): %.*s\n", 
            msgl, msgl, msg);
        break;
    }

    return p67_dml_handle_msg(conn, msg, msgl, NULL);
}

void
pudp_evt_callback(p67_conn_pass_t * pass, int evt, void * arg)
{
    char buff[120];
    printf("EVT: %s\n", p67_pdp_evt_str(buff, sizeof(buff), evt));
    if(evt == P67_PDP_EVT_ERROR) {
        p67_err_print_err("err: ", *(p67_err*)arg);
    }
}

int
main(int argc, char ** argv)
{
    p67_conn_pass_t pass = P67_CONN_PASS_INITIALIZER;
    p67_err err;
    int len;
    int sigterm = P67_PDP_EVT_NONE;
    
    char keypath[] = "p2pcert";
    char certpath[] = "p2pcert.cert";
    
    pass.local.rdonly = 1;
    pass.remote.rdonly = 1;
    pass.certpath = certpath;
    pass.keypath = keypath;
    pass.args = NULL;
    pass.handler = process_message;

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
    
#define MSG "hellow"
#define MSGL (sizeof(MSG) - 1)

    char msg[sizeof(p67_pdp_urg_hdr_t) + MSGL];

    if(p67_pdp_generate_urg_for_msg(MSG, MSGL, msg, sizeof(msg), 0) == NULL) {
        err = p67_err_einval;
        goto end;
    }

    unsigned char * res;
    int resl;
    
    if((err = p67_pdp_write_urg(
                &pass.remote, msg, sizeof(msg), 0, &sigterm, (void **)&res, &resl)) != 0)
        goto end; 

    if((err = p67_mutex_wait_for_change(&sigterm, P67_PDP_EVT_NONE, -1)) != 0)
        goto end;

    if(sigterm == P67_PDP_EVT_GOT_ACK) {
        p67_dml_pretty_print(res, resl);
        free(res);
    } else {
        char buff[32];
        printf("\nFinished with status: %s.\n", 
            p67_pdp_evt_str(buff, sizeof(buff), sigterm));
    }

    getchar();

    err = p67_net_async_terminate(&pass);

end:
    if(err != 0) p67_err_print_err("Error[s] occurred in main: ", err);
    p67_lib_free();
    if(err == 0) return 0; else return 2;
}
