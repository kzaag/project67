#include <signal.h>
#include <stdio.h>

#include <client/cli/p2p.h>
#include <client/cli/cmd.h>
#include <p67/all.h>

static p67_hashcntl_t * cmdbuf = NULL;
static p67_cmd_ctx_t cmdctx = {0};
static p67_thread_sm_t 
    connect_sm = P67_THREAD_SM_INITIALIZER, 
    listen_sm = P67_THREAD_SM_INITIALIZER;
static p67_pdp_keepalive_ctx_t ws_keepalive_ctx = {0};

P67_CMN_NO_PROTO_ENTER
void
finish(
P67_CMN_NO_PROTO_EXIT
    int sig)
{
    if(sig == SIGINT) {
        p67_log("Cleanup\n");
        p67_pdp_free_keepalive_ctx(&ws_keepalive_ctx);
        p67_net_listen_terminate(&listen_sm);
        p67_net_connect_terminate(&connect_sm);
        p67_hashcntl_free(cmdbuf);
        p67_cmd_ctx_free(&cmdctx);
        p67_lib_free();
        exit(0);
    }
    raise(sig);
}

const char * str_empty = "";
const char * str_anon = "anon";

P67_CMN_NO_PROTO_ENTER
p67_err
p67_handle_call_request(
P67_CMN_NO_PROTO_EXIT
    p67_addr_t * const server_addr,
    p67_pckt_t * const msg, const int msgl)
{
    const p67_pckt_t * msgp = msg + sizeof(p67_pdp_urg_hdr_t);
    const p67_tlv_header_t * tlv_hdr;
    const p67_pckt_t * tlv_value;
    p67_addr_t * src_addr;
    const char * src_host, * src_svc;
    const char * src_message = NULL, * src_username = NULL;
    int msgpl = msgl - sizeof(p67_pdp_urg_hdr_t);
    p67_err err;
    
    while((err = p67_tlv_next(&msgp, &msgpl, &tlv_hdr, &tlv_value)) == 0) {
        switch(tlv_hdr->tlv_key[0]) {
        case 'p':
            src_svc = p67_tlv_get_cstr(tlv_hdr, tlv_value);
            if(!src_svc) return p67_err_etlvf;
            break;
        case 'a':
            src_host = p67_tlv_get_cstr(tlv_hdr, tlv_value);
            if(!src_host) return p67_err_etlvf;
            break;
        case 'm':
            src_message = p67_tlv_get_cstr(tlv_hdr, tlv_value);
            if(!src_message) return p67_err_etlvf;
            break;
        case 'u':
            src_username = p67_tlv_get_cstr(tlv_hdr, tlv_value);
            if(!src_username) return p67_err_etlvf;
            break;
        }
    }

    if(err != p67_err_eot || !src_svc || !src_host)
        return err;

    if(!src_message)
        src_message = str_empty;
    if(!src_username)
        src_username = str_anon;

    if(!(src_addr = p67_addr_new_host_udp(src_host, src_svc))) {
        err = p67_err_einval | p67_err_eerrno;
        return err;
    }

    p67_log("Incoming call from: \"%s\" (%s:%s) with message: \"%s\"\n",
        src_username, 
        src_addr->hostname, 
        src_addr->service,
        src_message);

    if((err = p67_pdp_write_pack(server_addr, (p67_pdp_urg_hdr_t *)msg))) {
        p67_addr_free(src_addr);
        return err;
    }

    if(!p67_p2p_cache_add(server_addr, (unsigned char *)src_username, strlen(src_username))) {
        err = p67_err_einval;
        p67_addr_free(src_addr);
        return err;
    }

    p67_addr_free(src_addr);
    
    return 0;
}

P67_CMN_NO_PROTO_ENTER
p67_err
webserver_callback(
P67_CMN_NO_PROTO_EXIT
    p67_addr_t * addr, p67_pckt_t * msg, int msgl, void * args)
{
    p67_err err;
    const p67_dml_hdr_store_t * hs = p67_dml_parse_hdr(msg, msgl, NULL);
    if(!hs) return p67_err_einval;
    if(hs->cmn.cmn_stp != P67_DML_STP_PDP_URG) {
        return p67_dml_handle_msg(addr, msg, msgl, args);
    }

    switch(hs->urg.urg_utp) {
    case 'c':
        /* handle incoming call */
        if((err = p67_handle_call_request(addr, msg, msgl)) == 0) {
            return 0;
        } else {
            p67_err_print_err("handle call terminated with error/s: ", err);
        }
        break;
    default:
        break;
    }

    return p67_dml_handle_msg(addr, msg, msgl, args);
}

int
main(int argc, char ** argv)
{
    if(argc < 3) {
        printf("Usage: %s [source port] [dest host:port]\n", argv[0]);
        return 2;
    }

    p67_lib_init();
    signal(SIGINT, finish);
    p67_log_cb = p67_log_cb_terminal;
    
    p67_err err;
    
    p67_net_cred_t * cred 
        = p67_net_cred_create("p2pcert", "p2pcert.cert");
    p67_net_cb_ctx_t cbctx = p67_net_cb_ctx_initializer(webserver_callback);
    p67_addr_t * local_addr = p67_addr_new_localhost4_udp(argv[1]);
    p67_addr_t * ws_addr = p67_addr_new_parse_str_udp(argv[2]);

    if(!cred || !local_addr || !ws_addr) {
        err = p67_err_einval | p67_err_eerrno;
        goto end;
    }

    if((err = p67_net_start_listen(&listen_sm, local_addr, cred, cbctx, NULL)))
        goto end;
    if((err = p67_net_start_connect(
            &connect_sm, NULL, local_addr, ws_addr, cred, cbctx, NULL)))
        goto end;
    
    ws_keepalive_ctx.addr = p67_addr_ref_cpy(ws_addr);
    if((err = p67_pdp_start_keepalive_loop(&ws_keepalive_ctx)) != 0) goto end;

    cmdctx.cred = cred;
    cmdctx.local_addr = local_addr;
    cmdctx.ws_remote_addr = ws_addr;

    if((err = p67_cert_trust_address(ws_addr, "p2pcert.cert")))
        goto end;

    cmdbuf = p67_cmd_new();
    if(!cmdbuf) {
        err = p67_err_eerrno;
        goto end;
    }

    char n[120];
    char ** _argv;
    char * argvbuf;
    size_t nl, i, j, lv, _argvl = 0, argvbufl = 0;
    int _argc, argvbufix = 0, offset, rd;
    char tmp;

    while(1) {
       
        nl = 0;

        printf("\r> ");

        while((tmp = getchar()) != EOF && tmp != '\n') {
            if(nl >= (sizeof(n) - 1))
                break;
            n[nl++] = tmp;
        }

        if(nl < 1)
            continue;
        
        rd = 0;
        _argc = 0;

        for(i = 0; i < nl; i++) {
            if(rd && ((n[i] == ' ') || (i == nl - 1))) {
                _argc++;
                rd = 0;
            } else if(n[i] != ' ') {
                rd = 1;
                if(i == nl - 1)
                    i--;
            } else {
                rd = 0;
            }
        }

        _argvl = sizeof(void *)*_argc;
        _argv = malloc(_argvl);
        argvbufl = nl + _argc;
        argvbuf = malloc(argvbufl);
        
        if(!_argv || !argvbuf) {
            err = p67_err_eerrno;
            goto end;
        }

        argvbufix = 0;
        rd = 0;
        j = 0;

        for(i = 0; i < nl; i++) {
            if(rd && ((n[i] == ' ') || (i == nl - 1))) {
                if(n[i] == ' ') offset = 1;
                else offset = 0;
                _argv[j++] = argvbuf+argvbufix;
                memcpy(argvbuf+argvbufix, n+lv, i + 1 - offset - lv);
                argvbufix+= i + 1 - offset - lv;
                argvbuf[argvbufix++] = '\0';
                rd = 0;
            } else if(n[i] != ' ') {
                if(!rd) {
                    rd = 1;
                    lv = i;
                }
                if(i == nl - 1)
                    i--;
            } else {
                rd = 0;
            }
        }

        p67_cmd_execute(cmdbuf, &cmdctx, _argc, _argv);

        free(_argv);
        free(argvbuf);

        // if((err = call(&pass)) != 0) {
        //     p67_err_print_err("call: ", err);
        // }
    }

end:
    if(err != 0) p67_err_print_err("Main: ", err);
    raise(SIGINT);
}
