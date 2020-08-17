#include <signal.h>
#include <stdio.h>

#include <p67/p67.h>

#include "cmd.h"

p67_hashcntl_t * cmdbuf = NULL;
p67_cmd_ctx_t cmdctx = {0};
p67_pdp_keepalive_ctx_t kctx = {0};

int
log_cb(const char * fmt, va_list list)
{
    printf("\r");
    vprintf(fmt, list);
    printf("> ");
    fflush(stdout);
}

void
finish(int sig)
{
    printf("Cleanup\n");

    p67_thread_sm_terminate(&kctx.th, 500);
    p67_thread_sm_terminate(
        &cmdctx.conn_ctx.connect_tsm, 500);
    p67_hashcntl_free(cmdbuf);
    p67_addr_free(cmdctx.conn_ctx.local_addr);
    p67_addr_free(cmdctx.conn_ctx.remote_addr);
    p67_lib_free();
    raise(sig);
}

const char * str_empty = "";
const char * str_anon = "anon";

p67_err
p67_handle_call_request(
    p67_addr_t * const server_addr,
    p67_pckt_t * const msg, const int msgl)
{
    const p67_pckt_t * msgp = msg + sizeof(p67_pdp_urg_hdr_t);
    const p67_tlv_header_t * tlv_hdr;
    const p67_pckt_t * tlv_value;

    p67_addr_t * src_addr;
    const char * src_message = NULL, * src_username = NULL;
    const p67_sockaddr_t * src_saddr = NULL;
    int msgpl = msgl - sizeof(p67_pdp_urg_hdr_t);
    p67_err err;
    uint16_t src_port = 0;
    uint8_t src_usernamel = 0, src_messagel = 0, src_saddrl = 0;
    

    while((err = p67_tlv_next(&msgp, &msgpl, &tlv_hdr, &tlv_value)) == 0) {
        switch(tlv_hdr->tlv_key[0]) {
        case 'p':
            if(tlv_hdr->tlv_vlength != sizeof(src_port))
                return p67_err_etlvf;
            src_port = p67_cmn_ntohs(*(uint16_t *)tlv_value);
            break;
        case 'a':
            src_saddr = (p67_sockaddr_t *)tlv_value;
            src_saddrl = tlv_hdr->tlv_vlength;
            break;
        case 'm':
            src_message = (char *)tlv_value;
            src_messagel = tlv_hdr->tlv_vlength;
            break;
        case 'u':
            src_username = (char *)tlv_value;
            src_usernamel = tlv_hdr->tlv_vlength;
            break;
        }
    }

    if(err != p67_err_eot || src_port == 0 || src_saddr == NULL)
        err;

    if(!src_message)
        src_message = str_empty;
    if(!src_username)
        src_username = str_anon;

    if(!(src_addr = p67_addr_new())) return p67_err_eerrno;
    if((err = p67_addr_set_sockaddr(src_addr, src_saddr, src_saddrl)) != 0) {
        free(src_addr);
        return err;
    }

    p67_log("Incoming call from: \"%.*s\" (%s:%s) with message: \"%.*s\"\n",
        src_usernamel,
        src_username, 
        src_addr->hostname, 
        src_addr->service,
        src_messagel,
        src_message);

    free(src_addr);

    /* right now always reject calls */
    return p67_web_tlv_respond_with_status(
        (p67_pdp_urg_hdr_t *)msg, server_addr, p67_web_status_forbidden);

    //return p67_dml_handle_msg(server_addr, msg, msgl, NULL);
}

p67_err
webserver_callback(
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
        printf("Usage: ./%s [source port] [dest port]\n", argv[0]);
        return 2;
    }

    p67_lib_init();
    p67_log_cb = log_cb;

    p67_err err;
    const char * keypath = "test/p2pcert";
    const char * certpath = "test/p2pcert.cert";
    const char * remote_ip = IP4_LO1;

    cmdctx.conn_ctx.certpath = (char *)certpath;
    cmdctx.conn_ctx.keypath = (char *)keypath;
    cmdctx.conn_ctx.cb = webserver_callback;
    cmdctx.conn_ctx.local_addr = p67_addr_new();
    cmdctx.conn_ctx.remote_addr = p67_addr_new();

    if((err = p67_addr_set_localhost4_udp(
                cmdctx.conn_ctx.local_addr, argv[1])) != 0)
        goto end;

    if((err = p67_addr_set_host_udp(
                cmdctx.conn_ctx.remote_addr, remote_ip, argv[2])))
        goto end;

    kctx.addr = cmdctx.conn_ctx.remote_addr;

    if((err = p67_conn_ctx_start_persist_connect(&cmdctx.conn_ctx)) != 0) goto end;

    if((err = p67_pdp_start_keepalive_loop(&kctx)) != 0) goto end;

    cmdbuf = p67_cmd_new();
    if(!cmdbuf) {
        err = p67_err_eerrno;
        goto end;
    }

    signal(SIGINT, finish);

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
    p67_lib_free();
    if(err == 0) return 0; else return 2;
}
