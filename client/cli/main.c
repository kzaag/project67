#include <signal.h>
#include <stdio.h>

#include <p67/all.h>

#include <client/cli/node.h>
#include <client/cli/call.h>
#include <client/cli/cmd.h>

static p67_hashcntl_t * cmdbuf = NULL;
static p67_cmd_ctx_t cmdctx = {0};
static p67_thread_sm_t listen_sm = P67_THREAD_SM_INITIALIZER;
int cmd_last_exit_code = 0;
p67_thread_sm_t cmdsm = P67_THREAD_SM_INITIALIZER;
const int connect_to = 300;

p67_async_t cleanlock = 0;
int is_cleanup = 0;

P67_CMN_NO_PROTO_ENTER
void
finish(
P67_CMN_NO_PROTO_EXIT
    int sig)
{
    /*
        on sigint only exit application if no commands are running, else just kill command
    */
    if(sig != SIGINT) {
        raise(sig);
        return;
    }

    p67_err err;
    /*
        if command needs to cleanup after sigint, then it should handle state change in specified time,
        after which it will be terminated.
    */
    err = p67_thread_sm_terminate(&cmdsm, 500);
    if(err == 0 || err == p67_err_etime) {
        return;
    }

    if(cmdsm.state != P67_THREAD_SM_STATE_STOP) {
        return;
    }

    p67_mutex_lock(&cleanlock);
    
    if(is_cleanup) {
        return;
    }
    is_cleanup = 1;

    p67_log("Interrupt\n");

    p67_net_listen_terminate(&listen_sm);

    p67_lib_free();

    p67_hashcntl_free(cmdbuf);
    p67_cmd_ctx_free(&cmdctx);

    p67_mutex_unlock(&cleanlock);
    p67_log_restore_echo_canon();

    exit(0);
}

const char * str_empty = "";
const char * str_anon = "anon";
const int str_anon_l = 4;

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
    int msgpl = msgl - sizeof(p67_pdp_urg_hdr_t), usernamel;
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
            usernamel = tlv_hdr->tlv_vlength - 1; // vlength include null terminator
            if(!src_username) return p67_err_etlvf;
            break;
        }
    }

    if(err != p67_err_eot || !src_svc || !src_host)
        return err;

    if(!src_message)
        src_message = str_empty;
    if(!src_username) {
        src_username = str_anon;
        usernamel = str_anon_l;
    }

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

    err = p67_call_add_pending(
        server_addr, 
        src_addr, 
        src_username, 
        usernamel, 
        (p67_pdp_urg_hdr_t *)msg);

    if(err) {
        p67_err_print_err_dbg("Couldnt add pending call, reason: ", err);
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

    //p67_dml_pretty_print_addr(addr, msg, msgl);

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

typedef struct cmd_run_ctx {
    int argc;
    char ** argv;
} cmd_run_ctx_t;

/*
    you cant free args!
*/
P67_CMN_NO_PROTO_ENTER
void *
cmd_run(
P67_CMN_NO_PROTO_EXIT
    void * args)
{
    cmd_run_ctx_t * ctx = (cmd_run_ctx_t *)args;

    cmd_last_exit_code = p67_cmd_execute(cmdbuf, &cmdctx, ctx->argc, ctx->argv);
    
    if(cmdctx.tsm->state != P67_THREAD_SM_STATE_STOP) {
        p67_mutex_set_state(
            &cmdctx.tsm->state, 
            cmdctx.tsm->state, 
            P67_THREAD_SM_STATE_STOP);
    }

    return NULL;
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
    p67_log_cb = p67_log_cb_term;
    p67_net_config.conn_auth_type = P67_NET_AUTH_DONT_TRUST_UNKOWN;
    
    p67_err err;
    
    p67_net_cred_t * cred 
        = p67_net_cred_create("p2pcert", "p2pcert.cert");
    p67_addr_t * local_listen_addr = p67_addr_new_localhost4_udp(argv[1]);
    if(!cred || !local_listen_addr) {
        err = p67_err_einval | p67_err_eerrno;
        goto end;
    }

    /* handle all incoming connections with p2p handler. */
    if((err = p67_net_start_listen(
            &listen_sm, 
            local_listen_addr, 
            cred, 
            p67_ext_node_p2p_cb(), 
            NULL)))
        goto end;

    p67_addr_t * ws_addr = p67_addr_new_parse_str_udp(argv[2]);
    p67_net_cb_ctx_t server_cbctx = p67_net_cb_ctx_initializer(webserver_callback);
    if((err = p67_ext_node_insert_and_connect(
            ws_addr, "p2pcert.cert", "redirect/0", local_listen_addr, cred, server_cbctx)))
        goto end;

    cmdctx.cred = cred;
    cmdctx.local_addr = local_listen_addr;
    cmdctx.ws_remote_addr = ws_addr;
    cmdctx.p2p_cb_ctx = p67_ext_node_p2p_cb();

    cmdbuf = p67_cmd_new();
    if(!cmdbuf) {
        err = p67_err_eerrno | p67_err_einval;
        goto end;
    }

    size_t i;
    #define maxarg 32
    char * _argv[maxarg], * n;
    int reading_arg, nl, _argc, quote;

    while(1) {
        nl = 0;

        p67_log_set_term_char(p67_log_term_sgn_def);

        /*  return value wont be used by noone else anymore. 
            thats why i cast it to char * and modify it later */
        while(!(n = (char *)p67_log_read_term(&nl, &err, 0))) {
            p67_err_print_err(NULL, err);
        }

        if(nl < 1)
            continue;

        reading_arg = 0;
        _argc = 0;
        quote = 0;

        // since we are not using escape chars, we can parse arguments in-line.
        // without having to memcpy input buffer
        for(i = 0; i < nl; i++) {
            if(_argc == maxarg) {
                break;
            }
            if(!reading_arg) {
                switch(n[i]) {
                case '"':
                case '\'':
                    reading_arg = 1;
                    _argv[_argc++] = n+i+1;
                    quote = 1;
                    break;
                case ' ':
                    break;
                default:
                    reading_arg = 1;
                    _argv[_argc++] = n+i;
                    break;
                }
            } else {
                switch(n[i]) {
                case '"':
                case '\'':
                    if(quote) {
                        quote = 0;
                        if(n[i+1] == ' ' || n[i+1] == 0) {
                            reading_arg = 0;
                            n[i] = 0;
                        }
                    }
                    break;
                case ' ':
                    if(!quote) {
                        quote = 0;
                        reading_arg = 0;
                        n[i] = 0;
                    }
                    break;
                default:
                    break;
                }
            }
        }

        // for(i = 0; i < ptrarrix; i++) {
        //     printf("|%s|\n", ptrarr[i]);
        // }
        // continue;

        cmd_run_ctx_t c;
        c.argc = _argc;
        c.argv = _argv;
        cmdctx.tsm = &cmdsm;

        if((err = p67_thread_sm_start(&cmdsm, cmd_run, &c)) != 0) {
            p67_err_print_err("couldnt exec command: ", err);
        } else {
            if((err = p67_thread_sm_wait_for_exit(&cmdsm, -1)) != 0) {
                p67_err_print_err("couldnt await for command exit: ", err);
            }
        }
    }

end:
    if(err != 0) p67_err_print_err("Main: ", err);
    raise(SIGINT);
}
