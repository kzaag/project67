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
    p67_hashcntl_free(cmdbuf);
    p67_addr_free(cmdctx.conn_ctx.local_addr);
    p67_addr_free(cmdctx.conn_ctx.remote_addr);
    p67_thread_sm_terminate(
        &cmdctx.conn_ctx.connect_tsm, 500);
    p67_lib_free();
    raise(sig);
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
    cmdctx.conn_ctx.cb = p67_dml_handle_msg;
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

        printf("> ");

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
