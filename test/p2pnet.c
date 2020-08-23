#include <p67/p67.h>
#include <stdlib.h>
#include <alloca.h>
#include <unistd.h>
#include <fcntl.h>

/*
    communication with N hosts.
*/

int
log_cb(const char * fmt, va_list list)
{
    printf("\r");
    vprintf(fmt, list);
    printf("> ");
    fflush(stdout);
}

p67_err
process_message(p67_addr_t * addr, p67_pckt_t * msg, int msgl, void * args)
{
    //p67_dml_pretty_print(NULL, msg, msgl);
    p67_pdp_urg_hdr_t * u;
    if((u = (p67_pdp_urg_hdr_t *)p67_dml_parse_hdr(msg, msgl, NULL))
            && u->urg_stp == P67_DML_STP_PDP_URG && msgl > sizeof(*u)) {
        p67_log(
            "%s:%s says: %.*s\n", 
            addr->hostname, addr->service, msgl-sizeof(*u), msg+sizeof(*u));
    }
    return p67_dml_handle_msg(addr, msg, msgl, NULL);
}

#define conn_ctx_length 10
p67_conn_ctx_t conn_ctx[conn_ctx_length] = {0};
int conn_ctx_ix = 0;
p67_conn_ctx_t listen_ctx = {
    .cb = process_message,
    .keypath = "p2pcert",
    .certpath = "p2pcert.cert",
    .local_addr = NULL,
    .listen_tsm = P67_THREAD_SM_INITIALIZER
};

void
finish(int a)
{
    int i = 0;

    printf("Graceful exit\n");

    p67_addr_free(listen_ctx.local_addr);
    p67_thread_sm_terminate(&listen_ctx.listen_tsm, 500);
    
    for(i = 0; i < conn_ctx_length; i++) {
        p67_thread_sm_terminate(&conn_ctx[i].keepalive_ctx.th, 500);
        p67_thread_sm_terminate(&conn_ctx[i].listen_tsm, 500);
        p67_thread_sm_terminate(&conn_ctx[i].connect_tsm, 500);
        p67_addr_free(conn_ctx[i].local_addr);
        p67_addr_free(conn_ctx[i].remote_addr);
    }
    
    p67_lib_free();
    if(a == SIGINT) exit(0);
    else raise(a);
}

int
main(int argc, char ** argv)
{
    p67_lib_init();
    p67_log_cb = log_cb;
    signal(SIGINT, finish);

    char b[32];
    p67_err err;
    p67_hashcntl_t * nodes = p67_conn_node_cache();
    p67_hashcntl_entry_t * entry;
    p67_node_t * node_entry;
    int i;
    
    const int __buffl = 72;
    char __buff[__buffl];
    /* 
        have some space allocated on the left side of buffer
        so we can write network header into it 
        without having to copy whole buffer.
    */
    const int noffset = sizeof(p67_pdp_urg_hdr_t);
    const int buffl = __buffl - noffset;
    char * buff = __buff + noffset;
    int ix = 0;

    if(argc < 2) {
        printf("Usage: ./%s [source port]\n", argv[0]);
        return 2;
    }

    if(!(listen_ctx.local_addr = p67_addr_new()))
        p67_cmn_ejmp(err, p67_err_eerrno, end);

    if((err = p67_addr_set_localhost4_udp(
            listen_ctx.local_addr, argv[1])))
        goto end;

    if((err = p67_conn_ctx_start_listen(&listen_ctx)) != 0)
        goto end;

    // if((err = p67_addr_parse_str(argv[2], ctx.remote_addr, P67_SFD_TP_DGRAM_UDP)) != 0)
    //     goto end;

    //     if((err = p67_conn_ctx_start_listen(&ctx)) != 0)
    //         goto end;
    //     if((err = p67_conn_ctx_start_persist_connect(&ctx)) != 0)
    //         goto end;

    while(1) {
        do {
            write(1, "> ", 3);
        } while((ix = read(0, buff, buffl-1)) <= 1);
        buff[ix-1] = 0;

        switch(buff[0]) {
            case '\0':
                break;
            case ':':
                /* command mode */
                if(ix > 3 && buff[1] == 'c' && buff[2] == ' ') {
                    //p67_log("connect to: %s %lu\n", buff+3, strlen(buff+3));
                    if(conn_ctx_ix >= conn_ctx_length) {
                        p67_log("too many connections\n");
                        break;
                    }
                    conn_ctx[conn_ctx_ix].local_addr 
                        = p67_addr_ref_cpy(listen_ctx.local_addr);
                    conn_ctx[conn_ctx_ix].remote_addr = p67_addr_new();
                    if((err = p67_addr_parse_str(
                                buff+3, 
                                conn_ctx[conn_ctx_ix].remote_addr, 
                                P67_SFD_TP_DGRAM_UDP)) != 0) {
                        p67_addr_free(conn_ctx[conn_ctx_ix].local_addr);
                        p67_addr_free(conn_ctx[conn_ctx_ix].remote_addr);
                        p67_err_print_err("Invalid address: ", err);
                        break;
                    }
                    conn_ctx[conn_ctx_ix].cb = process_message;
                    conn_ctx[conn_ctx_ix].certpath = listen_ctx.certpath;
                    conn_ctx[conn_ctx_ix].keypath = listen_ctx.keypath;
                    
                    err = p67_conn_ctx_start_connect(&conn_ctx[conn_ctx_ix]);
                    if(err) {
                        p67_addr_free(conn_ctx[conn_ctx_ix].local_addr);
                        p67_addr_free(conn_ctx[conn_ctx_ix].remote_addr);
                        p67_err_print_err("Couldnt connect: ", err);
                        break;
                    }

                    conn_ctx[conn_ctx_ix].keepalive_ctx.addr 
                            = conn_ctx[conn_ctx_ix].remote_addr;

                    err = p67_pdp_start_keepalive_loop(
                        &conn_ctx[conn_ctx_ix].keepalive_ctx);
                    if(err) {
                        p67_addr_free(conn_ctx[conn_ctx_ix].local_addr);
                        p67_addr_free(conn_ctx[conn_ctx_ix].remote_addr);
                        p67_err_print_err("Couldnt start keepalive: ", err);
                        break;
                    }

                    conn_ctx_ix++;
                } else {
                    p67_log("Couldnt match command\n");
                }
                break;
            default:
                p67_hashcntl_lock(nodes);
                /* write message to __all__ connected peers */
                for(i = 0; i < nodes->bufferl; i++) {
                    entry = nodes->buffer[i];
                    if(!entry) continue;
                    node_entry = (p67_node_t *)entry->value;
                    if(!p67_pdp_generate_urg_for_msg(NULL, 0, __buff, noffset, 0)) {
                        p67_log("couldnt generate urg header for message\n");
                        break;
                    }
                    if((err = p67_pdp_write_urg(
                                node_entry->trusted_addr, 
                                __buff, ix+noffset-1, 
                                1000, NULL, NULL, NULL)) != 0)
                        p67_log("couldnt write for %s:%s", 
                            node_entry->trusted_addr->hostname, 
                            node_entry->trusted_addr->service);
                        p67_err_print_err("couldnt write for err was: ", err);
                }
                p67_hashcntl_unlock(nodes);
        }

    }

    getchar();

end:
    if(err != 0) p67_err_print_err("Main: ", err);
    finish(SIGINT);
}
