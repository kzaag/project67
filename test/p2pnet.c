#include <stdlib.h>
#include <alloca.h>
#include <unistd.h>
#include <fcntl.h>

#include <p67/all.h>

/*
    communication with N hosts.
*/

static p67_err
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
struct {
    p67_thread_sm_t connect_sm;
    p67_async_t sig;
    p67_pdp_keepalive_ctx_t keepalive_ctx;
} conn_ctx[conn_ctx_length];
int conn_ctx_ix = 0;
p67_thread_sm_t listen_sm = P67_THREAD_SM_INITIALIZER;
p67_addr_t * local_addr = NULL;
p67_net_cb_ctx_t cbctx = {
    .args = NULL,
    .cb = process_message,
    .free_args = NULL,
    .gen_args = NULL
};
p67_net_cred_t * cred = NULL;

static void
finish(int a)
{
    int i = 0;

    printf("Graceful exit\n");
    
    p67_net_listen_terminate(&listen_sm);
    p67_addr_free(local_addr);
    p67_net_cred_free(cred);

    for(i = 0; i < conn_ctx_ix; i++) {
        p67_pdp_free_keepalive_ctx(&conn_ctx[i].keepalive_ctx);
        p67_net_connect_terminate(&conn_ctx[i].connect_sm);
    }
    
    p67_lib_free();
    if(a == SIGINT) exit(0);
    else raise(a);
}

static p67_err
init_listener(const char * svc)
{
    p67_err err = p67_err_eerrno;
    
    local_addr = p67_addr_new_localhost4_udp(svc);
    if(!local_addr) goto end;
    cred = p67_net_cred_create("p2pcert", "p2pcert.cert");
    if(!cred) goto end;
    err = p67_net_start_listen(&listen_sm, local_addr, cred, cbctx, NULL);
end:
    return err;
}

/* this is not thread safe */
static p67_err
add_peer(const char * addrcstr)
{
    if(conn_ctx_ix >= conn_ctx_length) {
        return p67_err_enomem;
    }
    
    p67_addr_t * remote_addr;
    p67_err err;
    
    remote_addr = p67_addr_new_parse_str_udp(addrcstr);
    if(!remote_addr) return p67_err_einval | p67_err_eerrno;
    
    err = p67_net_start_connect(
        &conn_ctx[conn_ctx_ix].connect_sm,
        NULL,
        local_addr,
        remote_addr,
        cred,
        cbctx,
        NULL);
    
    if(err) {
        p67_addr_free(remote_addr);
        return err;
    }

    conn_ctx[conn_ctx_ix].keepalive_ctx.addr 
        = p67_addr_ref_cpy(remote_addr);

    err = p67_pdp_start_keepalive_loop(
        &conn_ctx[conn_ctx_ix].keepalive_ctx);
    if(err) {
        p67_net_connect_terminate(&conn_ctx[conn_ctx_ix].connect_sm);
        p67_addr_free(remote_addr);
        p67_pdp_free_keepalive_ctx(&conn_ctx[conn_ctx_ix].keepalive_ctx);
        return err;
    }

    conn_ctx_ix++;

    return 0;
}

int
main(int argc, char ** argv)
{
    if(argc < 2) {
        printf("Usage: %s [source port]\n", argv[0]);
        return 2;
    }

    p67_lib_init();
    p67_log_cb = p67_log_cb_term;
    signal(SIGINT, finish);

    //char b[32];
    p67_err err = p67_err_eerrno;
    p67_hashcntl_t * nodes = p67_node_cache();
    p67_hashcntl_entry_t * entry;
    p67_node_t * node_entry;
    int i;
    
    const int __buffl = 72;
    unsigned char __buff[__buffl];
    /* 
        have some space allocated on the left side of buffer
        so we can write network header into it 
        without having to copy whole buffer.
    */
    const int noffset = sizeof(p67_pdp_urg_hdr_t);
    const int buffl = __buffl - noffset;
    const char * buff = (char *)__buff + noffset;
    int ix = 0;

    if((err = init_listener(argv[1]))) goto end;


    while(1) {
        ix = buffl-1;
        while(!(buff = p67_log_read_term(&ix, NULL, 0)));

        switch(buff[0]) {
            case '\0':
                break;
            case ':':
                /* command mode */
                if(ix > 3 && buff[1] == 'c' && buff[2] == ' ') {
                    if((err = add_peer((char *)buff+3))) {
                        p67_err_print_err("Couldnt add connection: ", err);
                    }
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
