#include <stdlib.h>
#include <alloca.h>
#include <unistd.h>
#include <fcntl.h>
#include <signal.h>

#include <p67/all.h>

/*
    core networking integration testing
*/

static p67_err
process_message(p67_addr_t * addr, p67_pckt_t * msg, int msgl, void * args)
{
    p67_log("%s:%s says: %.*s\n", addr->hostname, addr->service, msgl, msg);
    return 0;
}

static p67_thread_sm_t 
    connect_sm = P67_THREAD_SM_INITIALIZER, 
    listen_sm = P67_THREAD_SM_INITIALIZER;
p67_addr_t * remote_addr = NULL;

static void
finish(int a)
{
    printf("Graceful exit\n");
    
    p67_net_listen_terminate(&listen_sm);
    p67_net_connect_terminate(&connect_sm);
    p67_addr_free(remote_addr);
    p67_lib_free();
    p67_log_restore_echo_canon();
    if(a == SIGINT) exit(0);
    else raise(a);
}

int
main(int argc, char ** argv)
{
    p67_lib_init();
    p67_net_config.shutdown_after_inactive = 0;
    signal(SIGINT, finish);
    
    if(argc < 3) {
        printf("Usage: %s [source port] [dest addr]\n", argv[0]);
        return 2;
    }

    p67_err err = 0;
    p67_addr_t * local_addr;
    p67_net_cb_ctx_t cbctx = {
        .args = NULL,
        .cb = process_message,
        .free_args = NULL,
        .gen_args = NULL
    };
    p67_net_cred_t * cred;
    p67_async_t sig = P67_NET_CONNECT_SIG_UNSPEC;  

    if(!(local_addr = p67_addr_new_localhost4_udp(argv[1])))
        goto end;
    if(!(remote_addr = p67_addr_new_parse_str_udp(argv[2])))
        goto end;
    if(!(cred = p67_net_cred_create("p2pcert", "p2pcert.cert")))
        goto end;

    err |= p67_net_start_connect(
            &connect_sm, &sig, local_addr, remote_addr, cred, cbctx, NULL);
    err |= p67_net_start_listen(
            &listen_sm, local_addr, cred, cbctx, NULL);

    if(err) goto end;

    p67_addr_free(local_addr);
    p67_net_cred_free(cred);

    p67_mutex_wait_for_change(&sig, P67_NET_CONNECT_SIG_UNSPEC, -1);

    if(err) goto end;

    /* switch to terminal logging style */
    p67_log_cb = p67_log_cb_term;
    const char * buff;
    int len = 0;
    while(1) {

        while(!(buff = p67_log_read_term(&len, NULL)));

        if((err = p67_net_write_msg(remote_addr, (unsigned char *)buff, len)) != 0)
            p67_err_print_err("couldnt write: ", err);
    }

end:
    if(err != 0) p67_err_print_err("Main: ", err);
    finish(SIGINT);
}
