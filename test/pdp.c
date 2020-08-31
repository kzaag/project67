#include <p67/p67.h>
#include <stdlib.h>
#include <alloca.h>
#include <string.h>

static p67_err
process_message(p67_addr_t * addr, p67_pckt_t * msg, int msgl, void * args)
{
    p67_dml_pretty_print("process message: ", msg, msgl);
    return p67_dml_handle_msg(addr, msg, msgl, NULL);
}

p67_addr_t * remote_addr = NULL;
static p67_thread_sm_t 
    connect_sm = P67_THREAD_SM_INITIALIZER, 
    listen_sm = P67_THREAD_SM_INITIALIZER;
p67_async_t connect_sig = P67_NET_CONNECT_SIG_UNSPEC;

static void
finish(int a)
{
    printf("Graceful exit\n");
    p67_net_listen_terminate(&listen_sm);
    p67_net_connect_terminate(&connect_sm);
    p67_addr_free(remote_addr);
    p67_lib_free();
    if(a != SIGINT) {
        raise(a);
    } else {
        exit(0);
    }
}

static p67_err
do_connect_and_listen(int argc, const char ** argv)
{
    if(argc < 3)
        return p67_err_einval;
    p67_addr_t * local_addr = p67_addr_new_localhost4_udp(argv[1]);
    remote_addr = p67_addr_new_parse_str_udp(argv[2]);
    p67_net_cb_ctx_t cbctx = p67_net_cb_ctx_initializer(process_message);
    p67_net_cred_t * cred = p67_net_cred_create("p2pcert", "p2pcert.cert");
    if(!local_addr || !remote_addr || !cred) {
        p67_addr_free(local_addr);
        p67_addr_free(remote_addr);
        p67_net_cred_free(cred);
        return p67_err_eerrno | p67_err_einval;
    }
    p67_err err = 0;

    err |= p67_net_start_connect(
        &connect_sm, &connect_sig, local_addr, remote_addr, cred, cbctx, NULL);
    err |= p67_net_start_listen(&listen_sm, local_addr, cred, cbctx, NULL);
    
    p67_addr_free(local_addr);
    p67_net_cred_free(cred);

    return err;
}

int
main(int argc, const char ** argv)
{
    p67_lib_init();
    signal(SIGINT, finish);

    p67_err err;
    
    if(argc < 3) {
        printf("Usage: ./p67corenet [source port] [dest host:port]\n");
        return 2;
    }

    if((err = do_connect_and_listen(argc, argv)))
        goto end;

    p67_net_connect_sig_wait_for_connect(connect_sig);
    
    p67_async_t psig = 0, psig2 = 0;
    char payload[] = "hello";
    char payload2[] = "world";
    p67_pdp_ack_hdr_t ack, ack2;
    int ackix = sizeof(p67_pdp_ack_hdr_t), ackix2 = sizeof(p67_pdp_ack_hdr_t);
    char errbuff[32];

    char msg[sizeof(p67_pdp_urg_hdr_t) + sizeof(payload)];

    const int ccount = 10000;
    int count = ccount;

    p67_cmn_epoch_t start, end;
    p67_cmn_epoch_t tstart, tend;

    p67_cmn_epoch_micro(&tstart);

    while(count-->0) {
        psig = 0;
        psig2 = 0;

        p67_cmn_epoch_micro(&start);

        if(p67_pdp_generate_urg_for_msg(
                payload, sizeof(payload), msg, sizeof(msg), 1) == NULL) {
            err = p67_err_einval;
            goto end;
        }
        
        if((err = p67_pdp_write_urg(
                    remote_addr, 
                    msg, sizeof(msg), 
                    0, &psig, 
                    (void *)&ack, &ackix)) != 0)
            goto end;

        if(p67_pdp_generate_urg_for_msg(
                    payload2, sizeof(payload), msg, sizeof(msg), 2) == NULL) {
            err = p67_err_einval;
            goto end;
        }
        
        if((err = p67_pdp_write_urg(
                    remote_addr, 
                    msg, sizeof(msg), 
                    0, &psig2, 
                    (void *)&ack2, &ackix2)) != 0)
            goto end;

        if((err = p67_mutex_wait_for_change(&psig, P67_PDP_EVT_NONE, -1)) != 0)
            goto end;
        if((err = p67_mutex_wait_for_change(&psig2, P67_PDP_EVT_NONE, -1)) != 0)
            goto end;

        if(psig == P67_PDP_EVT_GOT_ACK) {
            p67_dml_pretty_print("Main: ", (unsigned char *)&ack, ackix);
        } else {
            printf("\n1: Finished with status: %s.\n", 
                p67_pdp_evt_str(errbuff, sizeof(errbuff), psig));
        }

        if(psig2 == P67_PDP_EVT_GOT_ACK) {
            p67_dml_pretty_print("Main: ", (unsigned char *)&ack2, ackix2);
        } else {
            printf("\n2: Finished with status: %s.\n", 
                p67_pdp_evt_str(errbuff, sizeof(errbuff), psig2));
        }

        p67_cmn_epoch_micro(&end);
        printf("One done in %llu %s\n", end - start, P67_CMN_MICROSEC);
        //getchar();
    }


    p67_cmn_epoch_micro(&tend);

    printf("All done in %llu %s avg is %llu %s per iteration.\n", 
        tend - tstart, P67_CMN_MICROSEC,
        (tend - tstart) / (ccount), P67_CMN_MICROSEC);
    
    getchar();

end:
    if(err != 0) p67_err_print_err("Error[s] occurred in main: ", err);
    finish(SIGINT);
    if(err == 0) return 0; else return 2;
}
