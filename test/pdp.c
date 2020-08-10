#include <p67/p67.h>
#include <stdlib.h>
#include <alloca.h>
#include <string.h>

p67_err
process_message(p67_addr_t * addr, p67_pckt_t * msg, int msgl, void * args)
{
    p67_dml_pretty_print("process message: ", msg, msgl);
    return p67_dml_handle_msg(addr, msg, msgl, NULL);
}

p67_conn_ctx_t ctx = {
    .cb = process_message,
    .keypath = "p2pcert",
    .certpath = "p2pcert.cert",
    .local_addr = NULL,
    .remote_addr = NULL
};

void
finish(int a)
{
    p67_thread_sm_terminate(&ctx.listen_tsm, 500);
    p67_thread_sm_terminate(&ctx.connect_tsm, 500);
    p67_addr_free(ctx.local_addr);
    p67_addr_free(ctx.remote_addr);
    p67_lib_free();
    if(a != SIGINT) {
        raise(a);
    } else {
        exit(0);
    }
}

int
main(int argc, char ** argv)
{
    p67_lib_init();
    signal(SIGINT, finish);

    p67_err err;
    
    if(argc < 3) {
        printf("Usage: ./p67corenet [source port] [dest port]\n");
        return 2;
    }

    const char * remote_ip = IP4_LO1;

    ctx.local_addr = p67_addr_new();
    ctx.remote_addr = p67_addr_new();

    if(!ctx.local_addr || !ctx.remote_addr)
        return 2;

    if((err = p67_addr_set_localhost4_udp(ctx.local_addr, argv[1])) != 0)
        goto end;

    if((err = p67_addr_set_host_udp(ctx.remote_addr, remote_ip, argv[2])))
        goto end;

    if((err = p67_conn_ctx_start_listen(&ctx)) != 0)
        goto end;
    if((err = p67_conn_ctx_start_persist_connect(&ctx)) != 0)
        goto end;

    getchar();
    
    p67_async_t psig = 0, psig2 = 0;
    char payload[] = "hello";
    char payload2[] = "world";
    p67_pdp_ack_hdr_t ack, ack2;
    int ackix = sizeof(p67_pdp_ack_hdr_t), ackix2 = sizeof(p67_pdp_ack_hdr_t);
    char errbuff[32];

    char msg[sizeof(p67_pdp_urg_hdr_t) + sizeof(payload)];

    int count = 10000;

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
                    ctx.remote_addr, 
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
                    ctx.remote_addr, 
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

    printf("All done in %llu %s\n", tend - tstart, P67_CMN_MICROSEC);
    
    getchar();

end:
    if(err != 0) p67_err_print_err("Error[s] occurred in main: ", err);
    finish(SIGINT);
    if(err == 0) return 0; else return 2;
}
