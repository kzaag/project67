#include <signal.h>

#include <p67/all.h>
#include <server/err.h>
#include <server/ws.h>
#include <server/db.h>

static int main_initialized = 0;
static p67_hashcntl_t * login_user_cache = NULL;
static p67_thread_sm_t listener = P67_THREAD_SM_INITIALIZER;

P67_CMN_NO_PROTO_ENTER
static void
main_finish(
P67_CMN_NO_PROTO_EXIT
    int sig)
{
    printf("Graceful exit\n");

    if(sig == SIGINT) {

        if(main_initialized) {
            p67_net_listen_terminate(&listener);
            /* 
                first one has to free library ( and dispose sessions )
                then free user index. 
                Sessions use user index during cleanup
                TODO: to fix this neccesity one could use refcounting and make refcpys
                of user index for each session.
            */
            p67_lib_free();
            p67_hashcntl_free(login_user_cache);
            p67_db_free();
        }

        exit(0);
    } else {
        raise(sig);
    }
}

int
main(void)
{
    p67_lib_init();
    signal(SIGINT, main_finish);
    p67_net_config.conn_auth_type = P67_NET_AUTH_TRUST_UNKOWN;

    p67_ws_err err;

    p67_net_cred_t * cred 
        = p67_net_cred_create("p2pcert", "p2pcert.cert");
    if(!cred) {
        p67_log("Couldnt create cred.\n");
        exit(2);
    }

    p67_addr_t * local_addr = p67_addr_new_localhost4_udp("10000");
    if(!local_addr) {
        p67_log("Couldnt set up local address.\n");
        exit(2);
    }

    p67_timeout_t * tctx = NULL;
    if(!(tctx = p67_timeout_create(0, (p67_err *)&err))) {
        p67_err_print_err("Couldnt create timeout context. err was: ", err);
        exit(2);
    }

    p67_net_cb_ctx_t cbctx;

    if((err = p67_ws_create_cb_ctx(&cbctx))) {
        p67_err_print_err("Couldnt create callback context. err was: ", err);
        exit(2);
    }

    if((err = p67_net_start_listen(&listener, local_addr, cred, cbctx, tctx))) {
        p67_err_print_err("Couldnt start listener. err was: ", err);
        exit(2);
    }

    p67_timeout_free(tctx);
    p67_addr_free(local_addr);
    p67_net_cred_free(cred);

    main_initialized = 1;

    getchar();

    main_finish(SIGINT);

    return 0;
}