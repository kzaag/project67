
#include "err.h"
#include "db.h"
#include "ws.h"

#include <signal.h>
#include <p67/p67.h>

static int main_initialized = 0;
static p67_ws_ctx_t main_wsctx = {0};
static p67_thread_sm_t listener = P67_THREAD_SM_INITIALIZER;

void
main_finish(int sig)
{
    if(sig == SIGINT) {

        if(main_initialized) {
            p67_net_listen_terminate(&listener);
            p67_hashcntl_free(main_wsctx.user_nchix);
            p67_lib_free();
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

    err = p67_ws_user_nchix_create(&main_wsctx.user_nchix, 0);
    if(err != 0) {
        p67_err_print_err("Couldnt intiialize user_nchix. err was: ", err);
        exit(2);
    }

    p67_net_cred_t * cred 
        = p67_net_cred_create("test/p2pcert", "test/p2pcert.cert");

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

    p67_net_cb_ctx_t cbctx = p67_ws_get_cb_ctx(&main_wsctx);

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