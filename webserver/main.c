
#include "err.h"
#include "db.h"
#include "ws.h"

#include <signal.h>
#include <p67/p67.h>

static int main_initialized = 0;
static p67_ws_ctx_t main_wsctx = {0};
static p67_conn_ctx_t main_connctx = {0};

void
main_finish(int sig)
{
    if(sig == SIGINT) {

        if(main_initialized) {
            p67_db_ctx_free(main_wsctx.db);
            p67_hashcntl_free(main_wsctx.user_nchix);
            p67_thread_sm_terminate(&main_connctx.listen_tsm, 1000);
            p67_addr_free(main_connctx.local_addr);
            p67_addr_free(main_connctx.remote_addr);
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
    p67_ws_err err;

    err = p67_db_ctx_create_from_dp_config(&main_wsctx.db, "main.conf");
    if(err != 0) {
        p67_ws_err_print_err("Couldnt intiialize db_ctx. err was: ", err);
        exit(2);
    }

    err = p67_ws_user_nchix_create(&main_wsctx.user_nchix, 0);
    if(err != 0) {
        p67_err_print_err("Couldnt intiialize user_nchix. err was: ", err);
        exit(2);
    }

    main_connctx.certpath = "test/p2pcert.cert";
    main_connctx.keypath = "test/p2pcert";
    main_connctx.local_addr = p67_addr_new();
    assert(main_connctx.local_addr);

    err = p67_addr_set_localhost4_udp(main_connctx.local_addr, "10000");
    if(err != 0) {
        p67_err_print_err("Couldnt set up local address. err was: ", err);
        exit(2);
    }

    p67_ws_setup_conn_ctx(&main_connctx, &main_wsctx);

    err = p67_conn_ctx_start_listen(&main_connctx);
    if(err != 0) {
        p67_err_print_err("Couldnt start listener. err was: ", err);
        exit(2);
    }

    main_initialized = 1;

    getchar();

    main_finish(SIGINT);

    return 0;
}