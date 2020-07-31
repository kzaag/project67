#include <stdio.h>
#include <stdlib.h>
#include <p67/p67.h>
#include <string.h>
#include <limits.h>

#include "bwt.h"
#include "err.h"
#include "db.h"
#include "rserver.h"

#define T_YELLOW "\033[33m"
#define T_WHITE "\033[0m"

void
init(void)
{
    p67_lib_init();
    p67_net_config_val.c_auth = P67_NET_C_AUTH_TRUST_UNKOWN;
}

p67rs_err
init_conn_pass(p67_conn_pass_t * pass)
{
    p67rs_err err;
    pass->certpath = "test/p2pcert.cert";
    pass->keypath = "test/p2pcert";
    pass->local.rdonly = 1;
    pass->remote.rdonly = 1;
    if((err = p67_addr_set_localhost4_udp(&pass->local, "10000")) != 0)
        return err;
    return 0;
}

p67rs_err
init_server(p67rs_server_t * server)
{
    p67rs_err err;

    if((err = p67rs_db_ctx_create_from_dp_config(&server->db_ctx, "main.conf")) != 0)
        return err;

    // if((err = p67rs_db_user_delete(server->db_ctx, NULL)) != 0)
    //     return err;

    // p67rs_db_user_t user;
    // user.u_name = "test";
    // user.pass_cstr = "test";

    // if((err = p67rs_db_user_create(server->db_ctx, &user)) != 0)
    //     return err;

    if((err = p67rs_usermap_create(&server->usermap, -1)) != 0)
        return err;

    return 0;
}

int 
main(void)
{
    p67rs_err err;
    p67_conn_pass_t pass = P67_CONN_PASS_INITIALIZER;
    p67rs_server_t server;
    
    init();
    if((err = init_conn_pass(&pass)) != 0)
        goto end;

    if((err = init_server(&server)) != 0)
        goto end;

    p67rs_server_setup_pass(&pass, &server);

    if((err = p67_net_start_listen(&pass)) != 0) goto end;

    getchar();
    
end:
    p67_lib_free();
    if(err != 0) p67rs_err_print_err("terminating main thread with error/s: ", err);
    return err == 0 ? 0 : 2;
}
