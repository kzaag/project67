#include <p67/err.h>
#include <p67/client.h>
#include <p67/sfd.h>
#include <p67/server.h>
#include <p67/conn.h>

#include <stdio.h>
#include <time.h>
#include <unistd.h>
#include <strings.h>

int
msg_handler(p67_conn_t * conn, char * msg, int msgl, void * args)
{
    printf("%s:%s says: %*.*s\n", conn->addr.hostname, conn->addr.service, msgl, msgl, msg);
}


void
server(const char * port)
{
    p67_server_t * server;
    p67_err err;

    err = 0;

    if((server = p67_server_new()) == NULL) {
        goto end;
    }

    if((err = p67_addr_set_host(&server->addr, "127.0.0.1", port)) != 0) {
        goto end;
    }

    if((err = p67_server_set_cert(server, "server_cert.pem", "server_private_key")) != 0) {
        goto end;
    }

    if((err = p67_server_set_callback(server, msg_handler, NULL)) != 0) {
        goto end;
    }

    if((err = p67_server_start_listen(server)) != 0) {
        goto end;
    }

end:
    (void)1;
// end:
//     if(err != 0)
//         p67_err_print_err(err);
//     p67_server_free(server);
//     free(server);
}

void
client(const char * port)
{
    p67_err err;
    p67_addr_t addr;
    err = 0;

    if((err = p67_addr_set_host(&addr, "127.0.0.1", port)) != 0) {
        goto end;
    }

    if((err = p67_client_connect(&addr, "chain.pem")) != 0) {
        goto end;
    }

    if((err = p67_client_write_cstr(&addr, "hello world!")) != 0) {
        goto end;
    }

end:
    p67_err_print_all();

    if(err != 0)
        p67_err_print_err(err);

    p67_addr_free(&addr);
    p67_client_free_all();
}

int
main(int argc, char ** argv)
{
    if(argc > 1) {
        server("41999");
        getchar();
        client("41998");
        getchar();
    } else {
        server("41998");
        getchar();
        client("41999");
        getchar();
    }

    return 0;
}
