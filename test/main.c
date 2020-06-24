#include <p67/conn.h>
#include <p67/client.h>
#include <stdio.h>
#include <unistd.h>

int
main(void)
{
    p67_err err;
    p67_conn_t conn;
    int c;

    char * host = "aimat.pl";
    char * svc = "443";
    char * chain = "chain.pem";

    conn.trusted_chain = chain;
    conn.haddr.host = host;
    conn.haddr.service = svc;

    if((err = p67_client_connect(&conn)) != 0) {
        p67_err_print_err(err);
        return 2;
    }

    sleep(1);

    if((err = p67_client_disconnect(&conn)) != 0) {
        p67_conn_free(&conn);
        p67_err_print_err(err);
        return 2;
    }

    // if((err = p67_conn_connect(conn)) != 0) {
    //     p67_conn_free(conn);
    //     p67_err_print_err(err);
    //     return 1;
    // }
        
    // if((err = p67_conn_shutdown(conn)) != 0) {
    //     p67_conn_free(conn);
    //     p67_err_print_err(err);
    //     return 1;
    // }
        
    return 0;
}