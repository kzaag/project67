#include "../lib/net.h"

#include <stdio.h>
#include <unistd.h>

int
main(void)
{
    p67_err err;
    p67_conn_t * conn;
    int c;

    if((conn = p67_conn_new()) == NULL) {
        p67_err_print_all();
        return 1;
    }

    if((err = p67_conn_connect(conn, "aimat.pl", "443", "chain.pem")) != 0) {
        p67_conn_free(conn);
        p67_err_print_err(err);
        return 1;
    }
        
    if((err = p67_conn_shutdown(conn)) != 0) {
        p67_conn_free(conn);
        p67_err_print_err(err);
        return 1;
    }

    p67_conn_free(conn);
        
    return 0;
}