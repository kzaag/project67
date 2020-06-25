#include <p67/err.h>
#include <p67/client.h>
#include <p67/sfd.h>
#include <stdio.h>
#include <unistd.h>
#include <strings.h>

int
main(void)
{
    p67_err err;
    p67_addr_t addr;
    
    err = 0;

    if((err = p67_addr_set_host(&addr, "aimat.pl", "443")) != 0) {
        goto end;
    }

    if((err = p67_client_connect(&addr, "chain.pem")) != 0) {
        goto end;
    }
    
    if((err = p67_client_connect(&addr, "chain.pem")) != 0) {
        goto end;
    }

end:

    if(err != 0)
        p67_err_print_err(err);

    p67_addr_free(&addr);
    p67_conn_free_all();

    if(err == 0)
        return 0;
    else
        return 2;
}