#include <p67/p67.h>


/*
    core cert testing 
        - [*] certificates, 
        - [*] key pairs
*/
 
int
main(int argc, const char ** argv)
{
    p67_err err;

    const char * dcert = "p2pcert";
    const char * daddr = "127.0.0.1";

    const char * dcp, * dap;

    if(argc > 2) {
        //printf("Warn: usage: ./gencert [path] [address].\n");
        dcp = argv[1];
        dap = argv[2]; 
    } else {
        dcp = dcert;
        dap = daddr; 
    }

    printf("Generating certificates at %s, with CN set to %s\n", dcp, dap);

    if((err = p67_cert_new_cert(dcp, dap)) != 0) {
        p67_err_print_err(NULL, err);
        return 2;
    }
    return 0;
}
