#include <errno.h>
#include <openssl/err.h>
#include <string.h>
#include <stdio.h>

#include "err.h"

void
p67_err_print_err(p67_err err)
{
    if(err == p67_err_eok) {
        return;
    }

    if(err & p67_err_essl) {
        ERR_print_errors_fp(stdout);
    }

    if((err & p67_err_eerrno) && errno != 0) {
        printf("errno: %s\n", strerror(errno));
    }

    if(err & p67_err_einval) {
        printf("Invalid argument\n");
    }

    if(err & p67_err_eaconn) {
        printf("Already connected\n");
    }

    if(err & p67_err_enconn) {
        printf("Connection gone\n");
    }

    if(err & p67_err_enetdb) {
        printf("Couldnt obtain address info\n");
    }
}
