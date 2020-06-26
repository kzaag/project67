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
        ERR_print_errors_fp(stderr);
    }

    if((err & p67_err_eerrno) && errno != 0) {
        fprintf(stderr, "errno: %s\n", strerror(errno));
    }

    if(err & p67_err_einval) {
        fprintf(stderr, "Invalid argument\n");
    }

    if(err & p67_err_eaconn) {
        fprintf(stderr, "Already connected\n");
    }

    if(err & p67_err_enconn) {
        fprintf(stderr, "Connection gone\n");
    }

    if(err & p67_err_enetdb) {
        fprintf(stderr, "Couldnt obtain address information\n");
    }
}
