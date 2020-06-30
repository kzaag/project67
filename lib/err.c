#include <errno.h>
#include <openssl/err.h>
#include <string.h>
#include <stdio.h>

#include "err.h"

void
p67_err_print_err(const char * hdr, p67_err err)
{
    unsigned long sslerr;
    char errbuf[128];
    char fb = 0;

    if(hdr == NULL) {
        hdr = &fb;
    }

    if(err == p67_err_eok) return;

    if(err & p67_err_essl) {
        while((sslerr = ERR_get_error()) != 0) {
            ERR_error_string_n(sslerr, errbuf, 128);
            fprintf(stderr, "%s: %s\n", hdr, errbuf);
        }
    }

    if((err & p67_err_eerrno) && errno != 0) {
        fprintf(stderr, "%s: errno: %s\n", hdr, strerror(errno));
    }

    if(err & p67_err_einval) {
        fprintf(stderr, "%s: Invalid argument\n", hdr);
    }

    if(err & p67_err_eaconn) {
        fprintf(stderr, "%s: Already connected\n", hdr);
    }

    if(err & p67_err_enconn) {
        fprintf(stderr, "%s: Connection gone\n", hdr);
    }

    if(err & p67_err_enetdb) {
        fprintf(stderr, "%s: Couldnt obtain address information\n", hdr);
    }
}
