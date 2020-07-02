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
    int sslp;

    if(hdr == NULL) hdr = &fb;

    if(err == p67_err_eok) return;
    
    sslp = 0;
    if(err & p67_err_essl) {
        while((sslerr = ERR_get_error()) != 0) {
            ERR_error_string_n(sslerr, errbuf, 128);
            fprintf(stderr, "%s%s\n", hdr, errbuf);
            sslp = 1;
        }
        if(sslp == 0) fprintf(stderr, "%sUnknown OpenSSL error occurred.\n", hdr); 
    }

    if((err & p67_err_eerrno) && errno != 0) {
        fprintf(stderr, "%sErrno: %s\n", hdr, strerror(errno));
    }

    if(err & p67_err_einval) {
        fprintf(stderr, "%sInvalid argument\n", hdr);
    }

    if(err & p67_err_eaconn) {
        fprintf(stderr, "%sAlready connected\n", hdr);
    }

    if(err & p67_err_enconn) {
        fprintf(stderr, "%sConnection gone\n", hdr);
    }

    if(err & p67_err_enetdb) {
        fprintf(stderr, "%sCouldnt obtain address information\n", hdr);
    }

    if(err & p67_err_easync) {
        fprintf(stderr, "%sAsync state changed\n", hdr);
    }

    if(err & p67_err_etime) {
        fprintf(stderr, "%sTimeout\n", hdr);
    }
}
