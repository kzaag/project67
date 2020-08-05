#include "err.h"
#include "db.h"

#include <stdio.h>

void
p67rs_werr_print_status(const char * hdr, p67rs_werr err)
{
    if(err == p67rs_werr_200) {
        fprintf(stderr, "%sOK\n", hdr);
        return;
    }

    if(err & p67rs_werr_400) {
        fprintf(stderr, "%sBad Request\n", hdr);
    }

    if(err & p67rs_werr_401) {
        fprintf(stderr, "%sUnauthorized\n", hdr);
    }

    if(err & p67rs_werr_500) {
        fprintf(stderr, "%sInternal Server Error\n", hdr);
    }

    if(err & p67rs_werr_eacall) {
        fprintf(stderr, "%sAlready calling\n", hdr);
    }

    if(err & p67rs_werr_ecall) {
        fprintf(stderr, "%sCall failed\n", hdr);
    }
}

void
p67rs_err_print_err(const char * hdr, p67rs_err err)
{
    if(hdr == NULL) hdr = &(char){0};

    if(err & p67_err__prev__)
        p67_err_print_err(hdr, err);

    if(err & p67rs_err_pq) {
        fprintf(stderr, "%s%s\n", hdr, p67rs_db_err_get());
    }

    if(err & p67rs_err_bwt_sig) {
        fprintf(stderr, "%sBWT signature validation failed\n", hdr);
    }

    if(err & p67rs_err_bwt_exp) {
        fprintf(stderr, "%sBWT expired\n", hdr);
    }
}