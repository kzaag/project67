#include <stdio.h>

#include <server/err.h>
#include <server/db.h>

void
p67_ws_err_print_err(const char * hdr, p67_ws_err err)
{
    if(hdr == NULL) hdr = &(char){0};

    if(err & p67_err__prev__)
        p67_err_print_err(hdr, err);

    if(err & p67_ws_err_pq) {
        fprintf(stderr, "%s%s\n", hdr, p67_db_err_get());
    }

    if(err & p67_ws_err_bwt_sig) {
        fprintf(stderr, "%sBWT signature validation failed\n", hdr);
    }

    if(err & p67_ws_err_bwt_exp) {
        fprintf(stderr, "%sBWT expired\n", hdr);
    }
}