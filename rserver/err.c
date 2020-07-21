#include "err.h"
#include "db.h"

#include <stdio.h>

void
p67rs_err_print_err(const char * hdr, p67rs_err err)
{
    if(hdr == NULL) hdr = &(char){0};

    if(err & p67_err__prev__)
        p67_err_print_err(hdr, err);

    if(err & p67rs_err_pq) {
        fprintf(stderr, "%s%s\n", hdr, p67rs_db_err_get());
    }
}