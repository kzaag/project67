#include <stdio.h>

#include "err.h"
#include "db.h"

#include <p67/cmn.h>

int 
main(void)
{
    p67rs_err err;
    p67rs_db_ctx_t * ctx = NULL;

    if((err = p67rs_db_ctx_create_from_dp_config(\
            &ctx, 
            "/home/vattd/src/repos/p67/rserver/main.conf")) != 0)
        goto end;

    p67_epoch_t from, to;

    if((err = p67_cmn_time_ms(&from)) != 0) goto end;

    if((err = p67rs_db_create_user(ctx, "vattd", "vattd123")) != 0)
        goto end;

    if((err = p67_cmn_time_ms(&to)) != 0) goto end;

    printf("user created in %llu ms\n", to-from);

end:
    if(err != 0)
        p67rs_err_print_err(NULL, err);
    p67rs_db_ctx_free(ctx);

    return err == 0 ? 0 : 2;
}