#include <p67/net.h>
#include <p67/dml/pdp.h>
#include <p67/log.h>

void
p67_lib_init(void);

void
p67_lib_free(void);

void
p67_lib_init(void)
{
    p67_net_init();
}

void
p67_lib_free(void)
{
    p67_pdp_stop_loop();
    p67_conn_free_all();
    p67_log_free();
}