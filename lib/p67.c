#include <p67/net.h>

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
    p67_conn_shutdown_all();
}