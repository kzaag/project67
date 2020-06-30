#include "p67.h"

void
p67_lib_init(void)
{
    p67_net_init();
}

void
p67_lib_free(void)
{
    p67_net_free();
}