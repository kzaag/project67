#include "channel.h"

p67_err
p67_channel_open(p67_addr_t * addr)
{
    p67_log(
        "opening channel for: %s:%s\n", 
        addr->hostname, addr->service);
    return 0;
}
