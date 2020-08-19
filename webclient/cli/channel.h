#if !defined(CHANNEL_H)
#define CHANNEL_H 1

#include <p67/err.h>
#include <p67/conn.h>

p67_err
p67_channel_open(p67_addr_t * addr);

#endif