#if !defined(P67_TIMEOUT_H)
#define P67_TIMEOUT_H 1

#include <stddef.h>

#include "err.h"
#include "cmn.h"
#include "sfd.h"

typedef struct p67_timeout p67_timeout_t;

#define P67_TIMEOUT_DEFAULT_LEN 457

p67_timeout_t *
p67_timeout_create(size_t capacity, p67_err * err);

p67_err
p67_timeout_addr_for_epoch(
    p67_timeout_t * ctx, 
    p67_addr_t * addr,
    p67_cmn_epoch_t timeout_duration_ms, 
    int with_shutdown);

p67_err
p67_timeout_addr(
    p67_addr_t * addr, 
    int with_shutdown);

void
p67_timeout_free(p67_timeout_t * t);

#endif
