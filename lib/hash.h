#if !defined(HASH_H)
#define HASH_H

#include "net.h"

p67_conn_t *
p67_hash_conn_lookup(p67_conn_t * conn);

p67_conn_t *
p67_hash_conn_insert(p67_conn_t * val);

#endif