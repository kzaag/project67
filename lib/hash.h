#if !defined(HASH_H)
#define HASH_H

#include "conn.h"
#include <arpa/inet.h>

p67_conn_t *
p67_hash_conn_lookup(p67_conn_t * val);

p67_err
p67_hash_conn_insert(p67_conn_t * val, p67_conn_t ** ret);

p67_err
p67_hash_conn_remove(p67_conn_t * conn);

#endif