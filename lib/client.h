#if !defined(CLIENT_H)
#define CLIENT_H

#include "err.h"
#include "conn.h"

p67_err
p67_client_disconnect(p67_addr_t * addr);

p67_err
p67_client_connect(p67_addr_t * addr, const char * trusted_chain_path);

void
p67_conn_free_all(void);

#endif
