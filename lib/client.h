#if !defined(CLIENT_H)
#define CLIENT_H

#include "err.h"
#include "conn.h"

p67_err
p67_client_disconnect(p67_addr_t * addr);

p67_err
p67_client_connect(p67_addr_t * addr, const char * trusted_chain_path);

p67_err
p67_client_add_connected(p67_addr_t * addr, p67_conn_t ** conn);

void
p67_client_free_all(void);

p67_err
p67_client_write_cstr(p67_addr_t * addr, const char * msg);

p67_err
p67_client_write(p67_addr_t * addr, const char * msg, int msgl);

p67_err
p67_client_get_connection(p67_addr_t * addr, p67_conn_t ** conn);

#endif
