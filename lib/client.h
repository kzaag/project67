#if !defined(CLIENT_H)
#define CLIENT_H

#include "err.h"
#include "conn.h"

p67_err
p67_client_disconnect(p67_conn_t * conn);

p67_err
p67_client_connect(p67_conn_t * conn);

#endif
