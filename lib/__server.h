#if !defined(SERVER_H)
#define SERVER_H 1

#include "conn.h"
#include "sfd.h"

struct p67_server {
    p67_addr_t      addr;

    char            * certpath;
    char            * keypath;

    p67_callback    callback;
    void            * callback_args;
};

typedef struct p67_server p67_server_t;

p67_server_t *
p67_server_new(void);

p67_err
p67_server_set_cert(
                    p67_server_t * server, 
                    const char * certpath, 
                    const char * keypath);

p67_err
p67_server_set_callback(
                    p67_server_t * server, 
                    p67_callback callback, 
                    void * callback_args);

p67_err
p67_server_start_listen(p67_server_t * server);

p67_err
p67_server_listen(p67_server_t * server);

void
p67_server_free(p67_server_t *  server);

#endif
