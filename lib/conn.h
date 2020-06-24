#include <sys/socket.h>
#include <openssl/ssl.h>

#include "haddr.h"

#if !defined(CONNDEF_H)
#define CONNDEF_H

typedef struct p67_conn p67_conn_t;

typedef int (* p67_callback)(p67_conn_t *, char *, int, void*);

struct p67_conn {
    SSL             * ssl;
    char            * trusted_chain;
    p67_haddr_t     haddr;
    p67_callback    callback;
    void *          callback_args;
};

p67_err
p67_conn_assign_callback(
                p67_conn_t * conn, 
                p67_callback callback, 
                void * args);

p67_err
p67_conn_init(p67_conn_t * conn);

p67_err
p67_conn_listen(
    const char * hostname, 
    const char * service, 
    const char * certpath, 
    const char * keypath,
    p67_callback callback,
    void * callback_args);

p67_err
p67_conn_connect(p67_conn_t * conn);

p67_conn_t *
p67_conn_new(void);

int
p67_conn_is_connected(p67_conn_t * conn);

void
p67_conn_free_deps(p67_conn_t * conn);

void
p67_conn_free(p67_conn_t * conn);

p67_err
p67_conn_shutdown(p67_conn_t * conn);

p67_err
p67_conn_write(p67_conn_t * conn, char * arr, int arrl, int flags);

p67_err
p67_conn_read(p67_conn_t * conn);

p67_err
p67_conn_set_trusted_chain_path(p67_conn_t * conn, const char * path);

#endif
