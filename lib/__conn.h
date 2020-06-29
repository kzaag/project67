#include <openssl/ssl.h>

#include "sfd.h"

#if !defined(CONNDEF_H)
#define CONNDEF_H

#define CIPHER "ECDHE-ECDSA-AES256-GCM-SHA384"
#define CIPHER_ALT "HIGH:!aNULL:!kRSA:!PSK:!SRP:!MD5:!RC4"

typedef struct p67_conn p67_conn_t;

struct p67_conn {
    SSL                     * ssl;
    char                    * trusted_chain;
    p67_addr_t              addr;
    p67_addr_t              baddr;
};

typedef int (* p67_callback)(p67_conn_t *, char *, int, void*);

p67_err
p67_conn_assign_callback(
                p67_conn_t * conn, 
                p67_callback callback, 
                void * args);

p67_err
p67_conn_init(p67_conn_t * conn);

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
p67_conn_write(p67_conn_t * conn, const char * arr, int arrl, int flags);

p67_err
p67_conn_read(p67_conn_t * conn, p67_callback callback, void * args);

p67_err
p67_conn_set_trusted_chain_path(p67_conn_t * conn, const char * path);

#endif
