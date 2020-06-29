#if !defined NET_H
#define NET_H

#include "sfd.h"
#include <openssl/ssl.h>
#include "err.h"

typedef struct p67_client p67_client_t;

typedef struct p67_cert_store p67_cert_store_t;

struct p67_cert_store {
    char * certpath;
    char * keypath;
    char * trusted_chain_path;
};

/* single peer connection */
struct p67_client {
    SSL              * ssl;
    p67_sfd_t        sfd;
    pthread_t        servethr;

    p67_addr_t       local_addr;
    p67_addr_t       remote_addr;
    p67_cert_store_t cert;
};

p67_err
p67_client_start_serve(p67_client_t * client);

int
p67_client_is_connected(p67_client_t * client);

p67_err
p67_client_connect(p67_client_t * client, int f);

p67_err
p67_client_write(p67_client_t * client, const char * msg, int msgl, int f);

p67_err
p67_client_serve(p67_client_t * client);

p67_err
p67_client_disconnect(p67_client_t * client);



#endif