#if !defined(HADDR_H)
#define HADDR_H 1

#include <arpa/inet.h>

#include "err.h"

typedef struct p67_haddr {
    char * host;
    char * service;
    struct sockaddr addr;
    socklen_t addrl;
} p67_haddr_t;

void
p67_haddr_free_deps(p67_haddr_t * haddr);

p67_err
p67_haddr_set_host(p67_haddr_t * conn, const char * host, const char * svc);

p67_err
p67_haddr_set_peer_addr(p67_haddr_t * conn, struct sockaddr * addr, socklen_t addrl);

#endif