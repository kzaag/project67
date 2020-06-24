#include <stdlib.h>
#if !defined(__USE_XOPEN_EXTENDED)
#define __USE_XOPEN_EXTENDED 1
#endif
#include <string.h>
#include <stdio.h>

#include "haddr.h"
#include "sfd.h"

/* maximum address string length */
#define AL 120

void
p67_haddr_free_deps(p67_haddr_t * haddr)
{
    if(haddr == NULL) return;
    if(haddr->host != NULL) free(haddr->host);
    if(haddr->service != NULL) free(haddr->service);
}

p67_err
p67_haddr_set_host(p67_haddr_t * conn, const char * host, const char * svc)
{
    p67_err err;

    if(conn == NULL) return p67_err_einval;

    conn->addrl = sizeof(struct sockaddr);
    if((err = p67_sfd_create_address(&conn->addr, &conn->addrl, host, svc)) != 0)
        return err;

    if(conn->host != NULL) free(conn->host);
    if(conn->service != NULL) free(conn->service);

    if((conn->host = strdup(host)) == NULL) return p67_err_eerrno;
    if((conn->service = strdup(svc)) == NULL) return p67_err_eerrno;

    return 0;
}

/*
    Assign connected peer to connection using address
    Method is not thread safe
*/
p67_err
p67_haddr_set_peer_addr(p67_haddr_t * conn, struct sockaddr * addr, socklen_t addrl)
{
    char cb[AL], svc[10];

    if(conn == NULL) return p67_err_einval;

    conn->addrl = addrl;
    conn->addr = *addr;

    switch(addr->sa_family) {
    case AF_INET:
        inet_ntop(addr->sa_family, &((struct sockaddr_in *)addr)->sin_addr, cb, AL);
        sprintf(svc, "%u", ((struct sockaddr_in *)&addr)->sin_port);
        break;
    case AF_INET6:
        inet_ntop(addr->sa_family, &((struct sockaddr_in6 *)addr)->sin6_addr, cb, AL);
        sprintf(svc, "%u", ((struct sockaddr_in6 *)&addr)->sin6_port);
        break;
    default:
        snprintf(cb, AL, "<Unknown>");
        snprintf(svc, 10, "<Unknown>");
        break;
    }

    if(conn->host != NULL) free(conn->host);
    if(conn->service != NULL) free(conn->service);

    if((conn->host = strdup(cb)) == NULL) return p67_err_eerrno;
    if((conn->service = strdup(svc)) == NULL) return p67_err_eerrno;

    return 0;
}
