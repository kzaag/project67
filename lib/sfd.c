#include <netinet/in.h>
#include <arpa/inet.h>
#include <linux/tcp.h>
#include <fcntl.h>
#include <unistd.h>
#if !defined(__USE_XOPEN_EXTENDED)
#define __USE_XOPEN_EXTENDED 1
#endif
#include <string.h>
#include <strings.h>
#include <stdio.h>
#include <stdlib.h>

#include "sfd.h"

#define AL 120

p67_err
p67_addr_set_host(
                p67_addr_t * addr, 
                //socklen_t * addrl, 
                const char * hostname, 
                const char * service)
{
    int ret;
    struct addrinfo hint, * info, *cp;
    
    bzero(addr, sizeof(*addr));

    hint.ai_addr = NULL;
    hint.ai_addrlen = 0;
    hint.ai_canonname = NULL;
    hint.ai_family = AF_UNSPEC;
    hint.ai_socktype = SOCK_STREAM;
    hint.ai_flags = AI_PASSIVE;
    hint.ai_next = NULL;
    hint.ai_protocol = 0;

    if((ret = getaddrinfo(hostname, service, &hint, &info)) != 0) {
        return p67_err_enetdb | p67_err_eerrno;
    }

    ret = 1;

    for (cp = info; cp != NULL; cp = cp->ai_next) {
        switch(info->ai_family) {
        case AF_INET:
            addr->sock.sin = *((struct sockaddr_in *)&info->ai_addr);
            ret = 0;
            break;
        case AF_INET6:
            addr->sock.sin6 = *((struct sockaddr_in6 *)&info->ai_addr);
            ret = 0;
            break;
        default:
            break;
        }
        
        if(ret != 0) continue;

        addr->socklen = info->ai_addrlen;
        break;
    }

    freeaddrinfo(info);

    if(ret == 1)
        return p67_err_enetdb;

    if((addr->hostname = strdup(hostname)) == NULL) return p67_err_eerrno;
    if((addr->service = strdup(service)) == NULL) {
        free(addr->hostname);
        return p67_err_eerrno;
    }

    return 0;
}

/*
    free all deps from address, but WITHOUT addr pointer itself.
*/
void
p67_addr_free(p67_addr_t * addr)
{
    if((addr)->hostname != NULL) free((addr)->hostname);
    if((addr)->service != NULL) free((addr)->service);
}

/*
    Assign connected peer to connection using address
    Method is not thread safe
*/
p67_err
p67_addr_set_sockaddr(p67_addr_t * addr, struct sockaddr * sa, socklen_t sal)
{
    char cb[AL], svc[10];

    if(addr == NULL) return p67_err_einval;

    switch(sa->sa_family) {
    case AF_INET:
        addr->sock.sin = *(struct sockaddr_in *)&sa;
        inet_ntop(sa->sa_family, &((struct sockaddr_in *)addr)->sin_addr, cb, AL);
        sprintf(svc, "%u", ((struct sockaddr_in *)&addr)->sin_port);
        break;
    case AF_INET6:
        addr->sock.sin6 = *(struct sockaddr_in6 *)&sa;
        inet_ntop(sa->sa_family, &((struct sockaddr_in6 *)addr)->sin6_addr, cb, AL);
        sprintf(svc, "%u", ((struct sockaddr_in6 *)&addr)->sin6_port);
        break;
    default:
        addr->sock.sa.sa_family = AF_UNSPEC;
        snprintf(cb, AL, "<Unknown>");
        snprintf(svc, 10, "<Unknown>");
        break;
    }

    if((addr->hostname = strdup(cb)) == NULL) return p67_err_eerrno;
    if((addr->service = strdup(svc)) == NULL) return p67_err_eerrno;

    addr->socklen = sal;

    return 0;
}

p67_err
p67_sfd_set_keepalive(p67_sfd_t sfd)
{
    if(setsockopt(sfd, SOL_SOCKET, SO_KEEPALIVE, &(int){1}, sizeof(int)) != 0) {
        return p67_err_eerrno;
    }

    return 0;
}

p67_err
p67_sfd_set_reuseaddr(p67_sfd_t sfd)
{
    if(setsockopt(sfd, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT, &(int){1}, sizeof(int)) != 0){
        return p67_err_eerrno;
    }

    return 0;
}

p67_err
p67_sfd_listen(p67_sfd_t sfd)
{
    if(listen(sfd, -1) != 0) {
        return p67_err_eerrno;
    }

    return 0;
}

p67_err
p67_sfd_get_err(p67_sfd_t sfd)
{
    int serr;
    socklen_t serrl = sizeof(serr);
    if(getsockopt(sfd, SOL_SOCKET, SO_ERROR, &serr, &serrl) != 0)
        return p67_err_einval;
    if(serr != 0)
        return p67_err_einval;
    return serr;
}

p67_err
p67_sfd_close(p67_sfd_t sfd)
{
    if(close(sfd) != 0) return p67_err_eerrno;
    return 0;
}

p67_err
p67_sfd_connect(p67_sfd_t sfd, struct sockaddr * addr, socklen_t len)
{
    if(connect(sfd, addr, len) != 0) {
        return p67_err_eerrno;
    }

    return 0;
}

/*
    flags:
        1 = bind
        2 = connect
*/
p67_err
p67_sfd_create_from_hint(p67_sfd_t * sfd, const char * hostname, const char * service, int flags)
{
    int ret;
    struct addrinfo hint, * info, * cp;
    
    hint.ai_addr = NULL;
    hint.ai_addrlen = 0;
    hint.ai_canonname = NULL;
    hint.ai_family = AF_UNSPEC;
    hint.ai_socktype = SOCK_STREAM;
    hint.ai_flags = AI_PASSIVE;
    hint.ai_next = NULL;
    hint.ai_protocol = 0;

    if((ret = getaddrinfo(hostname, service, &hint, &info)) != 0) {
        return p67_err_enetdb | p67_err_eerrno;
    }

    for(cp = info; cp != NULL; cp = cp->ai_next) {
        *sfd = socket(cp->ai_family, cp->ai_socktype, cp->ai_protocol);
        if(*sfd <= 0)
            continue;

        if(flags == 1) {
            if(bind(*sfd, cp->ai_addr, cp->ai_addrlen) != 0) {
                close(*sfd);
                *sfd = 0;
                continue;
            }
        }

        if(flags == 2) {
            if(connect(*sfd, cp->ai_addr, cp->ai_addrlen) != 0) {
                close(*sfd);
                *sfd = 0;
                continue;
            }
        }
        
        break;
    }

    freeaddrinfo(info);

    if(*sfd <= 0)
        return p67_err_eerrno; 

    return 0;
}

