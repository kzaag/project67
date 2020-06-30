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
#include <poll.h>
#include <errno.h>

#include "sfd.h"

#define AL 120

#define ADDR_STR_LEN (INET6_ADDRSTRLEN+1+5)

#define p67_sfd_fill_type_and_proto(tp, typeval, protoval) \
    { \
        switch(tp) { \
        case P67_SFD_TP_DGRAM_UDP: \
            typeval = SOCK_DGRAM; \
            protoval = IPPROTO_UDP; \
            break;                    \
        case P67_SFD_TP_STREAM_TCP: \
        case P67_SFD_TP_DEF: \
        default: \
            typeval = SOCK_STREAM; \
            protoval = IPPROTO_TCP; \
            break;                   \
        } \
    }

p67_err
p67_addr_set_host(
                p67_addr_t * addr,
                const char * hostname, 
                const char * service,
                int p67_sfd_tp)
{
    int ret;
    struct addrinfo hint, * info, *cp;
    
    if(addr == NULL || hostname == NULL || service == NULL) return p67_err_einval;

    bzero(addr, sizeof(*addr));

    hint.ai_addr = NULL;
    hint.ai_addrlen = 0;
    hint.ai_canonname = NULL;
    hint.ai_family = AF_UNSPEC;
    hint.ai_socktype = SOCK_STREAM;
    hint.ai_flags = AI_PASSIVE;
    hint.ai_next = NULL;
    hint.ai_protocol = 0;

    if(p67_sfd_tp != P67_SFD_TP_DEF) {
        p67_sfd_fill_type_and_proto(
            p67_sfd_tp, 
            hint.ai_socktype, 
            hint.ai_protocol);
    }

    if((ret = getaddrinfo(hostname, service, &hint, &info)) != 0) {
        return p67_err_enetdb | p67_err_eerrno;
    }

    ret = 1;

    for (cp = info; cp != NULL; cp = cp->ai_next) {
        switch(info->ai_family) {
        case AF_INET:
            addr->sock.sin = *((struct sockaddr_in *)info->ai_addr);
            ret = 0;
            break;
        case AF_INET6:
            addr->sock.sin6 = *((struct sockaddr_in6 *)info->ai_addr);
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
    free((addr)->hostname);
    free((addr)->service);
}

p67_err
p67_addr_dup(p67_addr_t * dest, const p67_addr_t * src)
{
    p67_err err;

    err = 0;

    if(dest == NULL || src == NULL)
        return p67_err_einval;

    if((dest->hostname = strdup(src->hostname)) == NULL)
        return p67_err_eerrno;

    if((dest->service = strdup(src->service)) == NULL) {
        err = p67_err_eerrno;
        free(dest->hostname);
        goto end;
    }

    dest->socklen = src->socklen;
    dest->sock = src->sock;

end:
    return err;
}

/*
    Assign connected peer to connection using address
    Method is not thread safe
*/
p67_err
p67_addr_set_sockaddr(p67_addr_t * addr, const p67_sockaddr_t * sa, socklen_t sal)
{
    char cb[AL], svc[10];

    if(addr == NULL) return p67_err_einval;

    switch(sa->sa.sa_family) {
    case AF_INET:
        addr->sock.sin = sa->sin;
        inet_ntop(sa->sa.sa_family, &sa->sin.sin_addr, cb, AL);
        sprintf(svc, "%hu", ntohs(sa->sin.sin_port));
        break;
    case AF_INET6:
        addr->sock.sin6 = sa->sin6;
        inet_ntop(sa->sa.sa_family, &sa->sin6.sin6_addr, cb, AL);
        sprintf(svc, "%hu", ntohs(sa->sin6.sin6_port));
        break;
    default:
        addr->sock.sa.sa_family = AF_UNSPEC;
        snprintf(cb, AL, "<Unknown>");
        snprintf(svc, 10, "<Unknown>");
        break;
    }

    if((addr->hostname = strdup(cb)) == NULL) return p67_err_eerrno;
    if((addr->service = strdup(svc)) == NULL) {
        free(addr->hostname);
        return p67_err_eerrno;
    }

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

/*
    Keep calling accept until valid request arrives.
    On failure return 0.
*/
p67_sfd_t
p67_sfd_accept(p67_sfd_t sfd, p67_addr_t * addr)
{
    p67_sockaddr_t saddr;
    socklen_t saddrl;
    p67_sfd_t csfd;

    while(1) {
        bzero(addr, sizeof(*addr));
        saddrl = sizeof(saddr);

        csfd = accept(sfd, (struct sockaddr *)&saddr, &saddrl);
        if(csfd < 0)
            continue;

        if(p67_addr_set_sockaddr(addr, &saddr, saddrl) != 0) {
            p67_addr_free(addr);
            close(csfd);
            continue;
        }

        break;
    }

    return csfd;
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
p67_sfd_valid(p67_sfd_t sfd)
{
    p67_err err;
    struct pollfd pfd = {.fd = sfd, .events=POLLERR};

    err = 0;

    if(poll(&pfd, 1, 1) < 0)
        err = p67_err_eerrno;

    if(pfd.events & POLLERR)
        errno = EPIPE;

    return err;
}

p67_err
p67_sfd_set_noblocking(p67_sfd_t sfd)
{
    int flags;
    
    if((flags = fcntl(sfd, F_GETFL, 0)) == -1) {
        return p67_err_eerrno;
    }

    flags |= O_NONBLOCK;

    if(fcntl(sfd, F_SETFL, flags) == -1) {
        return p67_err_eerrno;
    }

    return 0;
}

p67_err
p67_sfd_close(p67_sfd_t sfd)
{
    if(sfd <= 0) return 0;
    if(close(sfd) != 0) return p67_err_eerrno;
    return 0;
}

p67_err
p67_sfd_connect(p67_sfd_t sfd, p67_addr_t * addr)
{
    if(connect(sfd, &addr->sock.sa, addr->socklen) != 0) {
        return p67_err_eerrno;
    }

    return 0;
}

p67_err
p67_sfd_bind(p67_sfd_t sfd, p67_addr_t * addr)
{
    if(addr == NULL)
        return p67_err_einval;

    if(bind(sfd, &addr->sock.sa, addr->socklen) != 0)
        return p67_err_eerrno;

    return 0;
}

p67_err
p67_sfd_create_from_addr(p67_sfd_t * sfd, p67_addr_t * addr, int p67_sfd_tp)
{
    if(addr == NULL || sfd == NULL)
        return p67_err_einval;
    
    int type, proto;

    p67_sfd_fill_type_and_proto(p67_sfd_tp, type, proto);

    if((*sfd = socket(addr->sock.sa.sa_family, type, proto)) < 0) {
        return p67_err_eerrno;
    }

    return 0;
}

/*
    flags (P67_SFD_C_*):
        1 = bind
        2 = connect
        4 = reuse address
*/
p67_err
p67_sfd_create_from_hint(
                p67_sfd_t * sfd, 
                int p67_sfd_tp,
                const char * hostname, 
                const char * service, 
                int flags)
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

    if(p67_sfd_tp != P67_SFD_TP_DEF) {
        p67_sfd_fill_type_and_proto(
            p67_sfd_tp, 
            hint.ai_socktype, 
            hint.ai_protocol);
    }

    if((ret = getaddrinfo(hostname, service, &hint, &info)) != 0) {
        return p67_err_enetdb | p67_err_eerrno;
    }

    for(cp = info; cp != NULL; cp = cp->ai_next) {
        *sfd = socket(cp->ai_family, cp->ai_socktype, cp->ai_protocol);
        if(*sfd <= 0)
            continue;

        if(flags & 1) {
            if(bind(*sfd, cp->ai_addr, cp->ai_addrlen) != 0) {
                close(*sfd);
                *sfd = 0;
                continue;
            }
        } 
        
        if(flags & 2) {
            if(connect(*sfd, cp->ai_addr, cp->ai_addrlen) != 0) {
                close(*sfd);
                *sfd = 0;
                continue;
            }
        }

        if(flags & 4) {
            if(p67_sfd_set_reuseaddr(*sfd) != 0) {
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

p67_err
p67_addr_parse_str(const char * str, p67_addr_t * addr, int p67_sfd_tp) 
{
    const char * portstr;
    const char * ipstr;
    int ipstrl;
    char ip[ADDR_STR_LEN + 1];

    if((portstr = strrchr(str, ':')) == NULL) {
        errno = EBFONT;
        return p67_err_eerrno;
    }

    portstr++;

    if(portstr <= str) {
        errno = EBFONT;
        return p67_err_eerrno;
    }

    if(str[0] == '[') {
        ipstr = str + 1;
        ipstrl = portstr - ipstr - 2;
    } else {
        ipstr = str;
        ipstrl = portstr - ipstr - 1;
    }

    memcpy(ip, ipstr, ipstrl);
    ip[ipstrl] = 0;

    return p67_addr_set_host(addr, ip, portstr, p67_sfd_tp);
}

p67_err
p67_sfd_get_peer_name(p67_sfd_t sfd, p67_addr_t * addr)
{
    p67_sockaddr_t sockaddr;
    socklen_t len = sizeof(p67_sockaddr_t);
    if(getpeername(sfd, &sockaddr.sa, &len) != 0)
        return p67_err_eerrno;

    return p67_addr_set_sockaddr(addr, &sockaddr, len);
}
