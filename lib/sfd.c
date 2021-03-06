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
#include <sys/time.h>

#include <p67/sfd.h>
#include <p67/log.h>

#define AL 120

#define ADDR_STR_LEN (INET6_ADDRSTRLEN+1+5)

#define p67_addr_lock(addr) p67_spinlock_lock(&addr->spinlock)
#define p67_addr_unlock(addr) p67_spinlock_unlock(&addr->spinlock)

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

p67_addr_t *
p67_addr_new_host(const char * hostname, 
                const char * service,
                int p67_sfd_tp)
{
    p67_addr_t * ret = p67_addr_new();
    if(!ret) return NULL;
    if(p67_addr_set_host(ret, hostname, service, p67_sfd_tp)) {
        p67_addr_free(ret);
        return NULL;
    }
    return ret;
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

    if(addr == NULL || hostname == NULL || service == NULL) 
        return p67_err_einval;

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

    p67_addr_lock(addr);

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

    if(ret == 1) {
        p67_addr_unlock(addr);
        return p67_err_enetdb;
    }

    if((addr->hostname = strdup(hostname)) == NULL) {
        p67_addr_unlock(addr);
        return p67_err_eerrno;
    }
    if((addr->service = strdup(service)) == NULL) {
        free(addr->hostname);
        p67_addr_unlock(addr);
        return p67_err_eerrno;
    }

    p67_addr_unlock(addr);

    return 0;
}

p67_addr_t *
p67_addr_new(void)
{
    p67_addr_t * ret = calloc(1, sizeof(p67_addr_t));
    if(!ret) return NULL;
    ret->refcount = 1;
    return ret;
}

char *
p67_addr_str(p67_addr_t * addr, char * b, int bl)
{
    int ix = 0;

    if(ix >= bl)
        return b;

    if(addr->hostname) {
        ix = snprintf(b, bl, "%s:", addr->hostname);
    }

    if(ix >= bl)
        return b;

    if(addr->service) {
        ix += snprintf(b, bl - ix, "%s", addr->service);
    }

    return b;
}

void
p67_addr_free(p67_addr_t * addr)
{
    if(!addr)
        return;
    
    p67_addr_lock(addr);

    if(addr->refcount < 1) {
        p67_log(
            "Warn: Tried to perform free on address with refcount = %u", 
            addr->refcount);
        p67_addr_unlock(addr);
        return;
    }

    if(addr->refcount == 1) {
        addr->refcount--;
        p67_addr_unlock(addr);
        p67_cmn_sleep_ms(10);
        free(addr->service);
        free(addr->hostname);
        free(addr);
    } else {
        addr->refcount--;
        p67_addr_unlock(addr);
    }

}

p67_addr_t *
p67_addr_ref_cpy(p67_addr_t * src)
{
    assert(src);
    
    p67_addr_lock(src);

    src->refcount++;

    p67_addr_unlock(src);

    return src;
}

p67_addr_t *
p67_addr_new_dup(const p67_addr_t * src)
{
    p67_addr_t * ret = p67_addr_new();
    if(!ret) return NULL;
    if(p67_addr_dup(ret, src)) {
        p67_addr_free(ret);
        return NULL;
    }
    return ret;
}

p67_err
p67_addr_dup(p67_addr_t * dest, const p67_addr_t * src)
{
    p67_err err;

    err = 0;

    if(dest == NULL || src == NULL)
        return p67_err_einval;

    p67_addr_lock(dest);

    if((dest->hostname = strdup(src->hostname)) == NULL)
        return p67_err_eerrno;

    if((dest->service = strdup(src->service)) == NULL) {
        err = p67_err_eerrno;
        free(dest->hostname);
        goto end;
    }

    dest->socklen = src->socklen;
    dest->sock = src->sock;

    p67_addr_unlock(dest);

end:
    return err;
}

p67_addr_t *
p67_addr_new_sockaddr(const p67_sockaddr_t * sa, socklen_t sal)
{
    p67_addr_t * ret = p67_addr_new();
    if(!ret) return NULL;
    if(p67_addr_set_sockaddr(ret, sa, sal)) {
        p67_addr_free(ret);
        return NULL;
    }
    return ret;
}

/*
    Assign connected peer to connection using address
    function is not thread safe
*/
p67_err
p67_addr_set_sockaddr(
    p67_addr_t * addr, 
    const p67_sockaddr_t * sa, 
    socklen_t sal)
{
    char cb[AL], svc[10];
    (void)sal;

    if(addr == NULL) return p67_err_einval;

    p67_addr_lock(addr);

    switch(sa->sa.sa_family) {
    case AF_INET:
        addr->sock.sin = sa->sin;
        inet_ntop(sa->sa.sa_family, &sa->sin.sin_addr, cb, AL);
        sprintf(svc, "%hu", ntohs(sa->sin.sin_port));
        addr->socklen = sizeof(struct sockaddr_in);
        break;
    case AF_INET6:
        addr->sock.sin6 = sa->sin6;
        inet_ntop(sa->sa.sa_family, &sa->sin6.sin6_addr, cb, AL);
        sprintf(svc, "%hu", ntohs(sa->sin6.sin6_port));
        addr->socklen = sizeof(struct sockaddr_in6);
        break;
    default:
        addr->sock.sa.sa_family = AF_UNSPEC;
        snprintf(cb, AL, "<Unknown>");
        snprintf(svc, 10, "<Unknown>");
        break;
    }

    if((addr->hostname = strdup(cb)) == NULL) {
        p67_addr_unlock(addr);
        return p67_err_eerrno;
    }
    if((addr->service = strdup(svc)) == NULL) {
        free(addr->hostname);
        p67_addr_unlock(addr);
        return p67_err_eerrno;
    }

    p67_addr_unlock(addr);
    return 0;
}

p67_err
p67_sfd_set_keepalive(p67_sfd_t sfd)
{
    if(setsockopt(
            sfd, 
            SOL_SOCKET, 
            SO_KEEPALIVE, 
            &(int){1}, 
            sizeof(int)) != 0) {
        return p67_err_eerrno;
    }

    return 0;
}

p67_err
p67_sfd_set_reuseaddr(p67_sfd_t sfd)
{
    if(setsockopt(
            sfd, 
            SOL_SOCKET, 
            SO_REUSEADDR | SO_REUSEPORT, 
            &(int){1}, 
            sizeof(int)) != 0){
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
p67_sfd_connect(p67_sfd_t sfd, const p67_addr_t * addr)
{
    if(connect(sfd, &addr->sock.sa, addr->socklen) != 0) {
        return p67_err_eerrno;
    }

    return 0;
}

p67_err
p67_sfd_bind(p67_sfd_t sfd, const p67_addr_t * addr)
{
    if(addr == NULL)
        return p67_err_einval;

    if(bind(sfd, &addr->sock.sa, addr->socklen) != 0)
        return p67_err_eerrno;

    return 0;
}

p67_err
p67_sfd_create_from_addr(
    p67_sfd_t * sfd, 
    const p67_addr_t * addr, 
    int p67_sfd_tp)
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
p67_addr_parse_str(
    const char * str, 
    p67_addr_t * addr, 
    int p67_sfd_tp) 
{
    if(addr == NULL)
        return p67_err_einval;

    const char * portstr;
    const char * ipstr;
    int ipstrl;
    char ip[ADDR_STR_LEN + 1];

    if((portstr = strrchr(str, ':')) == NULL)
        return p67_err_einval;

    portstr++;

    if(portstr <= str)
        return p67_err_einval;

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

p67_addr_t *
p67_addr_new_parse_str(const char * src, int p67_sfd_tp)
{
    p67_addr_t * ret = p67_addr_new();
    if(!ret) return NULL;
    if(p67_addr_parse_str(src, ret, p67_sfd_tp)) {
        p67_addr_free(ret);
        return NULL;
    }
    return ret;
}

const uint16_t *
p67_addr_get_port_ref(const p67_addr_t * addr)
{
    if(!addr) return 0;

    switch(addr->sock.sa.sa_family) {
    case AF_INET:
        return &addr->sock.sin.sin_port;
    case AF_INET6:
        return &addr->sock.sin6.sin6_port;
    default:
        return 0;
    }
}

uint16_t
p67_addr_get_port(const p67_addr_t * addr)
{
    if(!addr) return 0;

    switch(addr->sock.sa.sa_family) {
    case AF_INET:
        return p67_cmn_ntohs(addr->sock.sin.sin_port);
    case AF_INET6:
        return p67_cmn_ntohs(addr->sock.sin6.sin6_port);
    default:
        return 0;
    }
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

p67_err
p67_sfd_set_timeouts(p67_sfd_t sfd, int sndto_ms, int rcvto_ms)
{
    struct timeval tv;

    if(sndto_ms > 0) {
        tv.tv_sec = sndto_ms / 1000;
        tv.tv_usec = (sndto_ms % 1000) * 1e3;
        if(setsockopt(sfd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv)) < 0)
            return p67_err_eerrno;
    }

    if(rcvto_ms > 0) {
        tv.tv_sec = rcvto_ms / 1000;
        tv.tv_usec = (rcvto_ms % 1000) * 1e3;
        if(setsockopt(sfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) < 0)
            return p67_err_eerrno;
    }

    return 0;
}

p67_err
p67_sfd_get_timeouts(p67_sfd_t sfd, int * sndto_ms, int * rcvto_ms)
{
    struct timeval tv;

    if(sndto_ms) {
        if(getsockopt(
                sfd, 
                SOL_SOCKET, 
                SO_SNDTIMEO, 
                &tv, 
                &(socklen_t){sizeof(tv)}) < 0)
            return p67_err_eerrno;
        *sndto_ms = (tv.tv_sec * 1000) + (tv.tv_usec / 1000);
    }

    if(rcvto_ms) {
        if(getsockopt(
                sfd, 
                SOL_SOCKET, 
                SO_RCVTIMEO, 
                &tv, 
                &(socklen_t){sizeof(tv)}) < 0)
            return p67_err_eerrno;
        *rcvto_ms = (tv.tv_sec * 1000) + (tv.tv_usec / 1000);
    }

    return 0;
}
