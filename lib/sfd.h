#if !defined(SFD_H)
#define SFD_H 1

#include "err.h"

#if !defined(__USE_XOPEN2K)
#define __USE_XOPEN2K
#endif
#if !defined(__USE_GNU)
#define __USE_GNU
#endif
#include <netdb.h>
#include <sys/socket.h>

#define IP4_ANY "0.0.0.0"
#define IP4_LO1 "127.0.0.1"
#define IP6_LO1 "::1"
#define IP6_ANY "::"


/* 
    actual value will depend on the function. 
    proto is usualy defaulted to IPPROTO_IP (0) 
    type will be SOCK_STREAM unless specified by other parameters */
#define P67_SFD_TP_DEF 0 
#define P67_SFD_TP_STREAM_TCP 1 /* SOCK_STREAM with IPPROTO_TCP */
#define P67_SFD_TP_DGRAM_UDP 2 /* SOCK_DGRAM with IPPRORO UDP */

#define p67_sfd_initialized(sfd) ((sfd) > 0)

typedef int p67_sfd_t;

union p67_sockaddr {
    struct sockaddr         sa;
    struct sockaddr_in      sin;
    struct sockaddr_in6     sin6;
    struct sockaddr_storage __ss;
};

typedef union p67_sockaddr p67_sockaddr_t;

struct p67_addr {
    p67_sockaddr_t sock;
    socklen_t      socklen;
    char           * hostname;
    char           * service;
    unsigned long  rdonly : 1;
};

typedef struct p67_addr p67_addr_t;

void
p67_addr_free(p67_addr_t * __restrict__ addr);

#define p67_addr_set_host_udp(addr, host, svc) \
    p67_addr_set_host((addr), (host), (svc), P67_SFD_TP_DGRAM_UDP)

#define p67_addr_set_localhost4_udp(addr, svc) \
    p67_addr_set_host_udp(addr, IP4_ANY, svc)

p67_err
p67_addr_set_host(
                p67_addr_t * __restrict__ addr, 
                const char * __restrict__ protocol,
                const char * __restrict__ hostname, 
                int p67_sfd_tp)
    __nonnull((1, 2, 3));

p67_err
p67_addr_set_sockaddr(
                p67_addr_t * __restrict__ addr,
                const p67_sockaddr_t * sa,
                socklen_t sal)
    __nonnull((1, 2));

#define P67_SFD_C_BIND    1
#define P67_SFD_C_CONNECT 2
#define P67_SFD_C_REUSE   4

p67_err
p67_sfd_create_from_hint(
            p67_sfd_t * __restrict__ sfd,
            const int p67_sfd_tp,
            const char * __restrict__ hostname,
            const char * __restrict__ service,
            int flags)
    __nonnull((1, 3, 4));

p67_err
p67_addr_dup(p67_addr_t * __restrict__ dest, const p67_addr_t * __restrict__ src)
    __nonnull((1, 2));

p67_err
p67_addr_parse_str(const char * str, p67_addr_t * __restrict__ addr, int p67_sfd_tp)
    __nonnull((2));


/*
    sfd  is socket to be created.
    addr is hint address
    p67_sfd_tp is type / proto specification.
            to get p67_sfd_tp possible values look for P67_SFD_TP_* constants.
*/
p67_err
p67_sfd_create_from_addr(
            p67_sfd_t * __restrict__ sfd, 
            const p67_addr_t * __restrict__ addr, 
            int p67_sfd_tp)
    __nonnull((2));

p67_err
p67_sfd_connect(p67_sfd_t sfd, const p67_addr_t * addr)
    __nonnull((2));

p67_err
p67_sfd_listen(p67_sfd_t sfd);

p67_err
p67_sfd_set_reuseaddr(p67_sfd_t sfd);

p67_err
p67_sfd_set_keepalive(p67_sfd_t sfd);

p67_err
p67_sfd_get_err(p67_sfd_t sfd);

p67_err
p67_sfd_close(p67_sfd_t sfd);

p67_sfd_t
p67_sfd_accept(p67_sfd_t sfd, p67_addr_t * __restrict__ addr)
    __nonnull((2));

p67_err
p67_sfd_valid(p67_sfd_t sfd);

p67_err
p67_sfd_bind(p67_sfd_t sfd, const p67_addr_t * addr)
    __nonnull((2));

p67_err
p67_sfd_set_noblocking(p67_sfd_t sfd);

p67_err
p67_sfd_get_peer_name(p67_sfd_t sfd, p67_addr_t * __restrict__ addr)
    __nonnull((2));

#endif