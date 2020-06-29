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

#define p67_sfd_initialized(sfd) ((sfd) > 0)

typedef int p67_sfd_t;

union p67_sockaddr {
    struct sockaddr         sa;
    struct sockaddr_in      sin;
    struct sockaddr_in6     sin6;
    /* 
        Only inet and inet6 is supported at the moment. 
        So sockaddr_storage is not needed (biggest address is sin6) 
        struct sockaddr_storage __ss;
    */
};

typedef union p67_sockaddr p67_sockaddr_t;

struct p67_addr {
    p67_sockaddr_t sock;
    socklen_t      socklen;
    char           * hostname;
    char           * service;
};

#define p67_addr_is_initialized(addr) \
    (((addr)->hostname != NULL) && ((addr)->service != NULL) && ((addr)->sock.sa.sa_family != 0))

typedef struct p67_addr p67_addr_t;

void
p67_addr_free(p67_addr_t * addr);

p67_err
p67_addr_set_host(
                p67_addr_t * addr, 
                const char * protocol,
                const char * hostname, 
                const char * service);

p67_err
p67_addr_set_sockaddr(
                p67_addr_t * addr,
                const struct sockaddr * sa,
                socklen_t sal);

p67_err
p67_sfd_create_from_hint(
            p67_sfd_t * sfd,
            const char * protocol,
            const char * hostname, 
            const char * service,
            int flags);

p67_err
p67_addr_dup(p67_addr_t * dest, const p67_addr_t * src);

p67_err
p67_addr_parse_str(const char * str, p67_addr_t * addr);

p67_err
p67_sfd_create_tcp_from_addr(p67_sfd_t * sfd, p67_addr_t * addr);

p67_err
p67_sfd_connect(p67_sfd_t sfd, p67_addr_t * addr);

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
p67_sfd_accept(p67_sfd_t sfd, p67_addr_t * addr);

p67_err
p67_sfd_valid(p67_sfd_t sfd);

p67_err
p67_sfd_bind(p67_sfd_t sfd, p67_addr_t * addr);

p67_err
p67_sfd_set_noblocking(p67_sfd_t sfd);

p67_err
p67_sfd_get_peer_name(p67_sfd_t sfd, p67_addr_t * addr);

#endif