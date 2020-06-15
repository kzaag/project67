#if !defined(SFD_H)
#define SFD_H 1

#include "net.h"
#if !defined(__USE_XOPEN2K)
#define __USE_XOPEN2K
#endif
#if !defined(__USE_GNU)
#define __USE_GNU
#endif
#include <netdb.h>
#include <sys/socket.h>

p67_err
p67_sfd_create_address(
            struct sockaddr * addr, 
            socklen_t * addrl, 
            const char * hostname, 
            const char * service);

p67_err
p67_sfd_create_from_hint(
            int * sfd, 
            const char * hostname, 
            const char * service, 
            int flags);

p67_err
p67_sfd_connect(
            int sfd, 
            struct sockaddr * addr, 
            socklen_t len);

p67_err
p67_sfd_listen(int sfd);

p67_err
p67_sfd_set_reuseaddr(int sfd);

p67_err
p67_sfd_set_keepalive(int sfd);

#endif