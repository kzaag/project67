#include <netinet/in.h>
#include <arpa/inet.h>
#include <linux/tcp.h>
#include <fcntl.h>
#include <unistd.h>

/*
 * x-plaftorm wrapper around sockets.
 */

#include "sfd.h"

p67_err
p67_sfd_create_address(
                struct sockaddr * addr, 
                socklen_t * addrl, 
                const char * hostname, 
                const char * service)
{
    int ret;
    struct addrinfo hint, * info, *cp;
    
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
        if(*addrl < info->ai_addrlen)
            continue;  
        *addr = *info->ai_addr;
        *addrl = info->ai_addrlen;
        ret = 0;
        break;
    }

    freeaddrinfo(info);

    if(ret == 1)
        return p67_err_enetdb;

    return 0;
}

p67_err
p67_sfd_set_keepalive(int sfd)
{
    if(setsockopt(sfd, SOL_SOCKET, SO_KEEPALIVE, &(int){1}, sizeof(int)) != 0) {
        return p67_err_eerrno;
    }

    return 0;
}

p67_err
p67_sfd_set_reuseaddr(int sfd)
{
    if(setsockopt(sfd, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT, &(int){1}, sizeof(int)) != 0){
        return p67_err_eerrno;
    }

    return 0;
}

p67_err
p67_sfd_listen(int sfd)
{
    if(listen(sfd, -1) != 0) {
        return p67_err_eerrno;
    }

    return 0;
}

p67_err
p67_sfd_connect(int sfd, struct sockaddr * addr, socklen_t len)
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
p67_sfd_create_from_hint(int * sfd, const char * hostname, const char * service, int flags)
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
                continue;
            }
        }

        if(flags == 2) {
            if(connect(*sfd, cp->ai_addr, cp->ai_addrlen) != 0) {
                close(*sfd);
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

