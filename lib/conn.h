#if !defined(CONNDEF_H)
#define CONNDEF_H

#include <sys/socket.h>
#include <openssl/ssl.h>
#include "net.h"

struct conn {
    SSL             * ssl;
    char            * host;
    char            * service;
    
    struct sockaddr addr;
    socklen_t       addrl;

    p67_callback    callback;
    void *          callback_args;

    pthread_mutex_t __lock;
};

#endif
