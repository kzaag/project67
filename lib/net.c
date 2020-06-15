#include <fcntl.h>
#include <unistd.h>
#if !defined(__USE_XOPEN_EXTENDED)
#define __USE_XOPEN_EXTENDED 1
#endif
#include <string.h>
#include <stdio.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <time.h>
#include <stdlib.h>
#include <pthread.h>
#include <stdio.h>

#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/err.h>

#include "net.h"
#include "conn.h"
#include "sfd.h"
#include "log.h"

#define CIPHER "ECDHE-ECDSA-AES256-GCM-SHA384"
#define CIPHER_ALT "HIGH:!aNULL:!kRSA:!PSK:!SRP:!MD5:!RC4"

#define fix_port(port) \
    { if((port) < 1050 || (port) > 0xFFFF) (port) = 443; }

/* read buffer length */
#define RBL 120
/* maximum address string length */
#define AL 120

/* ----begin private prototypes---- */

p67_err
p67_conn_assign_callback(p67_conn_t * conn, p67_callback callback, void * args);

#define p67_conn_lock(c) pthread_mutex_trylock(&(conn)->__lock)

#define p67_conn_unlock(c) pthread_mutex_unlock(&(conn)->__lock)

p67_err
p67_conn_assign_peer_addr(
                p67_conn_t * conn, 
                SSL * ssl, 
                struct sockaddr * addr, 
                socklen_t addrl);

p67_err
p67_conn_assign_peer_host(
                p67_conn_t * conn, 
                SSL * ssl, 
                const char * host, 
                const char * svc);

void *
listen_handle(void * args);

/* ----end private prototypes---- */

/*
    Method is not thread safe
*/
p67_err
p67_conn_assign_callback(p67_conn_t * conn, p67_callback callback, void * args)
{
    conn->callback = callback;
    conn->callback_args = args;
    return 0;
}

/*
    Assign connected peer to connection using address
    Method is not thread safe
*/
p67_err
p67_conn_assign_peer_addr(p67_conn_t * conn, SSL * ssl, struct sockaddr * addr, socklen_t addrl)
{
    char cb[AL], svc[10];

    if(conn == NULL || ssl == NULL) return p67_err_einval;

    p67_conn_shutdown(conn);

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

    if((conn->host = strdup(cb)) == NULL) return p67_err_eerrno;
    if((conn->service = strdup(svc)) == NULL) return p67_err_eerrno;

    conn->ssl = ssl;

    return 0;
}

/*
    Assign connected peer to connection using hostname and service.
    Method is not thread safe.
*/
p67_err
p67_conn_assign_peer_host(p67_conn_t * conn, SSL * ssl, const char * host, const char * svc)
{
    p67_err err;

    if(conn == NULL || ssl == NULL) return p67_err_einval;

    p67_conn_shutdown(conn);

    conn->addrl = sizeof(struct sockaddr);
    if((err = p67_sfd_create_address(&conn->addr, &conn->addrl, host, svc)) != 0)
        return err;

    if((conn->host = strdup(host)) == NULL) return p67_err_eerrno;
    if((conn->service = strdup(svc)) == NULL) return p67_err_eerrno;

    conn->ssl = ssl;

    return 0;
}

p67_conn_t *
p67_conn_new(void)
{
    p67_conn_t * conn = NULL;

    if((conn = calloc(sizeof(p67_conn_t), 1)) == NULL) return NULL;

    pthread_mutex_init(&(conn->__lock), NULL);

    return conn;
}

/*
    Method is not thread safe. 
*/
void
p67_conn_free(p67_conn_t * conn)
{
    if(conn == NULL) return;
    p67_conn_shutdown(conn);
    if(conn->host != NULL) free(conn->host);
    if(conn->service != NULL) free(conn->service);
    free(conn);
}

/*
    If connection is open then close it.
    Method is not thread safe.
    If connection is closed then return p67_err_enconn.
*/
p67_err
p67_conn_shutdown(p67_conn_t * conn) 
{
    int sfd;

    if(conn == NULL) return p67_err_enconn;

    if(conn->ssl == NULL) return p67_err_enconn;

    SSL_shutdown(conn->ssl);
    if((sfd = SSL_get_fd(conn->ssl)) > 0)
        close(sfd);
    SSL_free(conn->ssl);
    conn->ssl = NULL;
    DLOG("Shutdown for %s:%s\n", conn->host, conn->service);
    
    return 0;
}

p67_err
p67_conn_read(p67_conn_t * conn)
{
    int len, err;
    char buff[RBL];

    while(conn->ssl != NULL && !(SSL_get_shutdown(conn->ssl) & SSL_RECEIVED_SHUTDOWN)) {

        len = SSL_read(conn->ssl, buff, RBL);
        err = SSL_get_error(conn->ssl, len);
        switch(err) {

        case SSL_ERROR_NONE:
            if(conn->callback == NULL) break;
            if(conn->callback(conn, buff, len, conn->callback_args) != 0) goto end;
        default:
            goto end;
        }
    }

end:
    p67_conn_shutdown(conn);
    if(err != SSL_ERROR_NONE) 
        return p67_err_essl | p67_err_eerrno;
    return 0;
}

/*
    Connect to peer.
    Method is thread safe. 
*/
p67_err
p67_conn_connect(
            p67_conn_t * conn, 
            const char * hostname, 
            const char * service,
            const char * accepted_chain)
{
    SSL * ssl;
    X509 * cert;
    SSL_CTX * ssl_ctx;
    p67_err err;
    //struct sockaddr remote;
    //socklen_t remotel;
    int sfd;

    ERR_clear_error();
    ssl = NULL;
    p67_err_mask_all(err);
    ssl_ctx = NULL;
    //remotel = sizeof(struct sockaddr);
    sfd = -1;

    /**/

    if(p67_conn_lock(conn) != 0) goto end;

    p67_conn_shutdown(conn);
    
    /**/

    if((ssl_ctx = SSL_CTX_new(TLS_client_method())) == NULL) goto end;

    SSL_CTX_set_verify(ssl_ctx, SSL_VERIFY_PEER, NULL);

    SSL_CTX_set_options(ssl_ctx, SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3);

    SSL_CTX_set_verify_depth(ssl_ctx, 4);
    SSL_CTX_set_read_ahead(ssl_ctx, 1);

    if(SSL_CTX_load_verify_locations(ssl_ctx, accepted_chain, NULL) != 1) 
        goto end;

    /**/

    if((ssl = SSL_new(ssl_ctx)) == NULL) goto end;

    if(p67_sfd_create_from_hint(&sfd, hostname, service, 2) != 0) goto end;

    //if(p67_sfd_create_address(&remote, &remotel, hostname, service) != 0) goto end;
    //if((sfd = socket(remote.sa_family, SOCK_STREAM, 0)) <= 0) goto end;
    //if(p67_sfd_set_keepalive(sfd) != 0) goto end;
    //if(connect(sfd, &remote, remotel) != 0) goto end;

    if(SSL_set_cipher_list(ssl, CIPHER_ALT) != 1) goto end;

    if(SSL_set_tlsext_host_name(ssl, hostname) != 1) goto end;

    if(SSL_set_fd(ssl, sfd) != 1) goto end;

    if(SSL_connect(ssl) != 1) {
        goto end;
    }

    if((cert = SSL_get_peer_certificate(ssl)) == NULL) goto end;
    X509_free(cert);

    if(SSL_get_verify_result(ssl) != X509_V_OK) goto end;

    if(p67_conn_assign_peer_host(conn, ssl, hostname, service) != 0) goto end;

    DLOG("Connected to %s:%s\n", hostname, service);

    err = 0;

end:
    if(ssl_ctx != NULL) SSL_CTX_free(ssl_ctx);
    if(err != 0) {
        if(ssl != NULL) SSL_free(ssl);
        if(sfd > 0) close(sfd);
    }
    p67_conn_unlock(conn);
    return err;
}

void *
listen_handle(void * args)
{
    p67_conn_t * c;
    p67_err err;

    p67_err_mask_all(err);
    c = (p67_conn_t *)args;

    if(SSL_accept(c->ssl) != 1) goto end;

    err = p67_conn_read(c);

end:
    if(err != 0) {
        printf("In listen handle: ");
        p67_err_print_err(err);
        printf("\n");
    }
    
    p67_conn_shutdown(c);
    free(c);

    return NULL;
}

p67_err
p67_conn_listen(
    const char * hostname, 
    const char * service, 
    const char * certpath, 
    const char * keypath,
    p67_callback callback,
    void * callback_args)
{
    p67_err err;
    SSL_CTX * ctx;
    SSL * ssl;
    struct sockaddr addr;
    struct conn * pass;
    socklen_t addrl;
    int fd, sfd;
    pthread_t thr;

    ctx = NULL;
    fd = 0;
    p67_err_mask_all(err);
    ERR_clear_error();

    if((ctx = SSL_CTX_new(TLS_server_method())) == NULL) goto end;

    if((SSL_CTX_set_options(ctx, SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3)) != 1) goto end;

    if(SSL_CTX_set_cipher_list(ctx, CIPHER) != 1) goto end;

    if((SSL_CTX_use_PrivateKey_file(ctx, keypath, SSL_FILETYPE_PEM)) != 1) goto end;

    if((SSL_CTX_use_certificate_file(ctx, certpath, SSL_FILETYPE_PEM)) != 1) goto end;

    if((SSL_CTX_check_private_key(ctx)) != 1) goto end;

    SSL_CTX_set_read_ahead(ctx, 1);
    SSL_CTX_set_session_cache_mode(ctx, SSL_SESS_CACHE_OFF);

    if((p67_sfd_create_from_hint(&fd, hostname, service, 1)) != 0) goto end;

    if(listen(fd, -1) != 0) goto end;

    while(1) {
        if((sfd = accept(fd, &addr, &addrl)) != 0) {
            DLOG("%s\n", strerror(errno));
            continue;
        }
        if((ssl = SSL_new(ctx)) == NULL) goto end;
        if(SSL_set_fd(ssl, sfd) != 1) goto end;

        if((pass = p67_conn_new()) == NULL) goto end;

        if(p67_conn_assign_peer_addr(pass, ssl, &addr, addrl) != 0) goto end;

        p67_conn_assign_callback(pass, callback, callback_args);

        // if((pass = malloc(sizeof(struct conn))) == NULL) goto end;
        // pass->addr = addr;
        // pass->addrl = addrl;
        // pass->ssl = ssl;

        if(pthread_create(&thr, NULL, listen_handle, pass) != 0) goto end;
    }

    err = 0;

end:
    if(ctx != NULL) SSL_CTX_free(ctx);
    if(fd > 0) close(fd); 
    return err;
}
