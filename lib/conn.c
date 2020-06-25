#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <time.h>
#include <stdlib.h>
#include <pthread.h>
#include <stdio.h>
#if !defined(__USE_XOPEN_EXTENDED)
#define __USE_XOPEN_EXTENDED 1
#endif
#include <string.h>

#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/err.h>

#include "conn.h"
#include "sfd.h"
#include "log.h"
#include "conn.h"

#define CIPHER "ECDHE-ECDSA-AES256-GCM-SHA384"
#define CIPHER_ALT "HIGH:!aNULL:!kRSA:!PSK:!SRP:!MD5:!RC4"

#define fix_port(port) \
    { if((port) < 1050 || (port) > 0xFFFF) (port) = 443; }

/* read buffer length */
#define RBL 120

p67_err
p67_conn_set_trusted_chain_path(p67_conn_t * conn, const char * path)
{
    if(conn->trusted_chain != NULL) free(conn->trusted_chain);
    if((conn->trusted_chain = strdup(path)) == NULL) return p67_err_eerrno;
    return 0;
}

p67_conn_t *
p67_conn_new(void)
{
    p67_conn_t * conn = NULL;

    if((conn = calloc(sizeof(p67_conn_t), 1)) == NULL) return NULL;

    return conn;
}

void
p67_conn_free_deps(p67_conn_t * conn)
{
    if(conn == NULL) return;
    p67_conn_shutdown(conn);
    p67_addr_free(&conn->addr);
    if(conn->trusted_chain != NULL) free(conn->trusted_chain);
}

/*
    Method is not thread safe. 
*/
void
p67_conn_free(p67_conn_t * conn)
{
    if(conn == NULL) return;
    p67_conn_free_deps(conn);
    free(conn);
}

/*
    1 = is connected
    0 = is not connected
*/
int
p67_conn_is_connected(p67_conn_t * conn)
{
    if(conn == NULL || conn->ssl == NULL) return 0;

    return 1;
}

/*
    If connection is open then close it.
    Method is not thread safe.
    If connection is closed then return p67_err_enconn.
    Connection cannot be freed before
*/
p67_err
p67_conn_shutdown(p67_conn_t * conn) 
{
    int sfd;

    if(conn == NULL) return p67_err_enconn;

    if(conn->ssl == NULL) return p67_err_enconn;

    sfd = SSL_get_fd(conn->ssl);

    if( p67_sfd_get_err(sfd) == 0 && 
        !(SSL_get_shutdown(conn->ssl) & (SSL_RECEIVED_SHUTDOWN | SSL_SENT_SHUTDOWN)))
        SSL_shutdown(conn->ssl);

    close(sfd);

    SSL_free(conn->ssl);
    conn->ssl = NULL;
    DLOG("Shutdown %s:%s\n", conn->addr.hostname, conn->addr.service);
    
    return 0;
}


/* ----begin private prototypes---- */

p67_err
p67_conn_assign_callback(p67_conn_t * conn, p67_callback callback, void * args);

#define p67_conn_lock(c) pthread_mutex_trylock(&(conn)->__lock)

#define p67_conn_unlock(c) pthread_mutex_unlock(&(conn)->__lock)

void *
listen_handle(void * args);

/* ----end private prototypes---- */

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
            break;
        case SSL_ERROR_ZERO_RETURN:
            err = 0;
            goto end;
        case SSL_ERROR_SYSCALL:
            if(errno == ECONNRESET) {
                SSL_set_shutdown(conn->ssl, SSL_RECEIVED_SHUTDOWN);
                goto end;
            }
            // could be eagain or ewouldblock
            break;
        default:
            goto end;
        }
    }

end:
    p67_conn_shutdown(conn);
    if(err != 0) {
        return p67_err_essl | p67_err_eerrno;
    }
    return 0;
}

/*
    Connect to peer.
*/
p67_err
p67_conn_connect(p67_conn_t * conn)
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

    if(conn == NULL || !p67_addr_is_initialized(&conn->addr))
        return p67_err_einval;

    if((ssl_ctx = SSL_CTX_new(TLS_client_method())) == NULL) goto end;

    SSL_CTX_set_verify(ssl_ctx, SSL_VERIFY_PEER, NULL);

    SSL_CTX_set_options(ssl_ctx, SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3);

    SSL_CTX_set_mode(ssl_ctx, SSL_MODE_AUTO_RETRY);

    SSL_CTX_set_verify_depth(ssl_ctx, 4);
    SSL_CTX_set_read_ahead(ssl_ctx, 1);

    if(conn->trusted_chain != NULL && SSL_CTX_load_verify_locations(ssl_ctx, conn->trusted_chain, NULL) != 1)
        goto end;

    /**/

    if((ssl = SSL_new(ssl_ctx)) == NULL) goto end;

    if(p67_sfd_create_from_hint(&sfd, conn->addr.hostname, conn->addr.service, 2) != 0) goto end;

    //if(p67_sfd_create_address(&remote, &remotel, hostname, service) != 0) goto end;
    //if((sfd = socket(remote.sa_family, SOCK_STREAM, 0)) <= 0) goto end;
    //if(p67_sfd_set_keepalive(sfd) != 0) goto end;
    //if(connect(sfd, &remote, remotel) != 0) goto end;

    if(SSL_set_cipher_list(ssl, CIPHER_ALT) != 1) goto end;

    if(SSL_set_tlsext_host_name(ssl, conn->addr.hostname) != 1) goto end;

    if(SSL_set_fd(ssl, sfd) != 1) goto end;

    if(SSL_connect(ssl) != 1) goto end;

    if((cert = SSL_get_peer_certificate(ssl)) == NULL) goto end;
    X509_free(cert);

    if(SSL_get_verify_result(ssl) != X509_V_OK) goto end;

    conn->ssl = ssl;

    DLOG("Connected to %s:%s\n", conn->addr.hostname, conn->addr.service);

    err = 0;

end:
    if(ssl_ctx != NULL) SSL_CTX_free(ssl_ctx);
    if(err != 0) {
        if(ssl != NULL) SSL_free(ssl);
        if(sfd > 0) close(sfd);
    }
    return err;
}

void *
listen_handle(void * args)
{
    p67_conn_t * c;
    p67_err err;
    int sfd;

    p67_err_mask_all(err);
    c = (p67_conn_t *)args;

    if((sfd = SSL_get_fd(c->ssl)) <= 0) goto end;
    if(p67_sfd_get_err(sfd) != 0) goto end;

    if(SSL_accept(c->ssl) != 1) goto end;

    printf("Accepted %s:%s\n", c->addr.hostname, c->addr.service);

    err = p67_conn_read(c);

end:
    if(err != 0) p67_err_print_err(err);
    p67_conn_shutdown(c);
    free(c);

    return NULL;
}

p67_err
p67_conn_write(p67_conn_t * conn, char * arr, int arrl, int flags)
{
    int err;

    if((flags & 1) && !p67_conn_is_connected(conn)) p67_conn_connect(conn);

    if(conn->ssl == NULL) return p67_err_enconn;

    while(1) {
        if((err = SSL_write(conn->ssl, arr, arrl)) > 0) {
            err = 0;
            break;
        }
        err = SSL_get_error(conn->ssl, err);
        switch (err)
        {
        case SSL_ERROR_WANT_WRITE:
        case SSL_ERROR_WANT_READ:
            break;
        default:
            goto end;
        }
    }

end:
    if(err != 0) 
        return p67_err_essl;

    return 0;
}

// p67_err
// p67_conn_listen(
//     const char * hostname, 
//     const char * service, 
//     const char * certpath, 
//     const char * keypath,
//     p67_callback callback,
//     void * callback_args)
// {
//     p67_err err;
//     SSL_CTX * ctx;
//     SSL * ssl;
//     struct sockaddr saddr;
//     struct p67_conn * pass;
//     p67_addr_t aaddr;
//     socklen_t addrl;
//     int fd, sfd;
//     pthread_t thr;

//     ctx = NULL;
//     fd = 0;
//     p67_err_mask_all(err);
//     ERR_clear_error();
//     addrl = sizeof(saddr);

//     if((ctx = SSL_CTX_new(TLS_server_method())) == NULL) goto end;

//     //if((SSL_CTX_set_options(ctx, SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3)) != 1) goto end;

//     if(SSL_CTX_set_cipher_list(ctx, CIPHER) != 1) goto end;

//     if((SSL_CTX_use_PrivateKey_file(ctx, keypath, SSL_FILETYPE_PEM)) != 1) goto end;

//     if((SSL_CTX_use_certificate_file(ctx, certpath, SSL_FILETYPE_PEM)) != 1) goto end;

//     if((SSL_CTX_check_private_key(ctx)) != 1) goto end;

//     SSL_CTX_set_read_ahead(ctx, 1);
//     SSL_CTX_set_session_cache_mode(ctx, SSL_SESS_CACHE_OFF);

//     if((p67_sfd_create_from_hint(&fd, hostname, service, 1)) != 0) goto end;

//     if((p67_sfd_set_reuseaddr(fd)) != 0) goto end;

//     if(listen(fd, -1) != 0) goto end;
    
//     DLOG("Listen @ %s:%s\n", hostname, service);

//     while(1) {
//         if((sfd = accept(fd, &saddr, &addrl)) < 0) {
//             DLOG("%s\n", strerror(errno));
//             continue;
//         }

//         if((ssl = SSL_new(ctx)) == NULL) goto end;
//         if(SSL_set_fd(ssl, sfd) != 1) goto end;

//         if((pass = p67_conn_new()) == NULL) goto end;

//         if(p67_addr_set_sockaddr(&addr, &saddr, addrl) != 0) goto end;
        
//         pass->ssl = ssl;
//         pass->haddr = haddr;
//         pass->callback = callback;
//         pass->callback_args = callback_args;

//         // if((pass = malloc(sizeof(struct conn))) == NULL) goto end;
//         // pass->addr = addr;
//         // pass->addrl = addrl;
//         // pass->ssl = ssl;

//         if(pthread_create(&thr, NULL, listen_handle, pass) != 0) goto end;
//     }

//     err = 0;

// end:
//     if(ctx != NULL) SSL_CTX_free(ctx);
//     if(fd > 0) close(fd); 
//     return err;
// }
