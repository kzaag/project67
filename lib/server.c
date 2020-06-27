#if !defined(__USE_XOPEN_EXTENDED)
#define __USE_XOPEN_EXTENDED 1
#endif
#include <string.h>

#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/err.h>

#include "err.h"
#include "log.h"
#include "server.h"
#include "client.h"

/*
    used when forwarding user connect to listen_handle
*/
struct p67_conn_pass {
    p67_server_t * server;
    p67_conn_t   * conn;
};

typedef struct p67_conn_pass p67_conn_pass_t;

/* ----begin private prototypes---- */

void *
listen_handle(void * args);

void * 
p67_server_listen_wrapper(void * args);

/* ----end private prototypes---- */

p67_server_t *
p67_server_new(void)
{
    p67_server_t * ret;

    if((ret = calloc(sizeof(*ret), 1)) == NULL) 
        return NULL;
    
    return ret;
}

void
p67_server_free(p67_server_t *  server)
{
    if(server == NULL) return;
    p67_addr_free(&server->addr);
    if(server->certpath != NULL) free(server->certpath);
    if(server->keypath != NULL) free(server->keypath);
}

p67_err
p67_server_set_cert(p67_server_t * server, const char * certpath, const char * keypath)
{
    if(server == NULL) return p67_err_einval;

    if(certpath != NULL) {
        if((server->certpath = strdup(certpath)) == NULL) return p67_err_eerrno;
    }

    if(keypath != NULL) {
        if((server->keypath = strdup(keypath)) == NULL) {
            if(certpath != NULL) free(server->certpath);
            return p67_err_eerrno;
        }
    }

    return 0;
}

p67_err
p67_server_set_callback(p67_server_t * server, p67_callback callback, void * callback_args)
{
    if(server == NULL) return p67_err_einval;

    server->callback = callback;
    server->callback_args = callback_args;

    return 0;
}

void *
listen_handle(void * args)
{
    p67_conn_pass_t * pass;
    p67_err err;
    p67_sfd_t sfd;

    pass = (p67_conn_pass_t *)args;

    if((sfd = SSL_get_fd(pass->conn->ssl)) <= 0) goto end;

    if((err = p67_sfd_get_err(sfd)) != 0) goto end;

    /* if((err = p67_sfd_valid(pass->sfd)) != 0) goto end; */

    p67_err_mask_all(err);
    if(SSL_accept(pass->conn->ssl) != 1) goto end;

    printf("Accepted %s:%s\n", pass->conn->addr.hostname, pass->conn->addr.service);

    err = p67_conn_read(pass->conn, pass->server->callback, pass->server->callback_args);

end:
    p67_client_disconnect(&pass->conn->addr);
    if(err != 0)
        p67_err_print_err(err);
    free(pass);

    return NULL;
}

p67_err
p67_server_start_listen(p67_server_t * server)
{
    pthread_t t;

    return pthread_create(&t, NULL, p67_server_listen_wrapper, server);
}

void * 
p67_server_listen_wrapper(void * args)
{
    p67_err err;
    if((err = p67_server_listen((p67_server_t *)args)) != 0) {
        p67_err_print_err(err);
    }
    pthread_exit(NULL);
}

p67_err
p67_server_listen(p67_server_t * server)
{
    p67_err err;
    SSL_CTX * ctx;
    SSL * ssl;
    p67_conn_pass_t * pass;
    p67_conn_t * conn;
    p67_addr_t addr;
    int fd, sfd, fail, adcerr;
    pthread_t thr;

    ctx = NULL;
    fd = 0;
    p67_err_mask_all(err);
    ERR_clear_error();

    /*
        if server uses generic TLS_server_method, then client can remotely crash server
        if right after SSL_connect he disposes said connection ( server then will crash on SSL_accept )
    */
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
    if((ctx = SSL_CTX_new(TLSv1_2_server_method())) == NULL) goto end;
    //if((SSL_CTX_set_options(ctx, SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3)) != 1) goto end;
#pragma GCC diagnostic pop

    if(SSL_CTX_set_cipher_list(ctx, CIPHER) != 1) goto end;

    if(server->keypath == NULL || server->certpath == NULL) goto end;

    if((SSL_CTX_use_PrivateKey_file(ctx, server->keypath, SSL_FILETYPE_PEM)) != 1) goto end;

    if((SSL_CTX_use_certificate_file(ctx, server->certpath, SSL_FILETYPE_PEM)) != 1) goto end;

    if((SSL_CTX_check_private_key(ctx)) != 1) goto end;

    SSL_CTX_set_read_ahead(ctx, 1);
    SSL_CTX_set_session_cache_mode(ctx, SSL_SESS_CACHE_OFF);

    if((p67_sfd_create_from_hint(&fd, server->addr.hostname, server->addr.service, 1)) != 0) goto end;

    if((p67_sfd_set_reuseaddr(fd)) != 0) goto end;

    if(p67_sfd_listen(fd) != 0) goto end;
    
    DLOG("Listen @ %s:%s\n", server->addr.hostname, server->addr.service);

    while(1) {

        if((sfd = p67_sfd_accept(fd, &addr)) == 0)
            goto end;

        do {
            if((adcerr = p67_client_add_connected(&addr, &conn)) != 0) {
                fail = 1;
                err |= adcerr;
                break;
            }

            if((ssl = SSL_new(ctx)) == NULL) {
                fail = 1;
                break;
            }
            
            if(SSL_set_fd(ssl, sfd) != 1) {
                fail = 1;
                break;
            }

            conn->ssl = ssl;

            if((pass = calloc(sizeof(*pass), 1)) == NULL) {
                fail = 1;
                break;
            }

            pass->server = server;
            pass->conn = conn;

            if(pthread_create(&thr, NULL, listen_handle, pass) != 0) {
                fail = 1;
                break;
            }

            fail = 0;
        } while(0);

        if(fail) {
            if(ssl != NULL) SSL_free(ssl);
            if(sfd > 0) p67_sfd_close(sfd);
            if(pass != NULL) free(pass);
            if(adcerr == 0) p67_client_disconnect(&addr);
            p67_err_print_err(err);
        }
    }

    err = 0;

end:
    if(ctx != NULL) SSL_CTX_free(ctx);
    if(fd > 0) p67_sfd_close(fd); 
    return err;
}