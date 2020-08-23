#include "sfd.h"
#include "conn.h"
#include "log.h"

#include <sys/time.h>
#include <assert.h>
#include <string.h>
#include <openssl/ssl.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <errno.h>

typedef struct p67_conn p67_conn_t;

/*
    Structure representing physical established connections.
    All connections are kept in conn_cache hash table.
*/
struct p67_conn {
    p67_timeout_t * timeout;
    p67_addr_t * addr_remote;
    p67_addr_t * addr_local;
    SSL * ssl;
    p67_conn_callback_t callback;
    void * args;
    p67_conn_free_args_cb free_args;
    p67_thread_sm_t hread;
    p67_async_t lock;
    unsigned int sig_term : 1,
                 heap_alloc : 1;
};

P67_CMN_NO_PROTO_ENTER
p67_err
p67_conn_lock(
P67_CMN_NO_PROTO_EXIT
    p67_conn_t * conn)
{
    p67_spinlock_lock(&conn->lock);

    if(conn->sig_term)
        return p67_err_enconn;

    return 0;
}

#define p67_conn_unlock(c) \
    p67_spinlock_unlock(&c->lock)

#define COOKIE_SECRET_LENGTH 32

struct p67_conn_globals {
    p67_conn_config_t config;
    p67_hashcntl_t * conn_cache;
    p67_async_t conn_cache_ini_lock;
    p67_hashcntl_t * node_cache;
    p67_async_t node_cache_ini_lock;

    unsigned char cookie_secret[COOKIE_SECRET_LENGTH];
    p67_async_t cookie_secret_lock;

    unsigned int conn_initialized : 1,
                 nodes_initialized : 1,
                 cookie_initialized : 1;
};

struct p67_conn_globals __globals = {
    .config = {
        .conn_auth = P67_CONN_AUTH_LIMIT_TRUST_UNKNOWN,
        .timeout_duration_ms = 10*1000,
    },
    .conn_cache_ini_lock = P67_ASYNC_INTIIALIZER,
    .node_cache_ini_lock = P67_ASYNC_INTIIALIZER,
    .cookie_secret_lock = P67_ASYNC_INTIIALIZER,
    .conn_initialized = 0,
    .nodes_initialized = 0,
    .cookie_initialized = 0,
};

p67_conn_config_t *
p67_conn_config_location(void)
{
    return &__globals.config;
}

#define CONN_CACHE_LEN 337
#define NODE_CACHE_LEN 337

void
__p67_conn_free(p67_hashcntl_entry_t * entry);

void
__p67_node_free(p67_hashcntl_entry_t * entry);

p67_hashcntl_t *
p67_conn_cache(void) {
    if(!__globals.conn_initialized) {
        p67_spinlock_lock(&__globals.conn_cache_ini_lock);
        if(!__globals.conn_initialized) {
            __globals.conn_cache = p67_hashcntl_new(
                CONN_CACHE_LEN, __p67_conn_free, NULL);
            p67_cmn_assert_abort(
                !__globals.conn_cache, 
                "Couldnt initialize connection cache.");
            __globals.conn_initialized = 1;
        }
        p67_spinlock_unlock(&__globals.conn_cache_ini_lock);
    }

    return __globals.conn_cache;
}

p67_hashcntl_t *
p67_conn_node_cache(void) {
    if(!__globals.nodes_initialized) {
        p67_spinlock_lock(&__globals.node_cache_ini_lock);
        if(!__globals.nodes_initialized) {
            __globals.node_cache = p67_hashcntl_new(
                NODE_CACHE_LEN, __p67_node_free, NULL);
            p67_cmn_assert_abort(
                !__globals.node_cache, "Couldnt initialize node cache.");
            __globals.nodes_initialized = 1;
        }
        p67_spinlock_unlock(&__globals.node_cache_ini_lock);
    }

    return __globals.node_cache;
}

struct p67_conn_globals * 
p67_conn_globals_location(void)
{
    return &__globals;
}

#define p67_conn_globals_value (*p67_net_globals_location())


#define P67_CONN_DEFAULT_TIMEOUT_MS 200

/* sleep ms = P67_MIN_SLEEP_MS + [0 - P67_MOD_SLEEP_MS] */
#define P67_CONN_MIN_SLEEP_MS 500
#define P67_CONN_MOD_SLEEP_MS 1000

#define CIPHER "ECDHE-ECDSA-AES256-GCM-SHA384"
//#define CIPHER_ALT "HIGH:!aNULL:!kRSA:!PSK:!SRP:!MD5:!RC4"

p67_err
p67_conn_shutdown(p67_addr_t * addr)
{
    if(!addr) return p67_err_einval;
    return p67_hashcntl_remove_and_free(
        p67_conn_cache(), 
        (unsigned char *)&addr->sock, addr->socklen);
}

void
__p67_conn_free(p67_hashcntl_entry_t * entry)
{
    assert(entry);

    int sfd;
    p67_conn_t * conn = (p67_conn_t *)entry->value;

    if(conn->free_args != NULL)
        conn->free_args(conn->args);

    if(conn->sig_term)
        return;

    if(p67_conn_lock(conn) != 0)
        return;

    conn->sig_term = 1;
    if(conn->ssl) SSL_shutdown(conn->ssl);
    p67_thread_sm_terminate(&conn->hread, 500);

    p67_conn_unlock(conn);

    /* give everyone waiting some time to terminate */
    p67_cmn_sleep_ms(100);

    if(conn->ssl) {
        SSL_shutdown(conn->ssl);
        if((sfd = SSL_get_fd(conn->ssl)) > 0) 
            p67_sfd_close(sfd);
        SSL_free(conn->ssl);
        conn->ssl = NULL;
    }

    p67_log_debug(
        "Shutdown for %s:%s\n", 
        conn->addr_remote->hostname, 
        conn->addr_remote->service);

    p67_addr_free(conn->addr_local);
    p67_addr_free(conn->addr_remote);

    if(conn->heap_alloc)
        free(conn);
    free(entry);
    
    return;
}

P67_CMN_NO_PROTO_ENTER
p67_conn_t *
p67_conn_lookup(
P67_CMN_NO_PROTO_EXIT
    const p67_addr_t * addr)
{
    p67_hashcntl_entry_t * entry = p67_hashcntl_lookup(
        p67_conn_cache(), 
        (unsigned char *)&addr->sock,
        addr->socklen);
    if(!entry) return NULL;
    return (p67_conn_t *)entry->value;
}

p67_node_t *
p67_node_lookup(p67_addr_t * addr)
{
    if(!addr) return NULL;
    p67_hashcntl_entry_t * entry = p67_hashcntl_lookup(
        p67_conn_node_cache(), 
        (unsigned char *)&addr->sock,
        addr->socklen);
    if(!entry) return NULL;
    return (p67_node_t *)entry->value;
}

void
__p67_node_free(p67_hashcntl_entry_t * ptr)
{
    assert(ptr);
    
    p67_node_t * node = (p67_node_t *)ptr->value;

    if(node == NULL) return;

    p67_addr_free(node->trusted_addr);
    free(node->trusted_pub_key);

    if(node->heap_alloc)
        free(node);
    free(ptr);
}

P67_CMN_NO_PROTO_ENTER
p67_conn_t *
p67_conn_insert(
P67_CMN_NO_PROTO_EXIT
    p67_addr_t * addr_local,
    p67_addr_t * addr_remote,
    SSL * ssl,
    p67_conn_callback_t cb,
    void * args, 
    p67_conn_free_args_cb free_args_cb,
    p67_async_t lock,
    p67_timeout_t * timeout)
{

    assert(addr_local);
    assert(addr_remote);

    p67_addr_t * localcpy = NULL, * remotecpy = NULL;
    p67_hashcntl_entry_t * entry = NULL;
    p67_conn_t * ret = NULL;

    localcpy = p67_addr_ref_cpy(addr_local);
    remotecpy = p67_addr_ref_cpy(addr_remote);

    if(!localcpy || !remotecpy) goto end;
    
    entry = malloc(
        sizeof(p67_hashcntl_entry_t) +  // entry
        remotecpy->socklen +           // key
        sizeof(p67_conn_t));           // value

    if(!entry) goto end;

    entry->key = (unsigned char*)entry + sizeof(p67_hashcntl_entry_t);
    entry->keyl = remotecpy->socklen;
    entry->next = NULL;
    entry->value = entry->key + remotecpy->socklen;
    entry->valuel = sizeof(p67_conn_t);

    ret = (p67_conn_t *)entry->value;
    memset(ret, 0, sizeof(p67_conn_t));
    ret->addr_local = localcpy;
    ret->addr_remote = remotecpy;
    ret->args = args;
    ret->callback = cb;
    ret->free_args = free_args_cb;
    ret->lock = lock;
    ret->ssl = ssl;
    ret->timeout = timeout;

    memcpy(entry->key, &remotecpy->sock, remotecpy->socklen);

    if(p67_hashcntl_add(p67_conn_cache(), entry) != 0)
        goto end;

    return ret;

end:
    p67_addr_free(localcpy);
    p67_addr_free(remotecpy);
    free(entry);

    return NULL;
}

p67_node_t *
p67_conn_node_insert(
    p67_addr_t * addr,
    const char * trusted_key,
    int trusted_key_l,
    int node_state)
{
    p67_hashcntl_entry_t * entry = NULL;
    p67_addr_t * addrcpy = NULL;
    
    addrcpy = p67_addr_ref_cpy(addr);
    if(!addrcpy) return NULL;

    entry = malloc(
        sizeof(p67_hashcntl_entry_t) + 
        addr->socklen + 
        sizeof(p67_node_t) + 
        trusted_key_l + 1);
    
    if(!entry) goto end;

    entry->key = (unsigned char *)entry + sizeof(p67_hashcntl_entry_t);
    entry->keyl = addr->socklen;
    entry->next = NULL;
    entry->value = entry->key + addr->socklen;
    entry->valuel = sizeof(p67_node_t);

    memcpy(entry->key, &addr->sock, addr->socklen);

    p67_node_t * node = (p67_node_t *)entry->value;
    node->heap_alloc = 0;
    node->state = node_state;
    node->trusted_addr = addrcpy;
    node->trusted_pub_key = (char *)(entry->value + entry->valuel);

    memcpy(node->trusted_pub_key, trusted_key, trusted_key_l + 1);
    node->trusted_pub_key[trusted_key_l] = 0;

    if(p67_hashcntl_add(p67_conn_node_cache(), entry) != 0)
        goto end;

    return node;

end:
    p67_addr_free(addrcpy);
    free(entry);

    return NULL;
}

P67_CMN_NO_PROTO_ENTER
int
p67_net_generate_cookie_callback(
P67_CMN_NO_PROTO_EXIT
    SSL *ssl, unsigned char *cookie, unsigned int *cookie_len)
{
	unsigned char result[EVP_MAX_MD_SIZE];
	unsigned int resultlength;
	p67_sockaddr_t peer;

    if(!__globals.cookie_initialized) {
        p67_spinlock_lock(&__globals.cookie_secret_lock);
        if (!__globals.cookie_initialized) {
            p67_cmn_assert_abort(
                !RAND_bytes(__globals.cookie_secret, COOKIE_SECRET_LENGTH),
                "Couldnt initialize cookie secret")
            __globals.cookie_initialized = 1;
        }
        p67_spinlock_unlock(&__globals.cookie_secret_lock);
    }

    bzero(&peer, sizeof(p67_sockaddr_t));
	(void)BIO_dgram_get_peer(SSL_get_rbio(ssl), &peer);

	HMAC(
        EVP_sha1(), 
        (const void*) __globals.cookie_secret, 
        COOKIE_SECRET_LENGTH,
	    (const unsigned char *)&peer, sizeof(p67_sockaddr_t), 
        result, &resultlength);

	memcpy(cookie, result, resultlength);
	*cookie_len = resultlength;

	return 1;
}

P67_CMN_NO_PROTO_ENTER
int 
p67_net_verify_cookie_callback(
P67_CMN_NO_PROTO_EXIT
    SSL *ssl, const unsigned char *cookie, unsigned int cookie_len)
{
	unsigned char result[EVP_MAX_MD_SIZE];
	unsigned int resultlength;
	p67_sockaddr_t peer;

    /* cookie must havee been initialized at this point */
	assert(__globals.cookie_initialized);

    bzero(&peer, sizeof(p67_sockaddr_t));
	(void)BIO_dgram_get_peer(SSL_get_rbio(ssl), &peer);

	HMAC(
        EVP_sha1(), 
        (const void*) __globals.cookie_secret, COOKIE_SECRET_LENGTH,
	    (const unsigned char*)&peer, sizeof(p67_sockaddr_t), 
        result, &resultlength);

	if (cookie_len == resultlength && 
            memcmp(result, cookie, resultlength) == 0) return 1;

	return 0;
}

P67_CMN_NO_PROTO_ENTER
void *
p67_conn_run_read_loop(
P67_CMN_NO_PROTO_EXIT
    void * args)
{
    assert(args);
    ssize_t len;
    BIO * bio;
    // if no message arrives for max_rcvto_ms miliseconds then close connection
    const int max_rcvto_ms = 10000;
    /* TODO this one should be set to MTU */
    const int read_buffer_length = 512;
    const int err_buff_length = 128;

    p67_pckt_t rbuff[read_buffer_length];
    char errbuf[err_buff_length];
    int num_timeouts = 0, max_timeouts, sslr = 1, 
        err, callret, rcvto_ms;
    p67_conn_t * conn = (p67_conn_t *)args;
    p67_addr_t * remote = p67_addr_ref_cpy(conn->addr_remote);

    assert(remote);

    p67_sfd_t sfd;

    p67_err_mask_all(err);
    
    if((bio = SSL_get_rbio(conn->ssl)) == NULL) goto end;
    
    if((sfd = SSL_get_fd(conn->ssl)) < 0) goto end;

    if(p67_sfd_get_timeouts(sfd, NULL, &rcvto_ms) != 0)
        goto end;

    max_timeouts = max_rcvto_ms / rcvto_ms;

    while(!(SSL_get_shutdown(conn->ssl) & SSL_RECEIVED_SHUTDOWN) && num_timeouts < max_timeouts) {
        sslr = 1;
        while(sslr) {
            if(conn->hread.state != P67_THREAD_SM_STATE_RUNNING) {
                err = 0;
                goto end;
            }

            len = SSL_read(conn->ssl, rbuff, read_buffer_length);

            if(conn->hread.state != P67_THREAD_SM_STATE_RUNNING) {
                err = 0;
                goto end;
            }

            err = SSL_get_error(conn->ssl, len);

            switch (err) {
            case SSL_ERROR_NONE:
                if(conn->callback == NULL) break;
                callret = (*conn->callback)(remote, rbuff, len, conn->args);
                if(callret != 0) {
                    err = callret;
                    if(conn->timeout) {
                        if((callret = p67_timeout_addr_for_epoch(
                                conn->timeout, 
                                remote, 
                                __globals.config.timeout_duration_ms,
                                0)) != 0)
                            p67_err_print_err("couldnt timeout peer, error was: ", callret);
                        p67_log_debug(
                            "Timeout %s:%s due to error/s for %d ms.\n", 
                            remote->hostname, 
                            remote->service, 
                            __globals.config.timeout_duration_ms);
                    } else {
                        if((callret = p67_timeout_addr(remote, 0)) != 0)
                            p67_err_print_err("couldnt timeout peer, error was: ", callret);
                        p67_log_debug(
                            "Timeout %s:%s due to error/s indefinitely.\n", 
                            remote->hostname, remote->service);
                    }
                    p67_err_print_err("Terminating connection with error/s: ", err);
                    goto end;
                }
                num_timeouts = 0;
                break;
            case SSL_ERROR_WANT_READ:
                if (BIO_ctrl(bio, BIO_CTRL_DGRAM_GET_RECV_TIMER_EXP, 0, NULL)) {
					num_timeouts++;
					sslr = 0;
				}
                break;
            case SSL_ERROR_ZERO_RETURN:
                goto end;
            case SSL_ERROR_SYSCALL:
                if(errno == EAGAIN || errno == EWOULDBLOCK)
                    break;
                p67_log_debug("ssl_read: %d : %s\n", errno, strerror(errno));
                goto end;
            default:
                p67_log_debug("in read loop: %s\n", ERR_error_string(err, errbuf));
                sslr = 0;
                break;
            }
        }
    }

    end:
    //p67_log_debug("Leaving read loop\n");
    
    err |= p67_mutex_set_state(
        &conn->hread.state, 
        conn->hread.state, 
        P67_THREAD_SM_STATE_STOP);

    if(err != 0) p67_conn_shutdown(remote);
    p67_addr_free(remote);
    return NULL;
}

P67_CMN_NO_PROTO_ENTER
p67_err
p67_conn_start_read_loop(
P67_CMN_NO_PROTO_EXIT
    p67_conn_t * conn)
{
    return p67_thread_sm_start(
        &conn->hread,
        p67_conn_run_read_loop,
        conn);
}

P67_CMN_NO_PROTO_ENTER
p67_err
p67_conn_get_addr_from_x509_store_ctx(
P67_CMN_NO_PROTO_EXIT
    X509_STORE_CTX *ctx, p67_addr_t * addr) 
{
    int sfd, sslix;
    SSL * ssl;

    if(ctx == NULL) return p67_err_einval;

    if((sslix = SSL_get_ex_data_X509_STORE_CTX_idx()) < 0) {
        return p67_err_essl | p67_err_eerrno;
    }

    if((ssl = X509_STORE_CTX_get_ex_data(ctx, sslix)) == NULL) {
        return p67_err_essl | p67_err_eerrno;
    }

    if((sfd = SSL_get_fd(ssl)) <= 0) {
        return p67_err_essl | p67_err_eerrno;
    }

    if(p67_sfd_get_peer_name(sfd, addr) != 0)
        return p67_err_essl | p67_err_eerrno;

    return 0;
}

#define P67_PEM_CERT   1
#define P67_PEM_PUBKEY 2

#define p67_conn_get_cert_str(x509) \
    p67_conn_get_pem_str(x509, P67_PEM_CERT);

/*
    returned value must be freed after using
    if NULL is returned seek error in p67_err_essl | p67_err_eerrno

    type:
    1 for certififate ( is default )
    2 for public key
*/
P67_CMN_NO_PROTO_ENTER
char * 
p67_conn_get_pem_str(
P67_CMN_NO_PROTO_EXIT
    X509 * x509, int type)
{
    BIO * bio;
    X509_PUBKEY * xpubk = NULL;
    EVP_PKEY * pubk = NULL;
    char * outbuff;
    uint64_t wrote;
    int err = 1;

    if((bio = BIO_new(BIO_s_mem())) == NULL) {
        goto end;
    }

    switch(type) {
    case 2:

        if((xpubk = X509_get_X509_PUBKEY(x509)) == NULL) {
            goto end;
        }

        if((pubk = X509_PUBKEY_get(xpubk)) == NULL) {
            goto end;
        }

        if(PEM_write_bio_PUBKEY(bio, pubk) != 1) {
            goto end;
        }

        break;
    case 1:
    default:
        if(PEM_write_bio_X509(bio, x509) != 1) {
            goto end;
        }
    }

    wrote = BIO_number_written(bio);

    if((outbuff = malloc(wrote + 1)) == NULL) {
        goto end;
    }

    if(BIO_read(bio, outbuff, wrote + 1) <= 0) {
        free(outbuff);
        goto end;
    }

    outbuff[wrote] = 0;
    err = 0;
    
    end:
    if(bio != NULL) BIO_free(bio);
    if(pubk != NULL) EVP_PKEY_free(pubk);
    return err == 0 ? outbuff : NULL;
}

P67_CMN_NO_PROTO_ENTER
int 
p67_net_verify_ssl_callback(
P67_CMN_NO_PROTO_EXIT
    int ok, X509_STORE_CTX *ctx) 
{
    p67_addr_t * peer_addr = NULL;
    X509 * x509 = NULL;
    char *pubk = NULL;
    int cnix, success = 0, asnl;
    X509_NAME * x509_name = NULL;
    X509_NAME_ENTRY * ne = NULL;
    ASN1_STRING * castr = NULL;
    EVP_PKEY * pkey = NULL;
    p67_node_t * node = NULL;

    /* 
        this is neccessary because this callback will be called multiple times for one connection 
        To prevent this code running more than once ( per handshake ), 
        forward only after all evaluation errors pass ( and ok = 1 )
        if err is different than selfsigned then just reject connection.
    */
    if(!ok) {
        if(X509_STORE_CTX_get_error(ctx) == X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT) {
            return 1;
        } else {
            return 0;
        }
    }

    success = 0;

    if(!(peer_addr = p67_addr_new())) {
        goto end;
    }

    if(p67_conn_get_addr_from_x509_store_ctx(ctx, peer_addr) != 0)
        goto end;

    /* 
        if remote was already queued and their ssl conn closed then block them 
    */
    if((node = p67_node_lookup(peer_addr)) != NULL 
            && (node->state & P67_NODE_STATE_QUEUE)) {
        X509_STORE_CTX_set_error(ctx, X509_V_ERR_CERT_REVOKED);
        goto end;
    }

    if((x509 = X509_STORE_CTX_get_current_cert(ctx)) == NULL) {
        goto end;
    }

    if((pubk = p67_conn_get_pem_str(x509, P67_PEM_PUBKEY)) == NULL) {
        goto end;
    }

    /* 
        if remote is first timer then allow them to connect ( but queue them )
        we will warn user about new peer
    */
    if(node == NULL) {
        switch(__globals.config.conn_auth) {
        case P67_CONN_AUTH_LIMIT_TRUST_UNKNOWN:
            p67_log_debug("Unknown host connecting from %s:%s with public key:\n%s", 
                peer_addr->hostname, peer_addr->service, pubk);
            if(!p67_conn_node_insert(peer_addr, pubk, strlen(pubk), P67_NODE_STATE_QUEUE)) {
                p67_log("In ssl_validate_cb: couldnt insert node\n");
                goto end;
            }
            success = 1;
            break;
        case P67_CONN_AUTH_TRUST_UNKOWN:
            if(!p67_conn_node_insert(peer_addr, pubk, strlen(pubk), P67_NODE_STATE_NODE)) {
                p67_log("In ssl_validate_cb: couldnt insert node\n");
                goto end;
            }
            success = 1;
            break;
        case P67_CONN_AUTH_DONT_TRUST_UNKOWN:
            p67_log_debug("Rejected Unknown Host ( %s:%s )\n", 
                peer_addr->hostname, peer_addr->service);
            if(!p67_conn_node_insert(peer_addr, pubk, strlen(pubk), P67_NODE_STATE_QUEUE)) {
                p67_log("In ssl_validate_cb: couldnt insert node\n");
                goto end;
            }
            break;
        default:
            break;
        }
        goto end;
    }

    if(node->trusted_pub_key == NULL) {
        p67_log_debug("Couldnt verify host ( %s:%s ) with public key:\n%sHost moved to queue\n", 
            peer_addr->hostname, peer_addr->service, pubk);
        node->state |= P67_NODE_STATE_QUEUE;
        success = 1;
        goto end;
    }


    if((pkey = X509_get_pubkey(x509)) == NULL) {
        goto end;
    }

    if(X509_verify(x509, pkey) != 1) {
        p67_log_debug("Invalid SSL certificate coming from host at %s:%s.\nInvalid signature.\n", 
            peer_addr->hostname, peer_addr->service);
        goto end;
    }

    if((x509_name = X509_get_subject_name(x509)) == NULL) goto end;

    if((cnix = X509_NAME_get_index_by_NID(x509_name, NID_commonName, -1)) < 0) goto end;

    if((ne = X509_NAME_get_entry(x509_name, cnix)) == NULL) goto end;

    if((castr = X509_NAME_ENTRY_get_data(ne)) == NULL) goto end;

    asnl = ASN1_STRING_length(castr);
    
    if((size_t)asnl != strlen(peer_addr->hostname) 
            || memcmp(peer_addr->hostname, ASN1_STRING_get0_data(castr), asnl) != 0) {
        p67_log_debug(
            "Invalid SSL certificate coming from host at %s:%s. CN is set to %s\n", 
            peer_addr->hostname, peer_addr->service,
            ASN1_STRING_get0_data(castr));
        success = 0;
        goto end;
    }

    if((strlen(node->trusted_pub_key) != strlen(pubk)) || 
                                memcmp(node->trusted_pub_key, pubk, strlen(pubk)) != 0) {
        p67_log_debug("Invalid SSL certificate coming from host at address %s:%s.\n"
            "This can be potential mitm attack. Host moved to queue.\n", 
                peer_addr->hostname, peer_addr->service);

        p67_log_debug("Expected: \n%s\ngot:\n%s\n", node->trusted_pub_key, pubk);

        /* 
            Remove node from cache and insert into queue so it will be ignored. 
            Up to user to trust him ( by accepting / reconnecting ) or further ignore 
        */
        node->state |= P67_NODE_STATE_QUEUE;
        goto end;
    }

    success = 1;

end:
    if(pubk != NULL) free(pubk);
    p67_addr_free(peer_addr);
    //if(castr != NULL) ASN1_STRING_free(castr);
    //if(ne != NULL) X509_NAME_ENTRY_free(ne);
    //if(x509_name != NULL) X509_NAME_free(x509_name);
    if(pkey != NULL) EVP_PKEY_free(pkey);
    if(x509 != NULL) X509_free(x509);
	return success;
}

p67_err
p67_conn_get_peer_pk(p67_addr_t * addr, char ** pk) 
{
    p67_conn_t * conn;
    X509 * rcert;

    if(pk == NULL) return p67_err_einval;

    if((conn = p67_conn_lookup(addr)) == NULL)
        return p67_err_enconn;

    if(p67_conn_lock(conn)) return p67_err_enconn;

    if(conn->ssl == NULL) {
        p67_conn_unlock(conn);
        return p67_err_enconn;
    }

    if((rcert = SSL_get_peer_certificate(conn->ssl)) == NULL) {
        p67_conn_unlock(conn);
        return p67_err_essl;
    }

    if((*pk = p67_conn_get_pem_str(rcert, P67_PEM_PUBKEY)) == NULL)  {
        p67_conn_unlock(conn);
        return p67_err_essl | p67_err_eerrno;
    }

    p67_conn_unlock(conn);

    return 0;
}

P67_CMN_NO_PROTO_ENTER
void * 
__p67_conn_accept(
P67_CMN_NO_PROTO_EXIT
    void * args)
{
    p67_conn_t * __restrict__ pass = (p67_conn_t *)args;
    p67_err err;
    BIO * rbio;
    p67_sfd_t sfd;
    int ret;

    // if(p67_conn_is_already_connected(&pass->addr_remote)) {
    //     err = p67_err_eaconn;
    //     goto end;
    // }
 
    if((err = p67_sfd_create_from_addr(&sfd, pass->addr_local, P67_SFD_TP_DGRAM_UDP)) != 0)
        goto end;

    if((err = p67_sfd_set_reuseaddr(sfd)) != 0) goto end;

    if((err = p67_sfd_bind(sfd, pass->addr_local)) != 0) goto end;
        
    p67_err_mask_all(err);

    if((rbio = SSL_get_rbio(pass->ssl)) == NULL) goto end;

    if(p67_sfd_connect(sfd, pass->addr_remote) != 0) goto end;

    if(BIO_set_fd(rbio, sfd, BIO_NOCLOSE) != 1) goto end;

    if(BIO_ctrl(
            rbio, 
            BIO_CTRL_DGRAM_SET_CONNECTED,
            0, 
            &pass->addr_remote->sock) != 1) 
        goto end;

    p67_err_mask_all(err);

    if(p67_sfd_set_timeouts(
                sfd,
                P67_DEFAULT_TIMEOUT_MS,
                P67_DEFAULT_TIMEOUT_MS) != 0)
        goto end;

    //if(p67_net_bio_set_timeout(rbio, P67_DEFAULT_TIMEOUT_MS) != 0) goto end;

    do {
        ret = SSL_accept(pass->ssl);
    } while (ret == 0);
    
    if(ret < 0) {
        goto end;
    }

    p67_conn_unlock(pass);

    //if((err = p67_conn_insert_existing(pass)) != 0) goto end;

    // p67_log_debug("DBG SOCKET: testing socket\n");

    // sfd = SSL_get_fd(pass->ssl);

    // err = p67_sfd_get_err(sfd);
    // err |= p67_sfd_valid(sfd);
    // char buff[1];
    // if(SSL_get_error(pass->ssl, SSL_read(pass->ssl, buff, 1)) != SSL_ERROR_NONE) {
    //     err |= (p67_err_essl | p67_err_eerrno);
    // }

    // if(err != 0) {
    //     p67_err_print_err("DBG SOCKET: ", err);
    // } else {
    //     p67_log_debug("DBG SOCKET: ok\n");
    // }

    p67_log_debug(
        "Accepted %s:%s\n", 
        pass->addr_remote->hostname, pass->addr_remote->service);

    if((err = p67_conn_start_read_loop(pass)) != 0) {
        goto end;
    } else {
        return NULL;
    }

end:
    p67_err_print_err("Accept: ", err);
    p67_conn_unlock(pass);
    SSL_shutdown(pass->ssl);
    pass->ssl = NULL;
    p67_conn_shutdown(pass->addr_remote);
    if(sfd > 0) p67_sfd_close(sfd);
    return NULL;
}

p67_err
p67_conn_connect(
    p67_addr_t * local, p67_addr_t * remote,
    const char * certpath, const char * keypath,
    p67_conn_gen_args_cb gen_args, void * const args, p67_conn_free_args_cb free_args,
    p67_conn_callback_t read_cb,
    p67_timeout_t * conn_timeout_ctx)
{
    void * generated_args;
    SSL * ssl = NULL;
    BIO * bio = NULL;
    SSL_CTX * ctx = NULL;
    p67_conn_t * conn;
    int sfd, noclose;
    int sslerr;
    p67_err err;
    
    noclose = 0;

    if(p67_conn_lookup(remote)) return p67_err_eaconn;

    if((err = p67_sfd_create_from_addr(
                &sfd, 
                local, 
                P67_SFD_TP_DGRAM_UDP)) != 0) goto end;

    p67_err_mask_all(err);

    if(p67_sfd_set_reuseaddr(sfd) != 0) goto end;

    if(p67_sfd_bind(sfd, local) != 0) goto end;

    if((ctx = SSL_CTX_new(DTLS_client_method())) == NULL) goto end;

    if(SSL_CTX_set_cipher_list(ctx, CIPHER) != 1) goto end;

    SSL_CTX_set_mode(ctx, SSL_MODE_RELEASE_BUFFERS);
    SSL_CTX_set_options(ctx, SSL_OP_NO_COMPRESSION);

    if(SSL_CTX_use_certificate_file(ctx, certpath, SSL_FILETYPE_PEM) != 1) goto end;

    if(SSL_CTX_use_PrivateKey_file(ctx, keypath, SSL_FILETYPE_PEM) != 1) goto end;

    if(SSL_CTX_check_private_key(ctx) != 1) goto end;

    SSL_CTX_set_verify(
                    ctx, 
                    SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, 
                    p67_net_verify_ssl_callback);

	SSL_CTX_set_read_ahead(ctx, 1);

    if((ssl = SSL_new(ctx)) == NULL) goto end;

    if((bio = BIO_new_dgram(sfd, BIO_NOCLOSE)) == NULL) goto end;

    if(p67_sfd_connect(sfd, remote) != 0) goto end;

    BIO_ctrl(bio, BIO_CTRL_DGRAM_SET_CONNECTED, 0, &remote->sock);

    SSL_set_bio(ssl, bio, bio);

    if(p67_sfd_set_timeouts(sfd, P67_DEFAULT_TIMEOUT_MS, P67_DEFAULT_TIMEOUT_MS) != 0)
        goto end;

    //p67_net_bio_set_timeout(bio, P67_DEFAULT_TIMEOUT_MS);

    if ((sslerr = SSL_connect(ssl)) != 1) {
        goto end;
    }

    generated_args = NULL;

    if(gen_args)
        generated_args = gen_args(args);

    if(!(conn = p67_conn_insert(
            local, 
            remote, 
            ssl, 
            read_cb, 
            gen_args ? generated_args : args, 
            free_args,
            P67_XLOCK_STATE_UNLOCKED,
            conn_timeout_ctx))) {
        p67_cmn_ejmp(err, p67_err_eerrno, end);
    }

    p67_log_debug("Connected to %s:%s\n", remote->hostname, remote->service);

    /*
        As of this moment we are connected 
        and even if we cannot spawn read loop connection must stay alive
    */
    noclose = 1;

    err = p67_conn_start_read_loop(conn);

end:
    if(err != 0 && !noclose) {
        if(ssl != NULL) {
            SSL_clear(ssl);
            SSL_shutdown(ssl);
            SSL_free(ssl);
        }
        if(sfd > 0) p67_sfd_close(sfd);
        if(gen_args) {
            free(generated_args);
        }
    }
    if(ctx != NULL) SSL_CTX_free(ctx);

    return err;
}

P67_CMN_NO_PROTO_ENTER
p67_err
__p67_conn_write(
P67_CMN_NO_PROTO_EXIT
    p67_conn_t * conn, const p67_pckt_t * msg, int * msgl)
{
    assert(conn);

    p67_err err;

    if(p67_conn_lock(conn)) return p67_err_enconn;

    if(conn->ssl == NULL || SSL_get_shutdown(conn->ssl) & SSL_RECEIVED_SHUTDOWN) {
        p67_conn_unlock(conn);
        p67_conn_shutdown(conn->addr_remote);
        return p67_err_enconn;
    }

    p67_err_mask_all(err);

    *msgl = SSL_write(conn->ssl, msg, *msgl);

    switch (SSL_get_error(conn->ssl, *msgl)) {
		case SSL_ERROR_NONE:
            err = 0;
            break;
		case SSL_ERROR_WANT_WRITE:
		case SSL_ERROR_SYSCALL:
		case SSL_ERROR_SSL:
		default:
			break;
	}
    
    p67_conn_unlock(conn);
    
    return err;
}

p67_err
p67_conn_write_stream(
    const p67_addr_t * addr, const p67_pckt_t * msg, int msgl)
{
    int wl = msgl;
    const p67_pckt_t * msgc = msg;
    p67_err err;
    p67_conn_t * conn;

    if((conn = p67_conn_lookup(addr)) == NULL)
        return p67_err_enconn;

    while(1) {
        err = __p67_conn_write(conn, msgc, &wl);

        if(err != 0)
            return err;

        if(wl == msgl) return 0;

        if(wl > msgl) return p67_err_einval;

        msgc+=wl;
        msgl-=wl;
    }
}

p67_err
p67_conn_write(
    const p67_addr_t * addr, const void * msg, int * msgl)
{
    p67_conn_t * conn;

    if((conn = p67_conn_lookup(addr)) == NULL)
        return p67_err_enconn;

    return __p67_conn_write(conn, msg, msgl);
}

p67_err
p67_conn_write_once(
    const p67_addr_t * addr, const p67_pckt_t * msg, int msgl)
{
    p67_conn_t * conn;
    int wl = msgl;
    uint8_t * msgc = (uint8_t *)msg;
    p67_err err;

    if((conn = p67_conn_lookup(addr)) == NULL) 
        return p67_err_enconn;

    err = __p67_conn_write(conn, msgc, &wl);

    if(err != 0)
        return err;

    if(wl != msgl) {
        return err | p67_err_enconn;
    }

    return 0;
}

void
p67_conn_shutdown_all(void)
{
    p67_hashcntl_t * ctx = p67_conn_cache();
    p67_hashcntl_free(ctx);
}

void
p67_conn_init(void)
{
    OpenSSL_add_ssl_algorithms();
    SSL_load_error_strings();
}

// P67_CMN_NO_PROTO_ENTER
// p67_err
// p67_conn_bio_set_timeout(
// P67_CMN_NO_PROTO_EXIT
//     BIO * bio, time_t msec)
// {
//     struct timeval tv;
//     tv.tv_sec = msec / 1000;
//     tv.tv_usec = (msec % 1000)*1000;
//     if(BIO_ctrl(bio, BIO_CTRL_DGRAM_SET_RECV_TIMEOUT, 0, &tv) != 1) {
//         return p67_err_essl | p67_err_eerrno;
//     }
//     if(BIO_ctrl(bio, BIO_CTRL_DGRAM_SET_SEND_TIMEOUT, 0, &tv) != 1) {
//         return p67_err_essl | p67_err_eerrno;
//     }
//     return 0;
// }

p67_err
p67_conn_listen(
    p67_addr_t * laddr,
    const char * certpath, const char * keypath,
    p67_conn_gen_args_cb gen_args, 
    void * const args,
    p67_conn_free_args_cb free_args,
    p67_conn_callback_t cb,
    p67_async_t * state,
    p67_timeout_t * conn_timeout_ctx)
{
    void * generated_args;
    p67_sfd_t sfd;
    SSL_CTX * ctx;
    SSL * ssl;
    BIO * bio;
    p67_sockaddr_t remote;
    p67_addr_t * raddr;
    p67_conn_t * conn;
    p67_node_t * node;
    p67_err err;
    p67_thread_t accept_thr;

    // if(pass->hlisten.state != P67_ASYNC_STATE_STOP)
    //     return p67_err_eaconn;
    // if((err = p67_async_set_state(
    //                 &pass->hlisten, P67_ASYNC_STATE_STOP, P67_ASYNC_THREAD_STATE_RUNNING)) != 0)
    //     return err;

    p67_err_mask_all(err);

    generated_args = NULL;
    ctx = NULL;
    ssl = NULL;
    bio = NULL;
    sfd = 0;

    if((ctx = SSL_CTX_new(DTLS_server_method())) == NULL)
        return err;

    if((SSL_CTX_set_cipher_list(ctx, CIPHER)) != 1)
        goto end;

    SSL_CTX_set_session_cache_mode(ctx, SSL_SESS_CACHE_OFF);

    if(SSL_CTX_use_certificate_file(ctx, certpath, SSL_FILETYPE_PEM) != 1)
        goto end;

    if(SSL_CTX_use_PrivateKey_file(ctx, keypath, SSL_FILETYPE_PEM) != 1)
        goto end;

    SSL_CTX_set_mode(ctx, SSL_MODE_RELEASE_BUFFERS);
    SSL_CTX_set_options(ctx, SSL_OP_NO_COMPRESSION);

    if(SSL_CTX_check_private_key(ctx) != 1) goto end;

    SSL_CTX_set_verify(ctx, 
        SSL_VERIFY_PEER | SSL_VERIFY_CLIENT_ONCE |  SSL_VERIFY_FAIL_IF_NO_PEER_CERT, 
        p67_net_verify_ssl_callback);

	SSL_CTX_set_read_ahead(ctx, 1);
	SSL_CTX_set_cookie_generate_cb(ctx, p67_net_generate_cookie_callback);
	SSL_CTX_set_cookie_verify_cb(ctx, p67_net_verify_cookie_callback);

    if((err = p67_sfd_create_from_addr(&sfd, laddr, P67_SFD_TP_DGRAM_UDP)) != 0)
        goto end;

    if((err = p67_sfd_set_reuseaddr(sfd)) != 0) goto end;
    
    if((err = p67_sfd_bind(sfd, laddr)) != 0) goto end;

    if((err = p67_sfd_set_timeouts(
            sfd, P67_DEFAULT_TIMEOUT_MS, P67_DEFAULT_TIMEOUT_MS)) != 0)
        goto end;

    //if((err = p67_sfd_set_noblocking(sfd)) != 0) goto end;

    p67_log_debug("Listening @ %s:%s\n", laddr->hostname, laddr->service);

    while(1) {

        if(state && *state != P67_THREAD_SM_STATE_RUNNING) {
            err = 0; //p67_err_eint;
            goto end;
        }

        p67_err_mask_all(err);
        ssl = NULL;

        if((bio = BIO_new_dgram(sfd, BIO_NOCLOSE)) == NULL) goto end;

        //p67_conn_bio_set_timeout(bio, P67_DEFAULT_TIMEOUT_MS);

        if((ssl = SSL_new(ctx)) == NULL) goto end;

        SSL_set_bio(ssl, bio, bio);
        if(!(SSL_set_options(ssl, SSL_OP_COOKIE_EXCHANGE) & SSL_OP_COOKIE_EXCHANGE))
            goto end;
        
        while (DTLSv1_listen(ssl, (BIO_ADDR *)&remote) <= 0) {
            if(state && *state != P67_THREAD_SM_STATE_RUNNING) {
                err = 0; //p67_err_eint;
                goto end;
            }
        }

        generated_args = NULL;
        do {
            if(!(raddr = p67_addr_new())) break;
            if((err = p67_addr_set_sockaddr(raddr, &remote, sizeof(remote))) != 0)
                break;
            /* 
                moved from ssl verify cvallback due to memory leaks.
                if remote was already queued and their ssl conn closed then block them 
            */
            if((node = p67_node_lookup(raddr)) != NULL 
                    && (node->state & P67_NODE_STATE_QUEUE)) {
                err = p67_err_essl;
                break;
            }
            if(gen_args)
                generated_args = gen_args(args);

            conn = p67_conn_insert(
                laddr, raddr, ssl, cb, 
                gen_args ? generated_args : args, 
                free_args, P67_XLOCK_STATE_LOCKED,
                conn_timeout_ctx);
            if(!conn) {
                if(gen_args)
                    free(generated_args);
                break;
            }

            //__p67_conn_accept(conn);

            if((err = p67_cmn_thread_create(&accept_thr, __p67_conn_accept, conn)) != 0) {
                /* possible crash due to calling SSL_shutdown and SSL_Free without completing handshake */
                p67_conn_shutdown(raddr);
                err = 0;
                if(gen_args)
                    free(generated_args);
                break;
            }
            //err = 0;
        } while(0);
        
        if(err != 0) {
            SSL_free(ssl);
        }

        p67_addr_free(raddr);
        raddr = NULL;
    }

end:
    if(ctx != NULL) SSL_CTX_free(ctx);
    p67_sfd_close(sfd);
    if(ssl != NULL) SSL_free(ssl);
    err |= p67_mutex_set_state(
        state, *state, 
        P67_THREAD_SM_STATE_STOP);
    return err;
}
