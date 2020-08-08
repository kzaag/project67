#include <openssl/rand.h>
#include <openssl/err.h>

#if !defined(__USE_XOPEN_EXTENDED)
#define __USE_XOPEN_EXTENDED
#endif
#include <string.h>
#include <strings.h>
#include <sys/time.h>
#include <errno.h>

#include "hash.h"
#include "log.h"
#include "net.h"


#define P67_DEFAULT_TIMEOUT_MS 200

/* sleep ms = P67_MIN_SLEEP_MS + [0 - P67_MOD_SLEEP_MS] */
#define P67_MIN_SLEEP_MS 500
#define P67_MOD_SLEEP_MS 1000

p67_mutex_t cookie_lock = P67_CMN_MUTEX_INITIALIZER;
static volatile int cookie_initialized=0;
#define COOKIE_SECRET_LENGTH 32
unsigned char cookie_secret[COOKIE_SECRET_LENGTH];

struct p67_net_config __config = {
    .c_auth = P67_NET_C_AUTH_LIMIT_TRUST_UNKNOWN
};

/* linked item - generic structure used in hash table operations */
struct p67_liitem {
    p67_liitem_t * next;
    p67_addr_t key;
};

#define DAYS_TO_SEC(day) ((long)(60*60*24*day))

#define CONN_CACHE_LEN 337
#define NODE_CACHE_LEN 337

p67_conn_t * conn_cache[CONN_CACHE_LEN];
p67_node_t * node_cache[NODE_CACHE_LEN];
p67_async_t cache_lock = P67_ASYNC_INTIIALIZER;

#define CIPHER "ECDHE-ECDSA-AES256-GCM-SHA384"
#define CIPHER_ALT "HIGH:!aNULL:!kRSA:!PSK:!SRP:!MD5:!RC4"

#define READ_BUFFER_LENGTH 256
/*
    ssl error strings
*/
#define ERR_BUFFER_LENGTH 128

#define p67_conn_size sizeof(p67_conn_t)

/*---BEGIN PRIVATE PROTOTYPES---*/

p67_err
p67_conn_insert(
    p67_addr_t * local,
    p67_addr_t * remote,
    SSL * ssl,
    p67_conn_callback_t callback,
    void * args,
    p67_conn_free_args_cb free_args,
    p67_conn_t ** ret);

/*
    if also_free_ptr is set to 1 then free conn pointer itself.
    otherwise only free dependencies.
*/
void
p67_conn_free(void * ptr, int also_free_ptr);

extern inline p67_err 
p67_net_hash_get_table(int p67_ct, p67_liitem_t *** out, size_t * outl);

#define p67_conn_insert_existing(conn) \
    p67_net_hash_insert(P67_CT_CONN, &(conn)->addr_remote, NULL, (p67_liitem_t *)(conn))

#define p67_conn_remove(addr) \
    p67_net_hash_remove(P67_CT_CONN, addr, NULL, p67_conn_free)

int 
p67_net_verify_cookie_callback(
        SSL *ssl, 
        const unsigned char *cookie, 
        unsigned int cookie_len);

int 
p67_net_generate_cookie_callback(
        SSL *ssl, 
        unsigned char *cookie,
        unsigned int *cookie_len);

p67_err
p67_net_bio_set_timeout(BIO * bio, time_t msec);

void *
__p67_net_enter_read_loop(void * args)
    __nonnull((1))
    __attribute_deprecated_msg__("This function will not check whether read loop is already running");

p67_err
p67_net_get_addr_from_x509_store_ctx(X509_STORE_CTX *ctx, p67_addr_t * addr);

#define P67_PEM_CERT   1
#define P67_PEM_PUBKEY 2

#define p67_get_cert_str(x509) p67_get_pem_str(x509, P67_PEM_CERT);

char * 
p67_net_get_pem_str(X509 * x509, int type);

int 
p67_net_verify_ssl_callback(int ok, X509_STORE_CTX *ctx);

void * 
__p67_net_accept(void * args);

void *
__p67_net_persist_connect(void * arg)
    __nonnull((1));

void *
__p67_net_listen(void * args);

/*---END PRIVATE PROTOTYPES---*/

struct p67_net_config * p67_net_config_location(void)
{
    return &__config;
}

const p67_addr_t *
p67_conn_get_addr(p67_conn_t * conn)
{
    return &conn->addr_remote; 
}

void *
p67_conn_get_args(p67_conn_t * conn)
{
    return &conn->args; 
}

void
p67_conn_free(void * ptr, int also_free_ptr)
{
    int sfd;
    p67_conn_t * conn = (p67_conn_t *)ptr;
    p67_async_t state;

    if(ptr == NULL) return;

    if(conn->free_args != NULL)
        conn->free_args(conn->args);

    while(1) {
        state = conn->ssl_lock;
        if(state == P67_NET_SLOCK_STATE_LOCKED) {
            continue;
        } else if(state == P67_NET_SLOCK_STATE_TERM) {
            return; // already freeing so just exit
        } else if(state == P67_NET_SLOCK_STATE_FREE) {
            if(p67_atomic_set_state(
                    &conn->ssl_lock, &state, P67_NET_SLOCK_STATE_TERM))
            // give some time for everyone interested to terminate ops
            p67_cmn_sleep_ms(P67_CONN_TERM_PERIOD_MS);
            break;
        } else {
            return;
        }
    }

    p67_thread_sm_terminate(&conn->hread, P67_THREAD_SM_TIMEOUT_DEF);

    if(conn->ssl != NULL) {
        SSL_shutdown(conn->ssl);
        if((sfd = SSL_get_fd(conn->ssl)) > 0) p67_sfd_close(sfd);
        SSL_free(conn->ssl);
        conn->ssl = NULL;
    }

    DLOG("Shutdown for %s:%s\n", conn->addr_remote.hostname, conn->addr_remote.service);

    p67_addr_free(&conn->addr_local);
    p67_addr_free(&conn->addr_remote);

    if(also_free_ptr) free(conn);
    
    return;
}

void
p67_node_free(void * ptr, int also_free_ptr)
{
    p67_node_t * node = (p67_node_t *)ptr;

    if(node == NULL) return;

    p67_addr_free(&node->trusted_addr);
    if(node->trusted_pub_key != NULL) free(node->trusted_pub_key);
    if(also_free_ptr) free(node);
}

/*
    following methods mostly target cache accessing for 2 separate hash tables:
        - conn_cache
        - node_cache

    I actually had quite a lot of headaches concerning how to implement it.
    1 option was to completely duplicate hash access functions ( insert_*, remove_*, lookup_*).
    2 option was to follow dry principle and try to reuse the code.
    2 option was chosen by me, but this causes (negligible) loss of performance.
        And im not sure if gains are well worth it.
    So to any mantainer who happens to look at this code - if you feel that DRY-approach was wrong here.
        feel free to reverse-refractor it into duplicated functions. 
    I really dont know which approach is better.
*/

inline p67_err 
p67_net_hash_get_table(int p67_ct, p67_liitem_t *** out, size_t * outl)
{
    if(out == NULL) return p67_err_einval;

    switch(p67_ct) {
    case P67_CT_NODE:
        *out = (p67_liitem_t **)node_cache;
        if(outl != NULL) *outl = NODE_CACHE_LEN;
        break;
    case P67_CT_CONN:
        *out = (p67_liitem_t **)conn_cache;
        if(outl != NULL) *outl = CONN_CACHE_LEN;
        break;
    default:
        return p67_err_einval;
    }

    return 0;
}

p67_liitem_t * 
p67_net_hash_lookup(int p67_ct, const p67_addr_t * key)
{
    p67_liitem_t * ret = NULL, ** cc;
    size_t outlen;

    if(key == NULL) return NULL;

    if(p67_net_hash_get_table(p67_ct, &cc, &outlen) != 0) return NULL;
    
    p67_hash_t hash = p67_hash_fn(
        (__u_char *)&key->sock, key->socklen, outlen);

    p67_spinlock_lock(&cache_lock);

    for(ret = cc[hash]; ret != NULL; ret = ret->next) {
        if(ret->key.socklen != key->socklen)
            continue;
        if(memcmp(&key->sock, &ret->key.sock, key->socklen) == 0) break;
    }

    p67_spinlock_unlock(&cache_lock);

    return ret;
}

p67_err
p67_net_hash_insert(
    int p67_ct, 
    const p67_addr_t * key, 
    p67_liitem_t ** ret,
    p67_liitem_t * prealloc)
{
    if(key == NULL) return p67_err_einval;

    p67_liitem_t * r, ** np = NULL;
    p67_liitem_t ** cc;
    size_t outlen;

    if(p67_net_hash_get_table(p67_ct, &cc, &outlen) != 0)
        return p67_err_einval;

    unsigned long hash = p67_hash_fn((__u_char *)&key->sock, key->socklen, outlen);

    r = cc[hash];
    p67_spinlock_lock(&cache_lock);

    do {
        if(r == NULL) break;
        if(r->key.socklen == key->socklen 
                && memcmp(&key->sock, &r->key.sock, r->key.socklen) == 0) {
                    p67_spinlock_unlock(&cache_lock);
                    return p67_err_eaconn;
                }
        if(r->next == NULL) break;
    } while ((r=r->next) != NULL);
    
    if(r == NULL) {
        np = &cc[hash];
    } else {
        np = &r->next;
    }

    if(prealloc != NULL) {
        *np = prealloc;
        if(ret != NULL) *ret = *np;
        p67_spinlock_unlock(&cache_lock);
        return 0;
    }

    switch(p67_ct) {
    case P67_CT_NODE:
        if((*np = calloc(sizeof(p67_node_t), 1)) == NULL) goto err;
        break;
    case P67_CT_CONN:
        if((*np = calloc(sizeof(p67_conn_t), 1)) == NULL) goto err;
        break;
    default:
        goto err;
    }

    if(p67_addr_dup(&(*np)->key, key) != 0) goto err;

    if(ret != NULL)
        *ret = *np;

    p67_spinlock_unlock(&cache_lock);
    return 0;

err:
    free(*np);
    *np = NULL;
    p67_spinlock_unlock(&cache_lock);
    return p67_err_eerrno;
}

p67_err
p67_conn_insert(
    p67_addr_t * local, 
    p67_addr_t * remote, 
    SSL * ssl, 
    p67_conn_callback_t callback,
    void * args,
    p67_conn_free_args_cb free_args,
    p67_conn_t ** ret) 
{
    p67_err err;
    p67_addr_t laddr;
    p67_conn_t * conn;

    /* malloc before inserting to hash
        so in case of error one doesnt need to remove item from hash table */

    if(p67_addr_dup(&laddr, local) != 0) return p67_err_eerrno;
    
    if((err = p67_net_hash_insert(P67_CT_CONN, remote, (p67_liitem_t**)&conn, NULL)) != 0) {
        p67_addr_free(&laddr);
        return err;
    }

    (conn)->addr_local = laddr;
    if(callback != NULL) (conn)->callback = callback;
    if(args != NULL) (conn)->args = args;
    if(ssl != NULL) (conn)->ssl = ssl;
    if(free_args != NULL) (conn)->free_args = free_args;

    if(ret != NULL)
        *ret = conn;

    return 0;
}

p67_err
p67_node_insert(
    const p67_addr_t * addr,
    const char * trusted_key,
    int strdup_key,
    int node_state,
    p67_node_t ** ret) 
{
    p67_err err;
    p67_node_t * node;
    char * tkeycpy;
    
    if(trusted_key != NULL) {
        if(strdup_key) {
            if((tkeycpy = strdup(trusted_key)) == NULL) return p67_err_eerrno;
        } else {
            tkeycpy = (char *)trusted_key;
        }
    }

    if((err = p67_net_hash_insert(P67_CT_NODE, addr, (p67_liitem_t**)&node, NULL)) != 0) {
        return err;
    }

    if(trusted_key != NULL) node->trusted_pub_key = tkeycpy;
    node->state = node_state;

    if(ret != NULL)
        *ret = node;

    return 0;
}

p67_err
p67_net_hash_remove(
        int p67_ct, 
        p67_addr_t * addr, 
        p67_liitem_t ** out,
        dispose_callback_t callback)
{
    if(addr == NULL) return p67_err_einval;

    p67_liitem_t * ptr, * prev, ** cc;
    size_t outlen;
    prev = NULL;
    ptr = NULL;

    if(p67_net_hash_get_table(p67_ct, &cc, &outlen) != 0) return p67_err_einval;

    unsigned long hash = p67_hash_fn((__u_char *)&addr->sock, addr->socklen, outlen);

    p67_spinlock_lock(&cache_lock);

    for(ptr = cc[hash]; ptr != NULL; ptr = (ptr)->next) {
        if(addr->socklen == ptr->key.socklen 
            && memcmp(&addr->sock, &ptr->key.sock, ptr->key.socklen) == 0) break;
        prev = ptr;
    }

    if(ptr == NULL) {
        p67_spinlock_unlock(&cache_lock);
        return p67_err_enconn;
    }

    if(prev == NULL) {
        cc[hash] = NULL;
    } else {
        prev->next = ptr->next;
    }

    if(callback != NULL) {
        callback(ptr, 1);
        p67_spinlock_unlock(&cache_lock);
        return 0;
    }

    if(out != NULL) *out = ptr;

    p67_spinlock_unlock(&cache_lock);
    return 0;
}

int 
p67_net_generate_cookie_callback(SSL *ssl, unsigned char *cookie, unsigned int *cookie_len)
{
	unsigned char result[EVP_MAX_MD_SIZE];
	unsigned int resultlength;
	p67_sockaddr_t peer;

    if(!cookie_initialized) {
        if(p67_cmn_mutex_lock(&cookie_lock) != 0) return 0;
        if (!cookie_initialized) {
            if (!RAND_bytes(cookie_secret, COOKIE_SECRET_LENGTH)) {
                p67_cmn_mutex_unlock(&cookie_lock);
                return 0;
            }
            cookie_initialized = 1;
        }
        if(p67_cmn_mutex_unlock(&cookie_lock) != 0) return 0;
    }

    bzero(&peer, sizeof(p67_sockaddr_t));
	(void)BIO_dgram_get_peer(SSL_get_rbio(ssl), &peer);

	HMAC(
        EVP_sha1(), 
        (const void*) cookie_secret, 
        COOKIE_SECRET_LENGTH,
	    (const unsigned char *)&peer, sizeof(p67_sockaddr_t), 
        result, &resultlength);

	memcpy(cookie, result, resultlength);
	*cookie_len = resultlength;

	return 1;
}

int 
p67_net_verify_cookie_callback(SSL *ssl, const unsigned char *cookie, unsigned int cookie_len)
{
	unsigned char result[EVP_MAX_MD_SIZE];
	unsigned int resultlength;
	p67_sockaddr_t peer;

    /* no need to ensure thread safety here since cookie mustve been initialized at this point */
	if (!cookie_initialized) return 0;

    bzero(&peer, sizeof(p67_sockaddr_t));
	(void)BIO_dgram_get_peer(SSL_get_rbio(ssl), &peer);

	HMAC(
        EVP_sha1(), 
        (const void*) cookie_secret, COOKIE_SECRET_LENGTH,
	    (const unsigned char*)&peer, sizeof(p67_sockaddr_t), 
        result, &resultlength);

	if (cookie_len == resultlength && memcmp(result, cookie, resultlength) == 0) return 1;

	return 0;
}

p67_err
p67_net_bio_set_timeout(BIO * bio, time_t msec)
{
    struct timeval tv;
    tv.tv_sec = msec / 1000;
    tv.tv_usec = (msec % 1000)*1000;
    if(BIO_ctrl(bio, BIO_CTRL_DGRAM_SET_RECV_TIMEOUT, 0, &tv) != 1) {
        return p67_err_essl | p67_err_eerrno;
    }
    if(BIO_ctrl(bio, BIO_CTRL_DGRAM_SET_SEND_TIMEOUT, 0, &tv) != 1) {
        return p67_err_essl | p67_err_eerrno;
    }
    return 0;
}

p67_err
p67_net_start_read_loop_conn(p67_conn_t * conn)
{
    p67_err err;

    if(conn->hread.state != P67_THREAD_SM_STATE_STOP)
        return p67_err_eaconn;

    if((err = p67_mutex_set_state(
                    &conn->hread.state, 
                    P67_THREAD_SM_STATE_STOP, 
                    P67_THREAD_SM_STATE_RUNNING)) != 0)
        return err;

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
    if((err = p67_cmn_thread_create(
                &conn->hread.thr, __p67_net_enter_read_loop, conn)) != 0) {
#pragma GCC diagnostic pop
        err |= p67_mutex_set_state(
                    &conn->hread.state,
                    P67_THREAD_SM_STATE_RUNNING,
                    P67_THREAD_SM_STATE_STOP);
        return err;
    }

    return 0;
}

/*
    entry point for __p67_net_enter_read_loop
*/
p67_err
p67_net_start_read_loop(p67_addr_t * addr, p67_conn_callback_t cb, void * args)
{
    p67_conn_t * conn;

    if((conn = p67_conn_lookup(addr)) == NULL)
        return p67_err_enconn;

    conn->callback = cb;
    conn->args = args;

    return p67_net_start_read_loop_conn(conn);
}

void *
__p67_net_enter_read_loop(void * args)
{
    ssize_t len;
    BIO * bio;
    // if no message arrives for max_rcvto_ms miliseconds then close connection
    const int max_rcvto_ms = 10000;
    char rbuff[READ_BUFFER_LENGTH], errbuf[ERR_BUFFER_LENGTH];
    int num_timeouts = 0, max_timeouts, sslr = 1, 
        err, callret, rcvto_ms;
    p67_conn_t * conn = (p67_conn_t *)args;
    p67_sfd_t sfd;

    p67_err_mask_all(err);
    
    if((bio = SSL_get_rbio(conn->ssl)) == NULL) goto end;
    
    if((sfd = SSL_get_fd(conn->ssl)) < 0) goto end;

    if(p67_sfd_get_timeouts(sfd, NULL, &rcvto_ms) != 0)
        goto end;

    max_timeouts = max_rcvto_ms / rcvto_ms;

    //DLOG("Entering read loop\n");

    while(!(SSL_get_shutdown(conn->ssl) & SSL_RECEIVED_SHUTDOWN) && num_timeouts < max_timeouts) {
        sslr = 1;
        while(sslr) {
            if(conn->hread.state != P67_THREAD_SM_STATE_RUNNING) {
                err = 0;
                goto end;
            }

            len = SSL_read(conn->ssl, rbuff, READ_BUFFER_LENGTH);
            err = SSL_get_error(conn->ssl, len);

            switch (err) {
            case SSL_ERROR_NONE:
                if(conn->callback == NULL) break;
                callret = (*conn->callback)(conn, rbuff, len, conn->args);
                if(callret != 0 && callret != p67_err_eagain) {
                    err = callret;
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
                DLOG("ssl_read: %d : %s\n", errno, strerror(errno));
                goto end;
            default:
                DLOG("in read loop: %s\n", ERR_error_string(err, errbuf));
                sslr = 0;
                break;
            }
        }
    }

    end:
    //DLOG("Leaving read loop\n");
    p67_mutex_set_state(
            &conn->hread.state, 
            P67_THREAD_SM_STATE_RUNNING, 
            P67_THREAD_SM_STATE_STOP); /* leave on error */
    p67_mutex_set_state(
            &conn->hread.state, 
            P67_THREAD_SM_STATE_SIG_STOP, 
            P67_THREAD_SM_STATE_STOP); /* leave on interrupt */
    if(err != 0) p67_conn_remove(&conn->addr_remote);
    return NULL;
}

p67_err
p67_net_get_addr_from_x509_store_ctx(X509_STORE_CTX *ctx, p67_addr_t * addr) 
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

/*
    returned value must be freed after using
    if NULL is returned seek error in p67_err_essl | p67_err_eerrno

    type:
    1 for certififate ( is default )
    2 for public key
*/
char * 
p67_net_get_pem_str(X509 * x509, int type)
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

int 
p67_net_verify_ssl_callback(int ok, X509_STORE_CTX *ctx) 
{
    p67_addr_t addr;
    X509 * x509 = NULL;
    char *pubk = NULL;
    int cnix, success = 0, asnl;
    X509_NAME * x509_name = NULL;
    X509_NAME_ENTRY * ne = NULL;
    ASN1_STRING * castr = NULL;
    EVP_PKEY * pkey = NULL;
    p67_node_t * node = NULL;

    return 1;

    bzero(&addr, sizeof(p67_addr_t));

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

    if(p67_net_get_addr_from_x509_store_ctx(ctx, &addr) != 0)
        return 0;

    /* 
        if remote was already queued and their ssl conn closed then block them 
    */
    if((node = p67_node_lookup(&addr)) != NULL 
            && (node->state & P67_NODE_STATE_QUEUE) != 0) {
        X509_STORE_CTX_set_error(ctx, X509_V_ERR_CERT_REVOKED);
        return 0;
    }

    if((x509 = X509_STORE_CTX_get_current_cert(ctx)) == NULL) {
        return 0;
    }

    if((pubk = p67_net_get_pem_str(x509, P67_PEM_PUBKEY)) == NULL) {
        return 0;
    }

    success = 0;

    /* 
        if remote is first timer then allow them to connect ( but queue them )
        we will warn user about new peer
    */
    if(node == NULL) {
        switch(__config.c_auth) {
        case P67_NET_C_AUTH_LIMIT_TRUST_UNKNOWN:
            DLOG("Unknown host connecting from %s:%s with public key:\n%s", 
                addr.hostname, addr.service, pubk);
            if(p67_node_insert(&addr, pubk, 1, P67_NODE_STATE_QUEUE, NULL) != 0)
                goto end;
            success = 1;
            break;
        case P67_NET_C_AUTH_TRUST_UNKOWN:
            if(p67_node_insert(&addr, pubk, 1, 0, NULL) != 0) 
                goto end;
            success = 1;
            break;
        case P67_NET_C_AUTH_DONT_TRUST_UNKOWN:
            DLOG("Rejected Unknown Host ( %s:%s ) with public key:\n%s", 
                addr.hostname, addr.service, pubk);
            if(p67_node_insert(&addr, pubk, 1, P67_NODE_STATE_QUEUE, NULL) != 0) 
                goto end;
            break;
        default:
            break;
        }
        goto end;
    }

    if(node->trusted_pub_key == NULL) {
        DLOG("Couldnt verify host ( %s:%s ) with public key:\n%sHost moved to queue\n", 
            addr.hostname, addr.service, pubk);
        node->state |= P67_NODE_STATE_QUEUE;
        success = 1;
        goto end;
    }


    if((pkey = X509_get_pubkey(x509)) == NULL) {
        goto end;
    }

    if(X509_verify(x509, pkey) != 1) {
        DLOG("Invalid SSL certificate coming from host at %s:%s.\nInvalid signature.\n", 
            addr.hostname, addr.service);
        goto end;
    }

    if((x509_name = X509_get_subject_name(x509)) == NULL) goto end;

    if((cnix = X509_NAME_get_index_by_NID(x509_name, NID_commonName, -1)) < 0) goto end;

    if((ne = X509_NAME_get_entry(x509_name, cnix)) == NULL) goto end;

    if((castr = X509_NAME_ENTRY_get_data(ne)) == NULL) goto end;

    asnl = ASN1_STRING_length(castr);
    
    if((size_t)asnl != strlen(addr.hostname) 
            || memcmp(addr.hostname, ASN1_STRING_get0_data(castr), asnl) != 0) {
        DLOG(
            "Invalid SSL certificate coming from host at %s:%s. CN is set to %s\n", 
            addr.hostname, addr.service,
            ASN1_STRING_get0_data(castr));
        success = 0;
        goto end;
    }

    if((strlen(node->trusted_pub_key) != strlen(pubk)) || memcmp(node->trusted_pub_key, pubk, strlen(pubk)) != 0) {
        DLOG("Invalid SSL certificate coming from host at address %s:%s.\n"
            "This can be potential mitm attack. Host moved to queue.\n", 
                addr.hostname, addr.service);

        DLOG("Expected: \n%s\ngot:\n%s\n", node->trusted_pub_key, pubk);

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
    p67_addr_free(&addr);
    //if(castr != NULL) ASN1_STRING_free(castr);
    //if(ne != NULL) X509_NAME_ENTRY_free(ne);
    //if(x509_name != NULL) X509_NAME_free(x509_name);
    if(pkey != NULL) EVP_PKEY_free(pkey);
    if(x509 != NULL) X509_free(x509);
	return success;
}

p67_err
p67_net_get_peer_pk(p67_addr_t * addr, char ** pk) 
{
    p67_conn_t * conn;
    X509 * rcert;

    if(pk == NULL) return p67_err_einval;

    if((conn = p67_conn_lookup(addr)) == NULL)
        return p67_err_enconn;

    if(conn->ssl == NULL) return p67_err_enconn;

    if((rcert = SSL_get_peer_certificate(conn->ssl)) == NULL)
        return p67_err_essl;

    if((*pk = p67_net_get_pem_str(rcert, P67_PEM_PUBKEY)) == NULL) 
        return p67_err_essl | p67_err_eerrno;

    return 0;
}

void * 
__p67_net_accept(void * args)
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
 
    if((err = p67_sfd_create_from_addr(&sfd, &pass->addr_local, P67_SFD_TP_DGRAM_UDP)) != 0)
        goto end;

    if((err = p67_sfd_set_reuseaddr(sfd)) != 0) goto end;

    if((err = p67_sfd_bind(sfd, &pass->addr_local)) != 0) goto end;
        
    p67_err_mask_all(err);

    if((rbio = SSL_get_rbio(pass->ssl)) == NULL) goto end;

    if(p67_sfd_connect(sfd, &pass->addr_remote) != 0) goto end;

    if(BIO_set_fd(rbio, sfd, BIO_NOCLOSE) != 1) goto end;

    if(BIO_ctrl(
            rbio, 
            BIO_CTRL_DGRAM_SET_CONNECTED,
            0, 
            &pass->addr_remote.sock) != 1) 
        goto end;

    p67_err_mask_all(err);

    if(p67_sfd_set_timeouts(sfd, P67_DEFAULT_TIMEOUT_MS, P67_DEFAULT_TIMEOUT_MS) != 0)
        goto end;

    //if(p67_net_bio_set_timeout(rbio, P67_DEFAULT_TIMEOUT_MS) != 0) goto end;

    do {
        ret = SSL_accept(pass->ssl);
    } while (ret == 0);
    
    if(ret < 0) goto end;

    p67_atomic_must_set_state(
        &pass->ssl_lock, 
        P67_NET_SLOCK_STATE_LOCKED, 
        P67_NET_SLOCK_STATE_FREE);

    //if((err = p67_conn_insert_existing(pass)) != 0) goto end;

    // DLOG("DBG SOCKET: testing socket\n");

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
    //     DLOG("DBG SOCKET: ok\n");
    // }

    DLOG("Accepted %s:%s\n", pass->addr_remote.hostname, pass->addr_remote.service);

    if((err = p67_net_start_read_loop_conn(pass)) != 0) {
        goto end;
    } else {
        return NULL;
    }

end:
    p67_err_print_err("Accept: ", err);
    p67_atomic_must_set_state(
        &pass->ssl_lock, 
        P67_NET_SLOCK_STATE_LOCKED, 
        P67_NET_SLOCK_STATE_FREE);
    SSL_shutdown(pass->ssl);
    pass->ssl = NULL;
    p67_conn_remove(&pass->addr_remote);
    if(sfd > 0) p67_sfd_close(sfd);
    return NULL;
}

p67_err
p67_net_connect(p67_conn_pass_t * pass)
{
    int sfd, noclose;
    p67_err err;
    int sslerr;
    SSL * ssl = NULL;
    BIO * bio = NULL;
    SSL_CTX * ctx = NULL;
    p67_conn_t * conn;
    void * args;
    
    noclose = 0;

    if(p67_conn_is_already_connected(&pass->remote) != 0) return p67_err_eaconn;

    if((err = p67_sfd_create_from_addr(
                &sfd, 
                &pass->local, 
                P67_SFD_TP_DGRAM_UDP)) != 0) goto end;

    p67_err_mask_all(err);

    if(p67_sfd_set_reuseaddr(sfd) != 0) goto end;

    if(p67_sfd_bind(sfd, &pass->local) != 0) goto end;

    if((ctx = SSL_CTX_new(DTLS_client_method())) == NULL) goto end;

    if(SSL_CTX_set_cipher_list(ctx, CIPHER) != 1) goto end;

    SSL_CTX_set_mode(ctx, SSL_MODE_RELEASE_BUFFERS);
    SSL_CTX_set_options(ctx, SSL_OP_NO_COMPRESSION);

    if(SSL_CTX_use_certificate_file(ctx, pass->certpath, SSL_FILETYPE_PEM) != 1) goto end;

    if(SSL_CTX_use_PrivateKey_file(ctx, pass->keypath, SSL_FILETYPE_PEM) != 1) goto end;

    if(SSL_CTX_check_private_key(ctx) != 1) goto end;

    SSL_CTX_set_verify(
                    ctx, 
                    SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, 
                    p67_net_verify_ssl_callback);

	SSL_CTX_set_read_ahead(ctx, 1);

    if((ssl = SSL_new(ctx)) == NULL) goto end;

    if((bio = BIO_new_dgram(sfd, BIO_NOCLOSE)) == NULL) goto end;

    if(p67_sfd_connect(sfd, &pass->remote) != 0) goto end;

    BIO_ctrl(bio, BIO_CTRL_DGRAM_SET_CONNECTED, 0, &pass->remote.sock.__ss);

    SSL_set_bio(ssl, bio, bio);

    if(p67_sfd_set_timeouts(sfd, P67_DEFAULT_TIMEOUT_MS, P67_DEFAULT_TIMEOUT_MS) != 0)
        goto end;
    //p67_net_bio_set_timeout(bio, P67_DEFAULT_TIMEOUT_MS);

    if ((sslerr = SSL_connect(ssl)) != 1) {
        /*
            i found it very tricky to try to recover DTLS connection 
                after one side crashes without sending close_notify ( SSL_shutdown ) or due to truncation attack.
            right now solution is to define rcv timeout, after which connection can be set anew;
            its not perfect since one side will have to wait for considerable amount of time
        */
        
        // if(SSL_get_error(ssl, sslerr) == SSL_ERROR_WANT_READ) {
        //     //SSL_shutdown(ssl);
        // }
        goto end;
    }

    if(pass->gen_args != NULL)
        args = pass->gen_args(pass->args);
    else
        args = pass->args;

    if(p67_conn_insert(
            &pass->local, 
            &pass->remote, 
            ssl, 
            pass->handler, 
            args, 
            pass->free_args, 
            &conn) != 0) goto end;

    DLOG("Connected to %s:%s\n", pass->remote.hostname, pass->remote.service);

    /*
        As of this moment we are connected 
        and even if we cannot spawn read loop connection must stay alive
    */
    noclose = 1;

    err = p67_net_start_read_loop_conn(conn);

end:
    if(err != 0 && !noclose) {
        if(ssl != NULL) {
            SSL_clear(ssl);
            SSL_shutdown(ssl);
            SSL_free(ssl);
        }
        if(sfd > 0) p67_sfd_close(sfd);
    }
    if(ctx != NULL) SSL_CTX_free(ctx);

    return err;
}

p67_err
p67_net_nat_connect(p67_conn_pass_t * pass, int p67_conn_cn_t)
{
    unsigned long interv;
    struct timespec sleepspec;
    int retries = 5;
    p67_err err;

    while(retries-->0 /*&& (pass->hconnect.state == P67_ASYNC_THREAD_STATE_RUNNING ) */ ) {
        if(p67_conn_lookup(&pass->remote) != NULL) {
            DLOG("\rNAT Connect:%d Connection exists.\n", p67_conn_cn_t);
            return p67_err_eaconn;
        }

        // hiding net_cache_get error
        if((err = p67_net_connect(pass)) == 0) break;

        if(p67_conn_cn_t == P67_CONN_CNT_PASS || p67_conn_cn_t == P67_CONN_CNT_DEF)
            break;

        if(p67_conn_lookup(&pass->remote) != NULL) {
            DLOG("\rNAT Connect:%d Connection exists.\n", p67_conn_cn_t);
            return p67_err_eaconn;
        }

        if(p67_conn_cn_t == P67_CONN_CNT_ACT) {
            err = p67_net_connect(pass);
            break;
        }

        if(p67_conn_lookup(&pass->remote) != NULL) {
            DLOG("\rNAT Connect:%d Connection exists.\n", p67_conn_cn_t);
            return p67_err_eaconn;
        }

        if(p67_conn_cn_t == P67_CONN_CNT_PERSIST) {

            if(1 != RAND_bytes((unsigned char *)&interv, sizeof(interv))) {
                p67_err_mask_all(err);
                break;
            }
            interv = (interv % 3000) + 1000;
            DLOG("NAT Connect:%d Sleeping for %lu\n", p67_conn_cn_t, interv);
            sleepspec.tv_sec = interv / 1000;
            sleepspec.tv_nsec = (interv % 1000) * 1000000;
            if(nanosleep(&sleepspec, &sleepspec) != 0) {
                err = p67_err_eerrno;
                break;
            }

            continue;
        }

        err = p67_err_einval;
        break;
    }

    if(err == 0) {
        DLOG("NAT Connect:%d Succeeded.\n", p67_conn_cn_t);
    } else {
        //DLOG("NAT Connect:%d Failed.\n", p67_conn_cn_t);
    }

   /* p67_async_set_state(&pass->hconnect, 
            P67_ASYNC_THREAD_STATE_SIG_STOP, P67_ASYNC_STATE_STOP);*/

    return err;
}

void *
__p67_net_persist_connect(void * arg)
{
    p67_conn_pass_t * pass = (p67_conn_pass_t *)arg;
    unsigned long interval = 0;
    p67_err err;

    DLOG("Background connect start\n");

    while(1) {
        if(pass->hconnect.state != P67_THREAD_SM_STATE_RUNNING) {
            err |= p67_err_eint;
            break;
        }

        // DLOG("Background connect iteration for %s:%s. Slept %lu ms\n", 
        //     pass->remote.hostname, pass->remote.service, interval);

        if(p67_conn_lookup(&pass->remote) == NULL) {
            if((err = p67_net_nat_connect(pass, P67_CONN_CNT_PASS)) != 0) {
                // p67_err_print_err("Background connect ", err);
            } else {
                DLOG("Background connected to %s:%s\n", 
                    pass->remote.hostname, pass->remote.service);
            }
        }

        if(pass->hconnect.state != P67_THREAD_SM_STATE_RUNNING) {
            err |= p67_err_eint;
            break;
        }

        if(1 != RAND_bytes((unsigned char *)&interval, sizeof(interval))) {
            p67_err_print_err("Background connect RAND_bytes ", p67_err_eerrno | p67_err_essl);
            break;
        }
        interval = (interval % P67_MOD_SLEEP_MS) + P67_MIN_SLEEP_MS;
        if(p67_cmn_sleep_ms(interval) != 0) {
            p67_err_print_err("Background connect p67_cmn_sleep_ms ", p67_err_eerrno);
            break;
        }
    }

    if(err != 0) p67_err_print_err("Background connect: ", err);
    p67_mutex_set_state(
        &pass->hconnect.state, 
        P67_THREAD_SM_STATE_RUNNING, 
        P67_THREAD_SM_STATE_STOP);
    p67_mutex_set_state(
        &pass->hconnect.state, 
        P67_THREAD_SM_STATE_SIG_STOP, 
        P67_THREAD_SM_STATE_STOP);
    return NULL;
}

p67_err
p67_net_start_persist_connect(p67_conn_pass_t * pass)
{
    p67_err err;

    /*
        this check is not needed but is placed here for convenience.
        better to return p67_err_eaconn than p67_err_easync
    */
    if(pass->hconnect.state != P67_THREAD_SM_STATE_STOP) 
        return p67_err_eaconn;

    if((err = p67_mutex_set_state(
            &pass->hconnect.state, 
            P67_THREAD_SM_STATE_STOP, 
            P67_THREAD_SM_STATE_RUNNING)) != 0) 
        return err;

    /* 
        since we dont simply pthread_kill or pthread_cancel there is no danger from putting 
        P67_ASYNC_THREAD_STATE_RUNNING before we start thread.
    */

    if((err = p67_cmn_thread_create(
            &pass->hconnect.thr, 
            __p67_net_persist_connect, 
            pass)) != 0) {
        err |= p67_mutex_set_state(
                &pass->hconnect.state,
                P67_THREAD_SM_STATE_RUNNING,
                P67_THREAD_SM_STATE_STOP);
    }

    return err;
}

p67_err
p67_net_write_conn(p67_conn_t * conn, const void * msg, int * msgl)
{
    p67_err err;

    if(conn == NULL)
        return p67_err_enconn;

    p67_async_t state;

    while(1) {
        state = conn->ssl_lock;
        if(state == P67_NET_SLOCK_STATE_TERM) {
            return p67_err_enconn;
        } else if(state == P67_NET_SLOCK_STATE_FREE) {
            if(p67_atomic_set_state(
                    &conn->ssl_lock, &state, P67_NET_SLOCK_STATE_LOCKED))
                break;
        } else if(state == P67_NET_SLOCK_STATE_LOCKED) {
            continue;
        } else {
            return p67_err_einval;
        }
    }

    if(conn->ssl == NULL || SSL_get_shutdown(conn->ssl) & SSL_RECEIVED_SHUTDOWN) {
        /*
            could try to reestablish communication. right now just return error
        */
        p67_atomic_must_set_state(
                &conn->ssl_lock, 
                P67_NET_SLOCK_STATE_LOCKED, 
                P67_NET_SLOCK_STATE_FREE);
        p67_conn_remove(&conn->addr_remote);
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
    
    p67_atomic_must_set_state(
        &conn->ssl_lock, 
        P67_NET_SLOCK_STATE_LOCKED, 
        P67_NET_SLOCK_STATE_FREE);
    
    return err;
}

p67_err
p67_net_must_write_conn(p67_conn_t * conn, const void * msg, int msgl)
{
    int wl = msgl;
    uint8_t * msgc = (uint8_t *)msg;
    p67_err err;

    while(1) {
        err = p67_net_write_conn(conn, msgc, &wl);

        if(err != 0)
            return err;

        if(wl == msgl) return 0;

        if(wl > msgl) return p67_err_einval;

        msgc+=wl;
        msgl-=wl;
    }
}

p67_err
p67_net_must_write(const p67_addr_t * addr, const void * msg, int msgl)
{
    p67_conn_t * conn;
    int wl = msgl;
    uint8_t * msgc = (uint8_t *)msg;
    p67_err err;

    if((conn = p67_conn_lookup(addr)) == NULL) return p67_err_enconn;

    err = p67_net_write_conn(conn, msgc, &wl);

    if(err != 0)
        return err;

    if(wl != msgl) {
        return err | p67_err_enconn;
    }

    return 0;
    // while(1) { 
    //     if((conn = p67_conn_lookup(addr)) == NULL) return p67_err_enconn;

    //     err = p67_net_write_conn(conn, msgc, &wl);

    //     if(err != 0)
    //         return err;

    //     if(wl == msgl) return 0;

    //     if(wl > msgl) return p67_err_einval;

    //     msgc+=wl;
    //     msgl-=wl;
    // }
}

p67_err
p67_net_write(const p67_addr_t * addr, const void * msg, int * msgl)
{
    p67_conn_t * conn;

    if((conn = p67_conn_lookup(addr)) == NULL) return p67_err_enconn;

    return p67_net_write_conn(conn, msg, msgl);
}

p67_err
p67_net_must_write_connect(p67_conn_pass_t * pass, const void * msg, int msgl)
{
    p67_conn_t * conn;
    p67_err err;

    if((conn = p67_conn_lookup(&pass->remote)) != NULL) {
        return p67_net_must_write(&conn->addr_remote, msg, msgl);
    }

    if((err = p67_net_nat_connect(pass, P67_CONN_CNT_PERSIST)) != 0 && err != p67_err_eaconn) {
        return err;
    }

    if((conn = p67_conn_lookup(&pass->remote)) != NULL) {
        return p67_net_must_write(&conn->addr_remote, msg, msgl);
    }

    return p67_err_enconn;
}

p67_err
p67_net_write_connect(
            p67_conn_pass_t * pass,
            const void * msg,
            int * msgl) 
{
    p67_conn_t * conn;
    p67_err err;

    if((conn = p67_conn_lookup(&pass->remote)) != NULL) {
        return p67_net_write_conn(conn, msg, msgl);
    }

    if((err = p67_net_nat_connect(pass, P67_CONN_CNT_PERSIST)) != 0 && err != p67_err_eaconn) {
        return err;
    }

    if((conn = p67_conn_lookup(&pass->remote)) != NULL) {
        return p67_net_write_conn(conn, msg, msgl);
    }

    return p67_err_enconn;
}

void
p67_conn_remove_all(void)
{
    size_t i;
    
    for(i = 0; i < CONN_CACHE_LEN; i++) {
        if(conn_cache[i] == NULL) continue;
        p67_conn_remove(&conn_cache[i]->addr_remote);
    }
}

void
p67_net_free(void)
{
    p67_conn_remove_all();
}

void
p67_net_init(void)
{
    OpenSSL_add_ssl_algorithms();
    SSL_load_error_strings();
}

p67_err
p67_net_start_listen(p67_conn_pass_t * pass)
{
    p67_err err;

    /* for explanation see body of p67_net_start_persist_connect */
    if(pass->hlisten.state != P67_THREAD_SM_STATE_STOP) 
        return p67_err_eaconn;

    if((err = p67_mutex_set_state(
            &pass->hlisten.state, 
            P67_THREAD_SM_STATE_STOP, 
            P67_THREAD_SM_STATE_RUNNING)) != 0)
        return err;

    if((err = p67_cmn_thread_create(&pass->hlisten.thr, __p67_net_listen, pass)) != 0) {
        err |= p67_mutex_set_state(
            &pass->hlisten.state, 
            P67_THREAD_SM_STATE_RUNNING, 
            P67_THREAD_SM_STATE_STOP);
        return err;
    }

    return 0;
}

void *
__p67_net_listen(void * args)
{
    p67_err err;
    p67_conn_pass_t * pass = (p67_conn_pass_t *)args;

    err = p67_net_listen(pass);

    if(err != 0) p67_err_print_err("Background listen: ", err);

    return NULL;
}

p67_err
p67_net_listen(p67_conn_pass_t * pass)
{
    p67_sfd_t sfd;
    SSL_CTX * ctx;
    SSL * ssl;
    BIO * bio;
    p67_sockaddr_t remote;
    p67_conn_t * conn;
    p67_err err;
    p67_thread_t accept_thr;

    // if(pass->hlisten.state != P67_ASYNC_STATE_STOP)
    //     return p67_err_eaconn;
    // if((err = p67_async_set_state(
    //                 &pass->hlisten, P67_ASYNC_STATE_STOP, P67_ASYNC_THREAD_STATE_RUNNING)) != 0)
    //     return err;

    p67_err_mask_all(err);

    ctx = NULL;
    ssl = NULL;
    bio = NULL;
    sfd = 0;

    if((ctx = SSL_CTX_new(DTLS_server_method())) == NULL)
        return err;

    if((SSL_CTX_set_cipher_list(ctx, CIPHER)) != 1)
        goto end;

    SSL_CTX_set_session_cache_mode(ctx, SSL_SESS_CACHE_OFF);

    if(SSL_CTX_use_certificate_file(ctx, pass->certpath, SSL_FILETYPE_PEM) != 1)
        goto end;

    if(SSL_CTX_use_PrivateKey_file(ctx, pass->keypath, SSL_FILETYPE_PEM) != 1)
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

    if((err = p67_sfd_create_from_addr(&sfd, &pass->local, P67_SFD_TP_DGRAM_UDP)) != 0)
        goto end;

    if((err = p67_sfd_set_reuseaddr(sfd)) != 0) goto end;
    
    if((err = p67_sfd_bind(sfd, &pass->local)) != 0) goto end;

    //if((err = p67_sfd_set_noblocking(sfd)) != 0) goto end;

    DLOG("Listening @ %s:%s\n", pass->local.hostname, pass->local.service);

    while(1) {
        p67_err_mask_all(err);
        ssl = NULL;

        if((bio = BIO_new_dgram(sfd, BIO_NOCLOSE)) == NULL) goto end;

        //p67_net_bio_set_timeout(bio, P67_DEFAULT_TIMEOUT_MS);

        if((ssl = SSL_new(ctx)) == NULL) goto end;

        SSL_set_bio(ssl, bio, bio);
        if(!(SSL_set_options(ssl, SSL_OP_COOKIE_EXCHANGE) & SSL_OP_COOKIE_EXCHANGE))
            goto end;
        
        if(pass->hlisten.state != P67_THREAD_SM_STATE_RUNNING) {
            err = p67_err_eint;
            goto end;
        }

        while (DTLSv1_listen(ssl, (BIO_ADDR *)&remote) <= 0) {
            if(pass->hlisten.state != P67_THREAD_SM_STATE_RUNNING) {
                err = p67_err_eint;
                goto end;
            }
        }

        do {
            if((conn = calloc(sizeof(p67_conn_t), 1)) == NULL) break;
            if((err = p67_addr_dup(&conn->addr_local, &pass->local)) != 0) break;
            if((err = p67_addr_set_sockaddr(&conn->addr_remote, &remote, sizeof(remote))) != 0)
                break;
            //DLOG("Accepting %s:%s...\n", conn->addr_remote.hostname, conn->addr_remote.service);
            conn->callback = pass->handler;
            if(pass->gen_args != NULL)
                conn->args = pass->gen_args(pass->args);
            else
                conn->args = pass->args;
            conn->free_args = pass->free_args;
            conn->ssl = ssl;
            conn->ssl_lock = P67_NET_SLOCK_STATE_LOCKED;
            if((err = p67_conn_insert_existing(conn)) != 0) break;
            if((err = p67_cmn_thread_create(&accept_thr, __p67_net_accept, conn)) != 0) {
                p67_conn_remove(&conn->addr_remote);
                err = 0;
                break;
            }
            //err = 0;
        } while(0);

        if(err != 0) 
            p67_conn_free(conn, 1);
    }

end:
    if(ctx != NULL) SSL_CTX_free(ctx);
    p67_sfd_close(sfd);
    if(ssl != NULL) SSL_free(ssl);
    p67_mutex_set_state(
        &pass->hlisten.state, 
        P67_THREAD_SM_STATE_SIG_STOP, 
        P67_THREAD_SM_STATE_STOP);
    return err;
}

/*
    generate cert from pre existing key
*/
p67_err
p67_net_create_cert_from_key(const char * path, const char * address)
{
    if(path == NULL || strlen(path) == 0) return p67_err_einval;

    X509 * x = NULL;
    EVP_PKEY * priv = NULL, * pub = NULL;
    BIO * privb = NULL, * pubb = NULL;
    FILE * keypr = NULL, * keypub = NULL, * cert = NULL;
    X509_NAME * name;
    size_t pathl = strlen(path);
    size_t extpl = pathl + 6;
    p67_err err;
    char * extp;

    p67_err_mask_all(err);

    if((extp = malloc(extpl)) == NULL) goto end;

    if(memcpy(extp, path, pathl) == NULL) goto end;

    if((keypr = fopen(extp, "w")) == NULL) goto end;

    if((privb = BIO_new_fp(keypr, BIO_NOCLOSE)) == NULL) goto end;

    if((PEM_read_bio_PrivateKey(privb, &priv, NULL, NULL)) == NULL) goto end;

    sprintf(extp+pathl, ".pub");
    if((keypub = fopen(extp, "w")) == NULL) goto end;

    if((pubb = BIO_new_fp(keypub, BIO_NOCLOSE)) == NULL) goto end;

    if((PEM_read_bio_PUBKEY(pubb, &pub, NULL, NULL)) == NULL) goto end;
    
    if((x = X509_new()) == NULL) goto end;

    X509_set_version(x, 2);
	X509_gmtime_adj(X509_get_notBefore(x),0);
	X509_gmtime_adj(X509_get_notAfter(x),DAYS_TO_SEC(30));
	X509_set_pubkey(x,pub);

    name = X509_get_subject_name(x);
    X509_NAME_add_entry_by_txt(
        name, "CN", MBSTRING_ASC, (const unsigned char *)address, -1, -1, 0);
	X509_set_issuer_name(x,name);

    if(X509_sign(x, priv, EVP_sha256()) <= 0) goto end;

    sprintf(extp+pathl, ".cert");
    if((cert = fopen(extp, "w")) == NULL) goto end;

    if(PEM_write_X509(cert, x) != 1) goto end;

    err = 0;

end:
    BIO_free_all(privb);
    BIO_free_all(pubb);
    EVP_PKEY_free(priv);
    EVP_PKEY_free(pub);
    X509_free(x);
    if(keypr != NULL)
        fclose(keypr);
    if(keypub != NULL)
        fclose(keypub);
    if(cert != NULL)
        fclose(cert);
    if(extp != NULL)
        free(extp);

    return err;
}

/*
    generate key pair
*/
p67_err
p67_net_new_key(char * path) 
{
    if(path == NULL || strlen(path) == 0) return p67_err_einval;

    EVP_PKEY * keystor = NULL;
    EC_KEY * key = NULL;
    BIO * fbio = NULL;
    FILE * keypr = NULL, * keypub = NULL;
    size_t pathl = strlen(path);
    size_t extpl = pathl + 6;
    char * extp = malloc(extpl);
    p67_err err;

    p67_err_mask_all(err);

    if(extp == NULL) goto end;

    bzero(extp, extpl);

    if(memcpy(extp, path, pathl) == NULL) goto end;

    if((keystor = EVP_PKEY_new()) == NULL) goto end;

    if((key = EC_KEY_new_by_curve_name(NID_secp384r1)) == NULL) goto end;

    EC_KEY_set_asn1_flag(key, OPENSSL_EC_NAMED_CURVE);

    if(EC_KEY_generate_key(key) != 1) goto end;

    if(EVP_PKEY_assign_EC_KEY(keystor, key) != 1) goto end;

    if((keypr = fopen(extp, "w")) == NULL) goto end;

    if((fbio = BIO_new_fp(keypr, BIO_NOCLOSE)) == NULL) goto end;

    if(PEM_write_bio_PrivateKey(
            fbio, keystor, NULL, NULL, 0, 0, NULL) != 1) goto end;

    sprintf(extp+pathl, ".pub");
    if((keypub = fopen(extp, "w")) == NULL) goto end;

    if(BIO_set_fp(fbio, keypub, BIO_NOCLOSE) != 1) goto end;

    if(PEM_write_bio_PUBKEY(fbio, keystor) != 1) goto end;

    err = 0;

end:
    BIO_free_all(fbio);
    EVP_PKEY_free(keystor);
    if(keypr != NULL)
        fclose(keypr);
    if(keypub != NULL)
        fclose(keypub);
    if(extp != NULL)
        free(extp);

    return err;
}


/*
    generate certificate along with its key.
    address is null terminated public ip of the host
*/
p67_err
p67_net_new_cert(const char * path, const char * address)
{
    if(path == NULL || strlen(path) == 0) return p67_err_einval;

    X509 * x = NULL;
    EVP_PKEY * keystor = NULL;
    EC_KEY * key = NULL;
    BIO * fbio = NULL;
    FILE * keypr = NULL, * keypub = NULL, * cert = NULL;
    X509_NAME * name;
    size_t pathl = strlen(path);
    size_t extpl = pathl + 6;
    char * extp = malloc(extpl);
    p67_err err;

    p67_err_mask_all(err);

    if(extp == NULL) goto end;
    
    bzero(extp, extpl);
    
    if(memcpy(extp, path, pathl) == NULL) goto end;

    if((keystor = EVP_PKEY_new()) == NULL) goto end;

    if((key = EC_KEY_new_by_curve_name(NID_secp384r1)) == NULL) goto end;

    EC_KEY_set_asn1_flag(key, OPENSSL_EC_NAMED_CURVE);

    if(EC_KEY_generate_key(key) != 1) goto end;

    if(EVP_PKEY_assign_EC_KEY(keystor, key) != 1) goto end;

    if((keypr = fopen(extp, "w")) == NULL) goto end;

    if((fbio = BIO_new_fp(keypr, BIO_NOCLOSE)) == NULL) goto end;

    if(PEM_write_bio_PrivateKey(fbio, keystor, NULL, NULL, 0, 0, NULL) != 1) goto end;

    sprintf(extp+pathl, ".pub");
    if((keypub = fopen(extp, "w")) == NULL) goto end;

    if(BIO_set_fp(fbio, keypub, BIO_NOCLOSE) != 1) goto end;

    if(PEM_write_bio_PUBKEY(fbio, keystor) != 1) goto end;

    if((x = X509_new()) == NULL) goto end;

    X509_set_version(x, 2);
	X509_gmtime_adj(X509_get_notBefore(x),0);
	X509_gmtime_adj(X509_get_notAfter(x),DAYS_TO_SEC(30));
	X509_set_pubkey(x,keystor);

    name = X509_get_subject_name(x);
    X509_NAME_add_entry_by_txt(
            name, "CN", MBSTRING_ASC, (const unsigned char *)address, -1, -1, 0);
	X509_set_issuer_name(x,name);

    if(X509_sign(x, keystor, EVP_sha256()) <= 0) goto end;

    sprintf(extp+pathl, ".cert");
    if((cert = fopen(extp, "w")) == NULL) goto end;

    if(PEM_write_X509(cert, x) != 1) goto end;

    err = 0;

end:
    BIO_free_all(fbio);
    EVP_PKEY_free(keystor);
    X509_free(x);
    if(keypr != NULL)
        fclose(keypr);
    if(keypub != NULL)
        fclose(keypub);
    if(cert != NULL)
        fclose(cert);
    if(extp != NULL)
        free(extp);

    return err;
}

p67_err
p67_net_start_connect_and_listen(p67_conn_pass_t * pass)
{
    p67_err err;

    err = p67_net_start_listen(pass);

    if(err != 0) return err;

    err = p67_net_start_persist_connect(pass);

    if(err != 0)
        err |= p67_thread_sm_terminate(
                &pass->hconnect, P67_THREAD_SM_TIMEOUT_DEF);
    
    return err;
}

p67_err
p67_net_async_terminate(p67_conn_pass_t * pass)
{
    p67_err err = 0;

    err |= p67_thread_sm_terminate(
            &pass->hconnect, P67_THREAD_SM_TIMEOUT_DEF);
    err |= p67_thread_sm_terminate(
            &pass->hlisten, P67_THREAD_SM_TIMEOUT_DEF);

    return err;
}


p67_err
p67_net_mux_cb_arg_init(struct p67_mux_cb_arg * v, size_t cblen)
{
    if(v == NULL || cblen < 1) return p67_err_einval;

    if((v->cb_arr = calloc(sizeof(p67_conn_callback_t *), cblen)) == NULL)
        return p67_err_eerrno;
    v->lock = 0;
    v->cb_arr_l = cblen;

    return 0;
}

void
p67_net_mux_cb_arg_free(struct p67_mux_cb_arg * v)
{
    if(v == NULL) return;
    free(v->cb_arr);
}

p67_err
p67_net_mux_callback(p67_conn_t * conn, const char * msg, int msgl, void * args)
{
    struct p67_mux_cb_arg * cba = (struct p67_mux_cb_arg *)args;
    size_t i;
    p67_err err;

    p67_spinlock_lock(&cba->lock);

    for(i = 0; i < cba->cb_arr_l; i++) {
        if(cba->cb_arr == NULL)
            continue;
        err = cba->cb_arr[i](conn, msg, msgl, cba->cb_arr_arg[i]);
        if(err == 0)
            break;
        else if(err == p67_err_eagain)
            continue;
        else
            return err;
    }

    p67_spinlock_unlock(&cba->lock);

    return 0;
}

/*
    tries to connect to the peer and returns 0 when finished.
*/
p67_err
p67_net_seq_connect_listen(p67_conn_pass_t * pass)
{
    p67_err err;
    unsigned int interval;

    while(1) {
        if((err = p67_net_start_listen(pass)) != 0)
            return err;

        if(1 != RAND_bytes((unsigned char *)&interval, sizeof(interval)))
            return p67_err_essl;
        interval = (interval % P67_MOD_SLEEP_MS) + P67_MIN_SLEEP_MS;
        if((err = p67_cmn_sleep_ms(interval)) != 0)
            return err;

        if((err = p67_thread_sm_terminate(&pass->hlisten, -1)) != 0)
            return err;
        if(p67_conn_lookup(&pass->remote) != NULL)
            return 0;
        
        if((err = p67_net_start_persist_connect(pass)) != 0)
            return err;
            
        if(1 != RAND_bytes((unsigned char *)&interval, sizeof(interval)))
            return p67_err_essl;
        interval = (interval % P67_MOD_SLEEP_MS) + P67_MIN_SLEEP_MS;
        if((err = p67_cmn_sleep_ms(interval)) != 0)
            return err;

        if((err = p67_thread_sm_terminate(&pass->hconnect, -1)) != 0)
            return err;
        if(p67_conn_lookup(&pass->remote) != NULL)
            return 0;
    }

    return 0;
}
