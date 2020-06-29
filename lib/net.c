#include <openssl/ssl.h>
#include <openssl/rand.h>
#include <openssl/err.h>

#include <string.h>
#include <strings.h>
#include <sys/time.h>
#include <errno.h>

#include "err.h"
#include "sfd.h"
#include "log.h"
#include "cmn.h"

p67_mutex_t cookie_lock = P67_CMN_MUTEX_INITIALIZER;
int cookie_initialized=0;
#define COOKIE_SECRET_LENGTH 32
unsigned char cookie_secret[COOKIE_SECRET_LENGTH];

typedef struct p67_conn p67_conn_t;
typedef struct p67_node p67_node_t;

typedef p67_err (* p67_conn_callback_t)(p67_conn_t * conn, char *, int); 

/*
    Structure representing physical established connections.
    All connections are kept in conn_cache hash table.
*/
struct p67_conn {
    p67_addr_t addr_local;
    p67_addr_t addr_remote;
    SSL * ssl;
    p67_conn_callback_t callback;
    p67_conn_t * next;
};

/*
    Structure representing loaded peers along with Their trusted keys 
    with whom we can connect, or who are blocked.
    newly arriwed requests are kept in the queue until user accepts them.
*/
struct p67_node {
    p67_addr_t trusted_addr;
    char * trusted_pub_key;
};

#define CONN_CACHE_LEN 337
#define NODE_CACHE_LEN 337
#define QUEUE_CACHE_LEN 337

p67_conn_t * conn_cache[CONN_CACHE_LEN];
p67_node_t * node_cache[NODE_CACHE_LEN];
p67_node_t * queue_cache[QUEUE_CACHE_LEN];

#define P67_FH_FNV1_OFFSET (p67_hash_t)0xcbf29ce484222425
#define P67_FH_FNV1_PRIME (p67_hash_t)0x100000001b3

#define CIPHER "ECDHE-ECDSA-AES256-GCM-SHA384"
#define CIPHER_ALT "HIGH:!aNULL:!kRSA:!PSK:!SRP:!MD5:!RC4"

#define READ_BUFFER_LENGTH 128
/*
    ssl error strings
*/
#define ERR_BUFFER_LENGTH 128


#define p67_conn_size sizeof(p67_conn_t)

typedef unsigned long p67_hash_t;

/*---BEGIN PRIVATE PROTOTYPES---*/

/*
    if also_free_ptr is set to 1 then free conn pointer itself.
    otherwise only free dependencies.
*/
void
p67_conn_free(p67_conn_t * conn, int also_free_ptr);

extern inline p67_hash_t
p67_conn_cache_fn(const __u_char * key, int len);

#define p67_net_is_already_connected(addr) \
    (p67_conn_pool_lookup((addr)) != NULL)

p67_conn_t *
p67_conn_pool_lookup(p67_addr_t * addr);

p67_err
p67_conn_pool_insert(
    p67_addr_t * local, 
    p67_addr_t * remote, 
    SSL * ssl, 
    p67_conn_callback_t callback, 
    p67_conn_t ** ret);

p67_err
p67_conn_pool_remove(p67_addr_t * addr);

int 
p67_net_verify_cookie(
        SSL *ssl, 
        const unsigned char *cookie, 
        unsigned int cookie_len);

int 
p67_net_generate_cookie(
        SSL *ssl, 
        unsigned char *cookie,
        unsigned int *cookie_len);

p67_err
p67_net_bio_set_timeout(BIO * bio, time_t sec);

void * 
__p67_net_read_loop(void * args);

void
p67_net_read_loop(p67_conn_t * conn);

p67_err
p67_net_get_addr_from_x509_store_ctx(X509_STORE_CTX *ctx, p67_addr_t * addr);

#define p67_get_cert_str(x509) p67_get_pem_str(x509, 1);

char * 
p67_net_get_pem_str(X509 * x509, int type);

/*---END PRIVATE PROTOTYPES---*/

void
p67_conn_free(p67_conn_t * conn, int also_free_ptr)
{
    int sfd;

    if(conn == NULL) return;

    DLOG("shutdown for %s:%s\n", conn->addr_remote.hostname, conn->addr_remote.service);

    p67_addr_free(&conn->addr_local);
    p67_addr_free(&conn->addr_remote);
    
    if(conn->ssl != NULL) {
        SSL_shutdown(conn->ssl);
        if((sfd = SSL_get_fd(conn->ssl)) > 0) p67_sfd_close(sfd);
        SSL_free(conn->ssl);
        conn->ssl = NULL;
    }

    if(also_free_ptr) free(conn);
    
    return;
}

inline p67_hash_t
p67_conn_cache_fn(const __u_char * key, int len)
{
    p67_hash_t hash = P67_FH_FNV1_OFFSET;
    while(len-->0) {
        hash ^= *(key++);
        hash *= P67_FH_FNV1_PRIME;
    }
    return (hash % CONN_CACHE_LEN);
}

p67_conn_t *
p67_conn_pool_lookup(p67_addr_t * addr)
{
    if(addr == NULL) return NULL;
    p67_conn_t * ret = NULL;
    p67_hash_t hash = p67_conn_cache_fn((__u_char *)&addr->sock, addr->socklen);
    for(ret = conn_cache[hash]; ret != NULL; ret = ret->next) {
        if(ret->addr_remote.socklen != addr->socklen)
            continue;
        if(memcmp(&addr->sock, &ret->addr_remote.sock, addr->socklen) == 0) break;
    }
    if(ret != NULL) return ret;
    return NULL;
}

p67_err
p67_conn_pool_insert(
    p67_addr_t * local, 
    p67_addr_t * remote, 
    SSL * ssl, 
    p67_conn_callback_t callback, 
    p67_conn_t ** ret) 
{
    if(remote == NULL) return p67_err_einval;

    unsigned long hash = p67_conn_cache_fn((__u_char *)&remote->sock, remote->socklen);
    p67_conn_t * r = conn_cache[hash], ** np = NULL;

    do {
        if(r == NULL) break;
        if(r->addr_remote.socklen == remote->socklen 
                && memcmp(&remote->sock, &r->addr_remote.sock, r->addr_remote.socklen) == 0) 
            return p67_err_eaconn;
        if(r->next == NULL) break;
    } while ((r=r->next) != NULL);
    
    if(r == NULL) {
        np = &conn_cache[hash];
    } else {
        np = &r->next;
    }

    if((*np = calloc(sizeof(**np), 1)) == NULL) goto err;
    if(p67_addr_dup(&(*np)->addr_local, local) != 0) goto err;
    if(p67_addr_dup(&(*np)->addr_remote, remote) != 0) goto err;
    if(callback != NULL) (*np)->callback = callback;
    if(ssl != NULL) (*np)->ssl = ssl;

    if(ret != NULL)
        *ret = *np;

    return 0;

err:
    if(np == NULL || *np == NULL)
        return p67_err_eerrno;

    p67_addr_free(&(*np)->addr_local);
    p67_addr_free(&(*np)->addr_remote);
    free(*np);
    *np = NULL;

    return p67_err_eerrno;
}

p67_err
p67_conn_pool_remove(p67_addr_t * addr)
{
    if(addr == NULL) return p67_err_einval;

    // remove Y from X -> Y -> Z    =>    X -> Z
    // remove Y from Y -> X -> Z    =>    X -> Z

    p67_conn_t * ptr, * prev;
    unsigned long hash = p67_conn_cache_fn((__u_char *)&addr->sock, addr->socklen);

    prev = NULL;
    ptr = NULL;

    for(ptr = conn_cache[hash]; ptr != NULL; ptr = (ptr)->next) {
        if(addr->socklen == ptr->addr_remote.socklen 
            && memcmp(&addr->sock, &ptr->addr_remote.sock, ptr->addr_remote.socklen) == 0) break;
        prev = ptr;
    }

    if(ptr == NULL) return p67_err_enconn;

    if(prev == NULL) {
        conn_cache[hash] = NULL;
    } else {
        prev->next = ptr->next;
    }

    p67_conn_free(ptr, 1);

    return 0;
}

int 
p67_net_generate_cookie(SSL *ssl, unsigned char *cookie, unsigned int *cookie_len)
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
p67_net_verify_cookie(SSL *ssl, const unsigned char *cookie, unsigned int cookie_len)
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

	if (cookie_len == resultlength && memcmp(result, cookie, resultlength) == 0)
		return 1;

	return 0;
}

p67_err
p67_net_bio_set_timeout(BIO * bio, time_t sec)
{
    struct timeval tv;
    tv.tv_sec = sec;
    tv.tv_usec = 0;
    if(BIO_ctrl(bio, BIO_CTRL_DGRAM_SET_RECV_TIMEOUT, 0, &tv) != 1) {
        return -1;
    }
    if(BIO_ctrl(bio, BIO_CTRL_DGRAM_SET_SEND_TIMEOUT, 0, &tv) != 1) {
        return -1;
    }
    return 0;
}

void * 
__p67_net_read_loop(void * args)
{
    p67_net_read_loop((p67_conn_t *)args);
    return NULL;
}

void
p67_net_read_loop(p67_conn_t * conn)
{
    ssize_t len;
    BIO * bio;
    char rbuff[READ_BUFFER_LENGTH], errbuf[ERR_BUFFER_LENGTH];
    int num_timeouts = 0, max_timeouts = 5, sslr = 1, err, callret;

    p67_err_mask_all(err);
    
    if((bio = SSL_get_rbio(conn->ssl)) == NULL) goto end;
    
    DLOG("Entering read loop\n");

    while(!(SSL_get_shutdown(conn->ssl) & SSL_RECEIVED_SHUTDOWN && num_timeouts < max_timeouts)) {
        sslr = 1;
        while(sslr) {
            len = SSL_read(conn->ssl, rbuff, READ_BUFFER_LENGTH-1);
            rbuff[len] = 0;

            err = SSL_get_error(conn->ssl, len);

            switch (err) {
            case SSL_ERROR_NONE:
                callret = (*conn->callback)(conn, rbuff, len);
                if(callret != 0) goto end;
                break;
            case SSL_ERROR_WANT_READ:
                if (BIO_ctrl(bio, BIO_CTRL_DGRAM_GET_RECV_TIMER_EXP, 0, NULL)) {
					num_timeouts++;
					sslr = 0;
				}
                break;
            case SSL_ERROR_ZERO_RETURN:
                goto end;
            default:
                if(err == SSL_ERROR_SYSCALL)
                    DLOG("ssl_read: %d : %s\n", errno, strerror(errno));
                else
                    DLOG("in read loop: %s\n", ERR_error_string(err, errbuf));
                sslr = 0;
                break;
            }
        }
    }

    end:
    DLOG("Exitting read loop\n");
    if(conn != NULL) p67_conn_pool_remove(&conn->addr_remote);
    return;
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
    X509_PUBKEY * xpubk;
    EVP_PKEY * pubk;
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
    return err == 0 ? outbuff : NULL;
}

int 
p67_net_verify_callback(int ok, X509_STORE_CTX *ctx) 
{
    p67_addr_t addr;
    X509 * x509;
    char *pubk = NULL;
    struct node_info * ni;
    int cnix, success = 0, asnl;
    X509_NAME * x509_name;
    X509_NAME_ENTRY * ne;
    ASN1_STRING * castr;
    EVP_PKEY * pkey;

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
    if(pns_get_node(PNSTQUEUE, &addr) != NULL) {
        X509_STORE_CTX_set_error(ctx, X509_V_ERR_CERT_REJECTED);
        return 0;
    }

    if((x509 = X509_STORE_CTX_get_current_cert(ctx)) == NULL) {
        return 0;
    }

    if((pubk = alloc_extract_pem_str(x509, 2)) == NULL) {
        return 0;
    }

    /* 
        if remote is first timer then allow him to proceed ( will be queued by protocol ) 
        but warn user about new host
    */
    if((ni = pns_get_node(PNSTCACHE, &addr)) == NULL) {
        LOG_DBG_PRINTF("Unknown host connecting from %s with public key:\n%s", addrs, pubk);
        success = 1;
        goto end;
    }

    if(ni->known_key == NULL) {
        LOG_PRINTF("Couldnt verify host ( %s ) with public key:\n%sHost moved to queue\n", addrs, pubk);
        if(pns_remove_node(PNSTCACHE, &addr) != 0) {
            LOG_PRINTF("Couldnt remove host from cache. %s\n", PE_STRERROR(errno));
            success = 0;
            goto end;
        }
        if(pns_insert_node(PNSTQUEUE, &addr) == NULL) {
            LOG_PRINTF("Couldnt insert host to cache. %s\n", PE_STRERROR(errno));
            success = 0;
            goto end;
        }
        success = 1;
        goto end;
    }


    #if defined(USEIPV6)

    inet_ntop(AF_INET6, &ni->addr, ips, INET6_ADDRSTRLEN);

    #else

    ips = inet_ntoa(ADDR_ADDR(ni->addr));

    #endif

    if((pkey = X509_get_pubkey(x509)) == NULL) {
        success = 0;
        goto end;
    }

    if(X509_verify(x509, pkey) != 1) {
        LOG_DBG_PRINTF("Invalid SSL certificate coming from host at %s.\nInvalid signature.\n", addrs);
        success = 0;
        goto end;
    }

    if((x509_name = X509_get_subject_name(x509)) == NULL) {
        success = 0;
        goto end;
    }

    if((cnix = X509_NAME_get_index_by_NID(x509_name, NID_commonName, -1)) < 0) {
        success = 0;
        goto end;
    }

    if((ne = X509_NAME_get_entry(x509_name, cnix)) == NULL) {
        success = 0;
        goto end;
    }

    if((castr = X509_NAME_ENTRY_get_data(ne)) == NULL) {
        success = 0;
        goto end;
    }

    asnl = ASN1_STRING_length(castr);
    
    if((size_t)asnl != strlen(ips) || memcmp(ips, ASN1_STRING_get0_data(castr), asnl) != 0) {
        LOG_DBG_PRINTF(
            "Invalid SSL certificate coming from host at %s. CN is set to %s\n", 
            ips,
            ASN1_STRING_get0_data(castr));
        success = 0;
        return 0;
    }

    if((strlen(ni->known_key) != strlen(pubk)) || memcmp(ni->known_key, pubk, strlen(pubk)) != 0) {
        LOG_PRINTF("Invalid SSL certificate coming from host at address %s.\n"
            "This can be potential mitm attack. Host moved to queue.\n", addrs);

        LOG_DBG_PRINTF("expected: \n%s\ngot:\n%s\n", ni->known_key, pubk);

        /* 
            right now removing node from cache and insert into nodes so its ignored. 
            up to user to trust him ( by accepting ) or ignore 
        */
        success = 0;

        if(pns_remove_node(PNSTCACHE, &addr) != 0) {
            LOG_DBG_PRINTF("Couldnt remove host from cache. %s\n", PE_STRERROR(errno));
            goto end;
        }
        if(pns_insert_node(PNSTQUEUE, &addr) == NULL) {
            LOG_DBG_PRINTF("Couldnt insert host to cache. %s\n", PE_STRERROR(errno));
            goto end;
        }
        goto end;
    }

    success = 1;

end:
    if(pubk != NULL) {
        free(pubk);
    }
    // should those variables be freed?
    if(pkey != NULL) {
        EVP_PKEY_free(pkey);
    }
	return success;
}
