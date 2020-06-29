#include <openssl/ssl.h>
#include <openssl/rand.h>
#include <openssl/err.h>

#if !defined(__USE_XOPEN_EXTENDED)
#define __USE_XOPEN_EXTENDED
#endif
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

typedef struct p67_liitem p67_liitem_t;

typedef p67_err (* p67_conn_callback_t)(p67_conn_t * conn, char *, int); 

/* linked item - generic structure used in hash table operations */
struct p67_liitem {
    p67_liitem_t * next;
    p67_addr_t key;
};

/*
    Structure representing physical established connections.
    All connections are kept in conn_cache hash table.
*/
struct p67_conn {
    p67_conn_t * next;
    p67_addr_t addr_remote;
    p67_addr_t addr_local;
    SSL * ssl;
    p67_conn_callback_t callback;
};

typedef __uint16_t p67_state_t;

#define P67_NODE_STATE_QUEUE 1

#define P67_NODE_STATE_ALL 1

/*
    Structure representing known ( not nessesarily connected ) peers.
    newly arrived requests are kept in the queue state until user accepts them.
*/
struct p67_node {
    p67_node_t * next;
    p67_addr_t trusted_addr;
    /* heap allocated null terminated string */
    char * trusted_pub_key;
    p67_state_t state;
};

#define CONN_CACHE_LEN 337
#define NODE_CACHE_LEN 337

p67_conn_t * conn_cache[CONN_CACHE_LEN];
p67_node_t * node_cache[NODE_CACHE_LEN];

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
p67_conn_free(void * ptr, int also_free_ptr);

void
p67_node_free(void * ptr, int also_free_ptr);

extern inline p67_hash_t
p67_hash_fn(const __u_char * key, int len);

/* cache types for nodes */
#define P67_CT_NODE 1
#define P67_CT_CONN 2

extern inline p67_err 
p67_hash_get_table(int p67_ct, p67_liitem_t *** out, size_t * outl);

#define p67_conn_lookup(addr) \
    ((p67_conn_t *)p67_hash_lookup(P67_CT_CONN, (addr)))

#define p67_node_lookup(addr) \
    ((p67_node_t *)p67_hash_lookup(P67_CT_NODE, (addr)))

p67_liitem_t * 
p67_hash_lookup(int p67_ct, const p67_addr_t * key);

#define p67_conn_is_already_connected(addr) \
    (p67_conn_lookup((addr)) != NULL)

p67_err
p67_hash_insert(int p67_ct, const p67_addr_t * key, p67_liitem_t ** ret);

p67_err
p67_conn_insert(
    p67_addr_t * local, 
    p67_addr_t * remote, 
    SSL * ssl, 
    p67_conn_callback_t callback, 
    p67_conn_t ** ret);

p67_err
p67_node_insert(
    const p67_addr_t * addr,
    const char * trusted_key,
    int strdup_key,
    p67_node_t ** ret);

typedef void (* dispose_callback_t)(void * p, int);

#define p67_conn_remove(addr) \
    p67_hash_remove(P67_CT_CONN, addr, NULL, p67_conn_free)

#define p67_node_remove(addr) \
    p67_hash_remove(P67_CT_NODE, addr, NULL, p67_node_free)

/*
    removes ptr from hash tbl and places it in * out so user can free it.
    If callback is provided then item will be disposed and nothing will be placed in *out
*/
p67_err
p67_hash_remove(
        int p67_ct, 
        p67_addr_t * addr, 
        p67_liitem_t ** out, 
        dispose_callback_t callback);

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

#define P67_PEM_CERT   1
#define P67_PEM_PUBKEY 2

#define p67_get_cert_str(x509) p67_get_pem_str(x509, P67_PEM_CERT);

char * 
p67_net_get_pem_str(X509 * x509, int type);

int 
p67_net_verify_callback(int ok, X509_STORE_CTX *ctx);

/*---END PRIVATE PROTOTYPES---*/

void
p67_conn_free(void * ptr, int also_free_ptr)
{
    int sfd;
    p67_conn_t * conn = (p67_conn_t *)ptr;

    if(ptr == NULL) return;

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

/* fnv 1a */
inline p67_hash_t
p67_hash_fn(const __u_char * key, int len)
{
    p67_hash_t hash = P67_FH_FNV1_OFFSET;
    while(len-->0) {
        hash ^= *(key++);
        hash *= P67_FH_FNV1_PRIME;
    }
    return (hash % CONN_CACHE_LEN);
}

inline p67_err 
p67_hash_get_table(int p67_ct, p67_liitem_t *** out, size_t * outl)
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
p67_hash_lookup(int p67_ct, const p67_addr_t * key)
{
    p67_liitem_t * ret = NULL, ** cc;
    p67_hash_t hash = p67_hash_fn((__u_char *)&key->sock, key->socklen);

    if(key == NULL) return NULL;

    if(p67_hash_get_table(p67_ct, &cc, NULL) != 0)
        return NULL;

    for(ret = cc[hash]; ret != NULL; ret = ret->next) {
        if(ret->key.socklen != key->socklen)
            continue;
        if(memcmp(&key->sock, &ret->key.sock, key->socklen) == 0) break;
    }
    if(ret != NULL) return ret;
    return NULL;
}

p67_err
p67_hash_insert(int p67_ct, const p67_addr_t * key, p67_liitem_t ** ret)
{
    if(key == NULL) return p67_err_einval;

    unsigned long hash = p67_hash_fn((__u_char *)&key->sock, key->socklen);
    p67_liitem_t * r, ** np = NULL;
    p67_liitem_t ** cc;

    if(p67_hash_get_table(p67_ct, &cc, NULL) != 0) return p67_err_einval;

    r = cc[hash];

    do {
        if(r == NULL) break;
        if(r->key.socklen == key->socklen 
                && memcmp(&key->sock, &r->key.sock, r->key.socklen) == 0) 
            return p67_err_eaconn;
        if(r->next == NULL) break;
    } while ((r=r->next) != NULL);
    
    if(r == NULL) {
        np = &cc[hash];
    } else {
        np = &r->next;
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

    return 0;

err:
    if(np == NULL || *np == NULL)
        return p67_err_eerrno;

    free(*np);
    *np = NULL;

    return p67_err_eerrno;
}

p67_err
p67_conn_insert(
    p67_addr_t * local, 
    p67_addr_t * remote, 
    SSL * ssl, 
    p67_conn_callback_t callback, 
    p67_conn_t ** ret) 
{
    p67_err err;
    p67_addr_t laddr;
    p67_conn_t * conn;

    /* malloc before inserting to hash
        so in case of error one doesnt need to remove item from hash table */

    if(p67_addr_dup(&laddr, local) != 0) return p67_err_eerrno;

    if((err = p67_hash_insert(P67_CT_CONN, remote, (p67_liitem_t**)&conn)) != 0) {
        p67_addr_free(&laddr);
        return err;
    }

    (conn)->addr_local = laddr;
    if(callback != NULL) (conn)->callback = callback;
    if(ssl != NULL) (conn)->ssl = ssl;

    if(ret != NULL)
        *ret = conn;

    return 0;
}

p67_err
p67_node_insert(
    const p67_addr_t * addr,
    const char * trusted_key,
    int strdup_key,
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

    if((err = p67_hash_insert(P67_CT_NODE, addr, (p67_liitem_t**)&node)) != 0) {
        return err;
    }

    if(trusted_key != NULL) node->trusted_pub_key = tkeycpy;

    if(ret != NULL)
        *ret = node;

    return 0;
}

p67_err
p67_hash_remove(
        int p67_ct, 
        p67_addr_t * addr, 
        p67_liitem_t ** out, 
        dispose_callback_t callback)
{
    if(addr == NULL || out == NULL) return p67_err_einval;

    p67_liitem_t * ptr, * prev, ** cc;
    unsigned long hash = p67_hash_fn((__u_char *)&addr->sock, addr->socklen);

    prev = NULL;
    ptr = NULL;

    if(p67_hash_get_table(p67_ct, &cc, NULL) != 0) return p67_err_einval;

    for(ptr = cc[hash]; ptr != NULL; ptr = (ptr)->next) {
        if(addr->socklen == ptr->key.socklen 
            && memcmp(&addr->sock, &ptr->key.sock, ptr->key.socklen) == 0) break;
        prev = ptr;
    }

    if(ptr == NULL) return p67_err_enconn;

    if(prev == NULL) {
        cc[hash] = NULL;
    } else {
        prev->next = ptr->next;
    }

    if(callback != NULL) {
        callback(ptr, 1);
        return 0;
    }

    *out = ptr;

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
    if(conn != NULL) p67_conn_remove(&conn->addr_remote);
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
    int cnix, success = 0, asnl;
    X509_NAME * x509_name;
    X509_NAME_ENTRY * ne;
    ASN1_STRING * castr;
    EVP_PKEY * pkey;
    p67_node_t * node;

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
        X509_STORE_CTX_set_error(ctx, X509_V_ERR_CERT_REJECTED);
        return 0;
    }

    if((x509 = X509_STORE_CTX_get_current_cert(ctx)) == NULL) {
        return 0;
    }

    if((pubk = p67_net_get_pem_str(x509, P67_PEM_PUBKEY)) == NULL) {
        return 0;
    }

    /* 
        if remote is first timer then allow them to connect ( will be queued by protocol later ) 
        but we can warn user about new peer
    */
    if(node == NULL) {
        DLOG("Unknown host connecting from %s:%s with public key:\n%s", 
            addr.hostname, addr.service, pubk);
        success = 1;
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
        success = 0;
        goto end;
    }

    if(X509_verify(x509, pkey) != 1) {
        DLOG("Invalid SSL certificate coming from host at %s:%s.\nInvalid signature.\n", 
            addr.hostname, addr.service);
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
    
    if((size_t)asnl != strlen(addr.hostname) 
            || memcmp(addr.hostname, ASN1_STRING_get0_data(castr), asnl) != 0) {
        DLOG(
            "Invalid SSL certificate coming from host at %s:%s. CN is set to %s\n", 
            addr.hostname, addr.service,
            ASN1_STRING_get0_data(castr));
        success = 0;
        return 0;
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
        success = 0;
        node->state |= P67_NODE_STATE_QUEUE;
        goto end;
    }

    success = 1;

end:
    if(pubk != NULL) free(pubk);
    // should those variables be freed?
    // future self answer = yeah
    if(pkey != NULL) EVP_PKEY_free(pkey);

	return success;
}