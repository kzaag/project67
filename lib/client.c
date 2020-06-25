#include <pthread.h>
#if !defined(__USE_XOPEN_EXTENDED)
#define __USE_XOPEN_EXTENDED 1
#endif
#include <string.h>

#include "client.h"
#include "err.h"
#include "conn.h"

#define HASHSIZE 337 

typedef unsigned long p67_hash_t;

#define P67_FH_FNV1_OFFSET (p67_hash_t)0xcbf29ce484222425
#define P67_FH_FNV1_PRIME (p67_hash_t)0x100000001b3

struct p67_conn_pool;

typedef struct p67_conn_pool p67_conn_pool_t;

struct p67_conn_pool {
    p67_conn_pool_t * next;
    __u_char        * key;
    size_t          keylen;
    p67_conn_t      conn;
} * conn_pool[HASHSIZE];

pthread_mutex_t __lock = PTHREAD_MUTEX_INITIALIZER;


/* begin private prototypes */

extern inline p67_hash_t
p67_conn_pool_fn(const __u_char * key, int len);

p67_conn_t *
p67_conn_pool_lookup(p67_addr_t * addr);

p67_err
p67_conn_pool_insert(p67_addr_t * addr, p67_conn_t ** ret);

p67_err
p67_conn_pool_remove(p67_addr_t * addr);

void
p67_conn_pool_free_1(p67_conn_pool_t * ptr);

/* end private prototypes */

inline p67_hash_t
p67_conn_pool_fn(const __u_char * key, int len)
{
    p67_hash_t hash = P67_FH_FNV1_OFFSET;
    while(len-->0) {
        hash ^= *(key++);
        hash *= P67_FH_FNV1_PRIME;
    }
    return (hash % HASHSIZE);
}

p67_conn_t *
p67_conn_pool_lookup(p67_addr_t * addr)
{
    if(addr == NULL) return NULL;
    p67_conn_pool_t * ret = NULL;
    __u_char * key = (__u_char *)&addr->sock;
    for(ret = conn_pool[p67_conn_pool_fn(key, addr->socklen)]; ret != NULL; ret = ret->next) {
        if(ret->keylen != addr->socklen)
            continue;
        if(memcmp(&addr->sock, &ret->key, addr->socklen) == 0) break;
    }
    if(ret != NULL)
        return &ret->conn;
    return NULL;
}

void
p67_conn_pool_free_1(p67_conn_pool_t * ptr)
{
    p67_conn_free_deps(&ptr->conn);
    free(ptr);
}

void
p67_conn_free_all(void)
{
    size_t i;
    p67_conn_pool_t * n, *nn;

    for(i = 0; i < HASHSIZE; i++) {
        n = NULL;
        if(conn_pool[i] == NULL) continue;
        n = conn_pool[i]->next;
        p67_conn_pool_free_1(conn_pool[i]);
        while(n != NULL) {
            nn = n->next;
            p67_conn_pool_free_1(n);
            n = nn;
        }
    }
}

p67_err
p67_conn_pool_insert(p67_addr_t * addr, p67_conn_t ** ret) 
{
    if(addr == NULL) return p67_err_einval;

    unsigned long hash = p67_conn_pool_fn((__u_char *)&addr->sock, addr->socklen);
    p67_conn_pool_t * r = conn_pool[hash], ** np = NULL;

    do {
        if(r == NULL) break;
        if(r->keylen == addr->socklen && memcmp(&addr->sock, r->key, r->keylen) == 0) 
            return p67_err_eaconn;
        if(r->next == NULL) break;
    } while ((r=r->next) != NULL);
    
    if(r == NULL) {
        np = &conn_pool[hash];
    } else {
        np = &r->next;
    }

    if((*np = calloc(sizeof(**np), 1)) == NULL) goto err;

    memcpy(&(*np)->conn.addr.sock, &addr->sock, sizeof(struct sockaddr));
    (*np)->conn.addr.socklen = addr->socklen;
    if(addr->hostname != NULL)
        if(((*np)->conn.addr.hostname = strdup(addr->hostname)) == NULL) goto err;
    if(addr->service != NULL)
        if(((*np)->conn.addr.service = strdup(addr->service)) == NULL) goto err;

    (*np)->next = NULL;
    (*np)->key = (__u_char *)&((*np)->conn.addr.sock);
    (*np)->keylen = (*np)->conn.addr.socklen;

    if(ret != NULL)
        *ret = &(*np)->conn;

    return 0;

err:
    if(np == NULL || *np == NULL)
        return p67_err_eerrno;

    if((*np)->conn.addr.hostname != NULL) free((*np)->conn.addr.hostname);
    if((*np)->conn.addr.service != NULL) free((*np)->conn.addr.service);
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

    p67_conn_pool_t * ptr, * prev;
    unsigned long hash = p67_conn_pool_fn((__u_char *)&addr->sock, addr->socklen);

    prev = NULL;
    ptr = NULL;

    for(ptr = conn_pool[hash]; ptr != NULL; ptr = (ptr)->next) {
        if(addr->socklen == ptr->keylen && memcmp(&addr->sock, ptr->key, ptr->keylen) == 0) break;
        prev = ptr;
    }

    if(ptr == NULL) return p67_err_enconn;

    if(prev == NULL) {
        conn_pool[hash] = NULL;
    } else {
        prev->next = ptr->next;
    }

    p67_conn_pool_free_1(ptr);

    return 0;
}

p67_err
p67_client_disconnect(p67_addr_t * addr)
{
    p67_err err;

    pthread_mutex_lock(&__lock);

    if((err = p67_conn_pool_remove(addr)) != 0) {
        pthread_mutex_unlock(&__lock);
        return err;
    }

    pthread_mutex_unlock(&__lock);

    return 0;
}

p67_err
p67_client_connect(p67_addr_t * addr, const char * trusted_chain_path)
{
    p67_err err;
    p67_conn_t * conn;

    pthread_mutex_lock(&__lock);

    if((err = p67_conn_pool_insert(addr, &conn)) != 0) {
        return err;
    }

    p67_conn_set_trusted_chain_path(conn, trusted_chain_path);

    if((err = p67_conn_connect(conn)) != 0) {
        goto end;
    }

end:
    if(err != 0) {
        p67_conn_pool_remove(addr);
    }

    pthread_mutex_unlock(&__lock);

    return err;
}

