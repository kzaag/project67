#include "err.h"
#include "conn.h"
#include "hash.h"

#if !defined(__USE_XOPEN_EXTENDED)
#define __USE_XOPEN_EXTENDED 1
#endif
#include <string.h>
#include <pthread.h>

#define HASHSIZE 337 

#define P67_FH_FNV1_OFFSET (unsigned long)0xcbf29ce484222425
#define P67_FH_FNV1_PRIME (unsigned long)0x100000001b3

struct p67_conn_store;

typedef struct p67_conn_store p67_conn_store_t;

struct p67_conn_store {
    p67_conn_store_t * next;
    char key[14];
    p67_conn_t conn;
} * ccache[HASHSIZE];

extern inline unsigned long
p67_hash_conn_fn(const char *, int);

inline unsigned long
p67_hash_conn_fn(const char * key, int len)
{
    unsigned long hash = P67_FH_FNV1_OFFSET;
    while(len-->0) {
        hash ^= *(key++);
        hash *= P67_FH_FNV1_PRIME;
    }
    return (hash % HASHSIZE);
}

p67_conn_t *
p67_hash_conn_lookup(p67_conn_t * val)
{
    if(val == NULL) return NULL;
    p67_conn_store_t * ret = NULL;
    for(ret = ccache[p67_hash_conn_fn(val->haddr.addr.sa_data, 14)]; ret != NULL; ret = ret->next)
        if(memcmp(val->haddr.addr.sa_data, ret->conn.haddr.addr.sa_data, 14) == 0) break;
    if(ret != NULL)
        return &ret->conn;
    return NULL;
}

p67_err
p67_hash_conn_insert(p67_conn_t * val, p67_conn_t ** ret) 
{
    if(val == NULL) return p67_err_einval;

    unsigned long hash = p67_hash_conn_fn(val->haddr.addr.sa_data, 14);
    p67_conn_store_t * r = ccache[hash], ** np = NULL;

    do {
        if(r == NULL) break;
        if(memcmp(val->haddr.addr.sa_data, r->conn.haddr.addr.sa_data, 14) == 0) 
            return p67_err_eaconn;
        if(r->next == NULL) break;
    } while ((r=r->next) != NULL);
    
    if(r == NULL) {
        np = &ccache[hash];
    } else {
        np = &r->next;
    }

    if((*np = calloc(sizeof(**np), 1)) == NULL) goto err;
    (*np)->next = NULL;
    memcpy((*np)->key, val->haddr.addr.sa_data, 14);
    memcpy(&(*np)->conn.haddr.addr, &val->haddr.addr, sizeof(struct sockaddr));
    (*np)->conn.haddr.addrl = val->haddr.addrl;
    (*np)->conn.callback = val->callback;
    (*np)->conn.callback_args = val->callback_args;
    (*np)->conn.ssl = val->ssl;
    if(((*np)->conn.trusted_chain = strdup(val->trusted_chain)) == NULL) goto err;
    if(((*np)->conn.haddr.host = strdup(val->haddr.host)) == NULL) goto err;
    if(((*np)->conn.haddr.service = strdup(val->haddr.service)) == NULL) goto err;

    if(ret != NULL)
        *ret = &(*np)->conn;

    return 0;

err:
    if(np == NULL || *np == NULL)
        return p67_err_eerrno;

    if((*np)->conn.haddr.host != NULL) free((*np)->conn.haddr.host);
    if((*np)->conn.haddr.service != NULL) free((*np)->conn.haddr.service);
    free(*np);
    *np = NULL;

    return p67_err_eerrno;
}

p67_err
p67_hash_conn_remove(p67_conn_t * conn)
{
    if(conn == NULL) return p67_err_einval;

    // remove Y from X -> Y -> Z    =>    X -> Z
    // remove Y from Y -> X -> Z    =>    X -> Z

    p67_conn_store_t * ptr, * prev;
    unsigned long hash = p67_hash_conn_fn(conn->haddr.addr.sa_data, 14);

    prev = NULL;
    ptr = NULL;

    for(ptr = ccache[hash]; ptr != NULL; ptr = (ptr)->next) {
        if(memcmp(conn->haddr.addr.sa_data, (ptr)->conn.haddr.addr.sa_data, 14) == 0) break;
        prev = ptr;
    }

    if(ptr == NULL) return p67_err_enconn;

    if(prev == NULL) {
        ccache[hash] = NULL;
    } else {
        prev->next = ptr->next;
    }

    p67_conn_free_deps(&ptr->conn);
    free(ptr);

    return 0;
}
