#include "err.h"
#include "conn.h"
#include "hash.h"

#if !defined(__USE_XOPEN_EXTENDED)
#define __USE_XOPEN_EXTENDED 1
#endif
#include <string.h>

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

extern inline long
p67_hash_conn_fn(const char *, int);

inline long
p67_hash_conn_fn(const char * key, int len)
{
    long hash = P67_FH_FNV1_OFFSET;
    while(len-->0) {
        hash ^= *(key++);
        hash *= P67_FH_FNV1_PRIME;
    }
    return hash % HASHSIZE;
}

p67_conn_t *
p67_hash_conn_lookup(p67_conn_t * conn)
{
    p67_conn_store_t * ret = NULL;
    for(ret = ccache[p67_hash_conn_fn(conn->addr.sa_data, 14)]; ret != NULL; ret = ret->next)
        if(memcmp(conn->addr.sa_data, ret->conn.addr.sa_data, 14) == 0) return &ret->conn;
    return NULL;
}

p67_conn_t *
p67_hash_conn_insert(p67_conn_t * val) 
{
    long hash = p67_hash_conn_fn(val->addr.sa_data, 14);
    p67_conn_store_t * ret = ccache[hash], ** np = NULL;

    do {
        if(ret == NULL || ret->next == NULL) break;
    } while ((ret=ret->next) != NULL);
    
    if(ret == NULL) {
        np = &ccache[hash];
    } else {
        np = &ret->next;
    }

    if((*np = calloc(sizeof(**np), 1)) == NULL) return NULL;
    (*np)->next = NULL;
    memcpy((*np)->key, val->addr.sa_data, 14);
    (*np)->conn.addr = val->addr;
    (*np)->conn.addrl = val->addrl;
    (*np)->conn.callback = val->callback;
    (*np)->conn.callback_args = val->callback_args;
    if(((*np)->conn.host = strdup(val->host)) == NULL) goto err;
    if(((*np)->conn.service = strdup(val->service)) == NULL) goto err;
    (*np)->conn.ssl = val->ssl;
    (*np)->conn.__lock = val->__lock;

    return &(*np)->conn;

err:
    if(np == NULL || *np == NULL)
        return NULL;

    if((*np)->conn.host != NULL) free((*np)->conn.host);
    if((*np)->conn.service != NULL) free((*np)->conn.service);
    free(*np);
    *np = NULL;

    return NULL;
}
