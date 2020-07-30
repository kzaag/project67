#if !defined(P67RS_RSERVER_H)
#define P67RS_RSERVER_H

#include <p67/tlv.h>
#include <p67/sfd.h>
#include <p67/net.h>

#include "db.h"
#include "err.h"

#define P67RS_DEFAULT_USERMAP_CAPACITY 1000

typedef struct p67rs_usermap_entry p67rs_usermap_entry_t;

struct p67rs_usermap_entry {
    char * username;
    p67_sockaddr_t saddr;
    p67rs_usermap_entry_t * next;
};

typedef struct p67rs_usermap {
    size_t                buffer_capacity;
    p67rs_usermap_entry_t ** buffer;
    p67_async_t           rwlock;
} p67rs_usermap_t;

typedef struct p67rs_server {
    p67rs_usermap_t  * usermap;
    p67rs_db_ctx_t   * db_ctx;
    p67_conn_pass_t  * conn;
} p67rs_server_t;

p67rs_err
p67rs_usermap_create(
    p67rs_usermap_t ** usermap,
    int usermap_capacity);

void
p67rs_usermap_free(p67rs_usermap_t * usermap);

p67rs_err
p67rs_usermap_add(
    p67rs_usermap_t * usermap,
    char * username, p67_sockaddr_t * saddr);

const p67rs_usermap_entry_t *
p67rs_usermap_lookup(
    p67rs_usermap_t * usermap,
    char * username);

p67_err
p67rs_usermap_remove(
    p67rs_usermap_t * usermap,
    char * username);

#endif