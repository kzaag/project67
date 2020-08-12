#if !defined(P67RS_RSERVER_H)
#define P67RS_RSERVER_H

#include <p67/tlv.h>
#include <p67/sfd.h>
#include <p67/hashcntl.h>
#include <p67/conn_ctx.h>

#include "db.h"
#include "err.h"

#define P67RS_DEFAULT_USERMAP_CAPACITY 1000

typedef struct p67rs_usermap_entry p67rs_usermap_entry_t;

typedef p67_hashcntl_t p67rs_usermap_t;

struct p67rs_usermap_entry {
    char * username;
    size_t usernamel;
    p67_sockaddr_t * saddr;
    char __padd[sizeof(size_t)+sizeof(p67_hashcntl_entry_t *)];
};

p67_cmn_static_assert(
    sizeof(p67rs_usermap_entry_t) == sizeof(p67_hashcntl_entry_t));

typedef struct p67rs_server {
    p67rs_usermap_t * usermap;
    p67rs_db_ctx_t * db_ctx;
} p67rs_server_t;

void
p67rs_(p67_conn_ctx_t * ctx, p67rs_server_t * server);

p67rs_err
p67rs_usermap_create(
    p67rs_usermap_t ** usermap,
    size_t usermap_capacity);

#endif