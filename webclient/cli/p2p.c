#include <string.h>
#include <strings.h>

#include "p2p.h"

// p67_hashcntl_t * __p2p_cache = NULL;
// p67_async_t __p2p_cache_lock = P67_ASYNC_INTIIALIZER;

// void
// p67_p2p_free_conn_args(void * args)
// {
//     p67_log("disposing p2p ctx\n");
//     p67_err err;
//     p67_hashcntl_entry_t * e = (p67_hashcntl_entry_t *)args;
//     if((err = p67_hashcntl_remove_and_free(
//             p2p_cache, e->key, e->keyl)) != 0) {
//         p67_err_print_err("Coudlnt free p2p ctx, err was: ", err);
//     }
// }

// void
// p67_p2p_cache_entry_free(p67_hashcntl_entry_t * e)
// {
//     if(!e) return;
//     p67_p2p_ctx_t * p2p = (p67_p2p_ctx_t *)e->value;
//     p67_thread_sm_terminate(&p2p->conn_ctx.connect_tsm, 500);
//     p67_thread_sm_terminate(&p2p->conn_ctx.listen_tsm, 500);
//     p67_thread_sm_terminate(&p2p->keepalive_ctx.th, 500);
//     p67_addr_free(p2p->conn_ctx.local_addr);
//     p67_addr_free(p2p->conn_ctx.remote_addr);
//     free(p2p->conn_ctx.certpath);
//     free(p2p->conn_ctx.keypath);
//     free(e);
// }

// p67_hashcntl_t ** 
// p2p_cache_location(void)
// {
//     if(!__p2p_cache) {
//         p67_spinlock_lock(&__p2p_cache_lock);
//         if(!__p2p_cache) {
//             __p2p_cache = p67_hashcntl_new(
//                 0, p67_p2p_cache_entry_free, NULL);
//             p67_cmn_assert_abort(
//                 !__p2p_cache, "Couldnt initialize p2p cache\n");
//         }
//         p67_spinlock_unlock(&__p2p_cache_lock);
//     }
//     return &__p2p_cache;
// }

// p67_p2p_ctx_t *
// p67_p2p_lookup(p67_addr_t * addr)
// {
//     p67_hashcntl_entry_t * e = p67_hashcntl_lookup(
//         p2p_cache, (unsigned char *)&addr->sock, addr->socklen);
//     if(!e) return NULL;
//     return (p67_p2p_ctx_t *)e->value;
// }

// p67_p2p_ctx_t *
// p67_p2p_cache_add(p67_conn_ctx_t * ctx)
// {
//     p67_hashcntl_entry_t * e = malloc(
//         sizeof(p67_hashcntl_entry_t) +
//         ctx->remote_addr->socklen + 
//         sizeof(p67_p2p_ctx_t));

//     e->key = (char *)e + sizeof(p67_hashcntl_entry_t);
//     e->keyl = ctx->remote_addr->socklen;
//     e->next = NULL;
//     e->value = e->key + ctx->remote_addr->socklen;
//     e->valuel = sizeof(p67_p2p_ctx_t);

//     memcpy(e->key, &ctx->remote_addr->sock, e->keyl);

//     p67_p2p_ctx_t * p2pctx = (p67_p2p_ctx_t *)e->value;
    
//     bzero(&p2pctx->conn_ctx, sizeof(p67_p2p_ctx_t));

//     p2pctx->conn_ctx.local_addr = p67_addr_ref_cpy(ctx->local_addr);
//     p2pctx->conn_ctx.remote_addr = p67_addr_ref_cpy(ctx->remote_addr);
//     p2pctx->conn_ctx.certpath = malloc(strlen(ctx->certpath) + 1);
//     p2pctx->conn_ctx.keypath = p67_cmn_strdup(ctx->keypath);
//     p2pctx->conn_ctx.certpath = p67_cmn_strdup(ctx->certpath);
//     p2pctx->keepalive_ctx.addr = p2pctx->conn_ctx.remote_addr;
//     p2pctx->conn_ctx.cb = p67_dml_handle_msg;
//     p2pctx->conn_ctx.args = e;
//     p2pctx->conn_ctx.free_args = p67_p2p_free_conn_args;

//     if(!p2pctx->conn_ctx.keypath || 
//             !p2pctx->conn_ctx.certpath ||
//             !p2pctx->conn_ctx.local_addr || 
//             !p2pctx->conn_ctx.remote_addr) {
//         p67_p2p_cache_entry_free(e);
//         return NULL;
//     }

//     if(p67_hashcntl_add(p2p_cache, e) != 0) {
//         p67_p2p_cache_entry_free(e);
//         return NULL;
//     }

//     return p2pctx;
// }

// p67_err
// p67_p2p_start_connect(p67_p2p_ctx_t * ctx)
// {
//     p67_err err;

//     err = p67_conn_ctx_start_persist_connect(&ctx->conn_ctx);
//     if(err) return err;
//     err = p67_pdp_start_keepalive_loop(&ctx->keepalive_ctx);
//     if(err) {
//         p67_thread_sm_terminate(&ctx->conn_ctx.connect_tsm, 500);
//         return err;
//     }

//     return 0;
// }
