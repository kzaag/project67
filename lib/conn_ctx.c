#include "sfd.h"
#include "conn_ctx.h"

#include <assert.h>
#include <openssl/rand.h>

#define P67_MOD_SLEEP_MS 500
#define P67_MIN_SLEEP_MS 500

P67_CMN_NO_PROTO_ENTER
void *
__p67_conn_ctx_listen(
P67_CMN_NO_PROTO_EXIT
    void * args)
{
    assert(args);
    p67_conn_ctx_t * ctx = (p67_conn_ctx_t *)args;
    p67_err err;

    err = p67_conn_listen(
        ctx->local_addr,
        ctx->certpath,
        ctx->keypath,
        ctx->gen_args,
        ctx->args,
        ctx->free_args,
        ctx->cb,
        &ctx->listen_tsm.state,
        ctx->conn_timeout_ctx);

    if(err != 0) {
        p67_err_print_err("error/s occured in __p67_conn_ctx_listen: ", err);
    }

    return NULL;
}

p67_err
p67_conn_ctx_start_listen(p67_conn_ctx_t * ctx)
{
    if(!ctx)
        return p67_err_einval;

    return p67_thread_sm_start(
        &ctx->listen_tsm,
        __p67_conn_ctx_listen,
        ctx);
}

p67_err
p67_conn_ctx_connect(p67_conn_ctx_t * ctx)
{
    if(!ctx)
        return p67_err_einval;

    return p67_conn_connect(
        ctx->local_addr,
        ctx->remote_addr,
        ctx->certpath,
        ctx->keypath,
        ctx->gen_args,
        ctx->args,
        ctx->free_args,
        ctx->cb,
        ctx->conn_timeout_ctx);
}

p67_err
p67_conn_ctx_nat_connect(
    p67_conn_ctx_t * ctx, int p67_conn_cn_t)
{
    if(!ctx)
        return p67_err_einval;

    unsigned long interv;
    struct timespec sleepspec;
    int retries = 5;
    p67_err err;

    while(retries-->0 /*&& (pass->hconnect.state == P67_ASYNC_THREAD_STATE_RUNNING ) */ ) {

        if((err = p67_conn_ctx_connect(ctx)) == 0) {
            if(err == p67_err_eaconn) {
                p67_log_debug("\rNAT Connect:%d Connection exists.\n", p67_conn_cn_t);
                return err;
            }
            break;
        }

        // hiding net_cache_get error
        if((err = p67_conn_ctx_connect(ctx)) == 0) break;

        if(p67_conn_cn_t == P67_CONN_CNT_PASS)
            break;

        if(err == p67_err_eaconn) {
            p67_log_debug("\rNAT Connect:%d Connection exists.\n", p67_conn_cn_t);
            return err;
        }

        if(p67_conn_cn_t == P67_CONN_CNT_ACT) {
            err = p67_conn_ctx_connect(ctx);
            break;
        }

        if(p67_conn_cn_t == P67_CONN_CNT_PERSIST) {

            if(1 != RAND_bytes((unsigned char *)&interv, sizeof(interv))) {
                p67_err_mask_all(err);
                break;
            }
            interv = (interv % 3000) + 1000;
            p67_log_debug("NAT Connect:%d Sleeping for %lu\n", p67_conn_cn_t, interv);
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
       // p67_log_debug("NAT Connect:%d Succeeded.\n", p67_conn_cn_t);
    } else {
        //p67_log_debug("NAT Connect:%d Failed.\n", p67_conn_cn_t);
    }

   /* p67_async_set_state(&pass->hconnect, 
            P67_ASYNC_THREAD_STATE_SIG_STOP, P67_ASYNC_STATE_STOP);*/

    return err;
}

P67_CMN_NO_PROTO_ENTER
void *
__p67_conn_ctx_persist_connect(
P67_CMN_NO_PROTO_EXIT
    void * arg)
{
    p67_conn_ctx_t * ctx = (p67_conn_ctx_t *)arg;
    unsigned long interval = 0;
    p67_err err;

    p67_log_debug(
        "Background connecting to: %s:%s\n",
        ctx->remote_addr->hostname,
        ctx->remote_addr->service);

    while(1) {
        if(ctx->connect_tsm.state != P67_THREAD_SM_STATE_RUNNING) {
            err = 0; //err |= p67_err_eint;
            break;
        }

        // p67_log_debug("Background connect iteration for %s:%s. Slept %lu ms\n", 
        //     pass->remote.hostname, pass->remote.service, interval);

        if((err = p67_conn_ctx_nat_connect(ctx, P67_CONN_CNT_PASS)) != 0) {
                // p67_err_print_err("Background connect ", err);
        } else {
            p67_log_debug(
                "Background connected to %s:%s\n", 
                ctx->remote_addr->hostname, 
                ctx->remote_addr->service);
        }

        if(ctx->connect_tsm.state != P67_THREAD_SM_STATE_RUNNING) {
            err = 0; //err |= p67_err_eint;
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
    err |= p67_mutex_set_state(
        &ctx->connect_tsm.state, 
        ctx->connect_tsm.state, 
        P67_THREAD_SM_STATE_STOP);
    return NULL;
}

p67_err
p67_conn_ctx_start_persist_connect(p67_conn_ctx_t * ctx)
{
    if(!ctx)
        return p67_err_einval;

    return p67_thread_sm_start(
        &ctx->connect_tsm,
        __p67_conn_ctx_persist_connect,
        ctx);
}

p67_err
p67_net_async_terminate(p67_conn_ctx_t * ctx)
{
    if(!ctx)
        return p67_err_einval;

    p67_err err = 0;

    err |= p67_thread_sm_terminate(
            &ctx->connect_tsm, P67_THREAD_SM_TIMEOUT_DEF);
    err |= p67_thread_sm_terminate(
            &ctx->listen_tsm, P67_THREAD_SM_TIMEOUT_DEF);

    return err;
}

/*
    tries to connect to the peer and returns 0 when finished.
*/
// p67_err
// p67_net_seq_connect_listen(p67_conn_ctx_t * ctx)
// {
//     p67_err err;
//     unsigned int interval;

//     while(1) {
//         if((err = p67_net_start_listen(pass)) != 0)
//             return err;

//         if(1 != RAND_bytes((unsigned char *)&interval, sizeof(interval)))
//             return p67_err_essl;
//         interval = (interval % P67_MOD_SLEEP_MS) + P67_MIN_SLEEP_MS;
//         if((err = p67_cmn_sleep_ms(interval)) != 0)
//             return err;

//         if((err = p67_thread_sm_terminate(&pass->hlisten, -1)) != 0)
//             return err;
//         if(p67_conn_lookup(&pass->remote) != NULL)
//             return 0;
        
//         if((err = p67_net_start_persist_connect(pass)) != 0)
//             return err;
            
//         if(1 != RAND_bytes((unsigned char *)&interval, sizeof(interval)))
//             return p67_err_essl;
//         interval = (interval % P67_MOD_SLEEP_MS) + P67_MIN_SLEEP_MS;
//         if((err = p67_cmn_sleep_ms(interval)) != 0)
//             return err;

//         if((err = p67_thread_sm_terminate(&pass->hconnect, -1)) != 0)
//             return err;
//         if(p67_conn_lookup(&pass->remote) != NULL)
//             return 0;
//     }

//     return 0;
// }
