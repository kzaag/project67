
#include "../log.h"

#include "pdp.h"
#include "dml.h"
#include "../conn.h"

#include <string.h>
#include <assert.h>

#define P67_PUDP_INODE_LEN 101
#define P67_PUDP_CHUNK_LEN P67_DML_SAFE_PAYLOAD_SIZE

#define pudp_hashin(ix) ((ix) % P67_PUDP_INODE_LEN)

#define p67_pdp_set_state(inode, p, n) \
    p67_atomic_set_state(&(inode).istate, PARG(p), n)

#define p67_pdp_must_set_state(inode, p, n) \
    p67_atomic_must_set_state(&(inode).istate, p, n)

typedef struct p67_pdp_inode {
    /* index in the underlying hash table */
    size_t index; 
    p67_cmn_epoch_t lt; /* time when inode was initialized */
    int * termsig; /* notify user about termination with error code (EVT) */

    p67_pckt_t * res;
    int * resl;

    p67_addr_t * addr;

    /* callback used to notify user about state changes and errors such as timeouts */
    /* p67_pdp_callback_t cb; */

    int istate; /* occupation of this inode */
    unsigned int size; /* size of the pudp_data chunk */
    unsigned int ttl;  /* inode timeout ( in miliseconds ) */

    /* id of this message. */
    uint16_t iid;
    uint16_t 
        preacked: 1;
} p67_pdp_inode_t;

static uint8_t pudp_data[P67_PUDP_INODE_LEN][P67_PUDP_CHUNK_LEN];
static p67_pdp_inode_t pudp_inodes[P67_PUDP_INODE_LEN];

static int pudp_wakeup = 0; 

/* main async loop handler */
static p67_thread_sm_t pudp = P67_THREAD_SM_INITIALIZER;

static __thread uint16_t __mid = 0;

/****BEGIN PRIVATE PROTOTYPES****/

static void *
pdp_loop(void * args);

void *
__p67_pdp_run_keepalive_loop(void * args);

p67_err
p67_pdp_run_keepalive_loop(p67_pdp_keepalive_ctx_t * ctx);

/****END PRIVATE PROTOTYPES****/

uint16_t *
p67_pdp_mid_location(void)
{
    __mid++;
    return &__mid;
}

char *
p67_pdp_evt_str(char * buff, int buffl, int evt)
{
    if(buff == NULL)
        return NULL;
    switch(evt) {
    case P67_PDP_EVT_GOT_ACK:
        snprintf(buff, buffl, "Received ACK");
        break;
    case P67_PDP_EVT_TIMEOUT:
        snprintf(buff, buffl, "Timeout");
        break;
    case P67_PDP_EVT_ERROR:
        snprintf(buff, buffl, "Error occurred");
        break;
    case P67_PDP_EVT_ENOMEM:
        snprintf(buff, buffl, "Buffer is too small");
        break;
    default:
        snprintf(buff, buffl, "Unknown EVT code: %d\n", evt);
        break;
    }
    return buff;
}

p67_err
p67_pdp_write_urg(
    p67_addr_t * addr, 
    const p67_pckt_t * msg, 
    int msgl, 
    int ttl,
    int * evt_termsig,
    void * res,
    int * resl)
{
    if(!addr) return p67_err_einval;

    p67_err err;
    size_t hash, i;
    const p67_pdp_urg_hdr_t * hdr;

    if(msgl > P67_PUDP_CHUNK_LEN) return p67_err_einval;

    if((hdr = (p67_pdp_urg_hdr_t *)p67_dml_parse_hdr(msg, msgl, NULL)) == NULL)
        return p67_err_epdpf;

    if(hdr->urg_stp != P67_DML_STP_PDP_URG)
        return p67_err_einval;

    uint16_t mid = p67_cmn_ntohs(hdr->urg_mid);

    if(pudp.state == P67_THREAD_SM_STATE_STOP)
        if((err = p67_pdp_start_loop()) != 0 && err != p67_err_eaconn)
            return err;

    hash = pudp_hashin(mid);

    i = hash;

    while(1) {

        if(pudp_inodes[i].istate != P67_PDP_ISTATE_FREE)
            goto LOOPEND;

        if(!p67_pdp_set_state(
                pudp_inodes[i], P67_PDP_ISTATE_FREE, P67_PDP_ISTATE_PASS))
            goto LOOPEND;

        if((err = p67_cmn_epoch_ms(&pudp_inodes[i].lt)) != 0) {
            p67_pdp_must_set_state(
                pudp_inodes[i], P67_PDP_ISTATE_PASS, P67_PDP_ISTATE_FREE)
            return err;
        }

        pudp_inodes[i].addr = p67_addr_ref_cpy(addr);
        assert(pudp_inodes[i].addr);
        pudp_inodes[i].size = msgl;

        pudp_inodes[i].res = res;
        pudp_inodes[i].resl = resl;

        pudp_inodes[i].index = i;
        pudp_inodes[i].iid = mid;
        pudp_inodes[i].preacked = 0;
        if(ttl <= 0)
            pudp_inodes[i].ttl = P67_PDP_TTL_DEF;
        else
            pudp_inodes[i].ttl = ttl;
        memcpy(pudp_data[i], msg, msgl);

        p67_pdp_must_set_state(
            pudp_inodes[i], P67_PDP_ISTATE_PASS, P67_PDP_ISTATE_ACTV);

        if(evt_termsig != NULL)
            pudp_inodes[i].termsig = evt_termsig;

        p67_mutex_set_state(&pudp_wakeup, 0, 1);

        return 0;

        // err = p67_net_write_connect(pass, msg, &wrote);
        // if(err != 0)
        //     return err;
        // if(wrote != msgl)
        //     return p67_err_eagain;

LOOPEND:
        
        i=(i+1)%P67_PUDP_INODE_LEN;
        if(i == hash)
            return p67_err_enomem;
    }
}

p67_err
p67_pdp_start_loop(void)
{
    return p67_thread_sm_start(&pudp, pdp_loop, &pudp);
}

p67_err
p67_pdp_urg_remove(
    uint16_t id, 
    p67_pckt_t * msg, int msgl,
    int preack)
{
    assert(msg);
    size_t hash, i;
    int dst_state;

    hash = pudp_hashin(id);

    i = hash;

    while(1) {

        if(pudp_inodes[i].istate != P67_PDP_ISTATE_ACTV)
            goto LOOPEND;

        if(pudp_inodes[i].iid != id)
            goto LOOPEND;

        if(!p67_pdp_set_state(
                pudp_inodes[i], P67_PDP_ISTATE_ACTV, P67_PDP_ISTATE_PASS))
            goto LOOPEND;

        if(pudp_inodes[i].iid != id)
            goto LOOPEND;

        if(preack) {
            pudp_inodes[i].preacked = 1;

            p67_pdp_must_set_state(
                    pudp_inodes[i], P67_PDP_ISTATE_PASS, P67_PDP_ISTATE_ACTV);
                
            return 0;
        }

        dst_state = P67_PDP_EVT_GOT_ACK;

        if(pudp_inodes[i].res != NULL && pudp_inodes[i].resl != NULL) {

            if(msgl > *pudp_inodes[i].resl) {
                dst_state = P67_PDP_EVT_ENOMEM;
            } else {
                memcpy(pudp_inodes[i].res, msg, *pudp_inodes[i].resl);
                *pudp_inodes[i].resl = msgl;
            }

        }

        if(pudp_inodes[i].termsig != NULL)
            p67_mutex_set_state(
                pudp_inodes[i].termsig, 
                P67_PDP_EVT_NONE, dst_state);

        p67_addr_free(pudp_inodes[i].addr);

        p67_pdp_must_set_state(
            pudp_inodes[i], P67_PDP_ISTATE_PASS, P67_PDP_ISTATE_FREE);

        return 0;

LOOPEND:
        
        i=(i+1)%P67_PUDP_INODE_LEN;
        if(i == hash) return p67_err_enconn;
    }
}

void *
pdp_loop(void * args)
{
    p67_err err;
    int i;
    unsigned long long t;
    (void)args;

    while(1) {
        err = p67_mutex_wait_for_change(&pudp_wakeup, 0, P67_PDP_INTERV);
        if(err == p67_err_eerrno)
            goto end;

        if(pudp.state != P67_THREAD_SM_STATE_RUNNING)
            goto end;
        
        pudp_wakeup = 0;

        for(i = 0; i < P67_PUDP_INODE_LEN; i++) {

            if(pudp_inodes[i].istate != P67_PDP_ISTATE_ACTV)
                continue;

            if(!p67_pdp_set_state(
                pudp_inodes[i], P67_PDP_ISTATE_ACTV, P67_PDP_ISTATE_PASS))
            continue;

            if((err = p67_cmn_epoch_ms(&t)) != 0)
                goto end;

            /* timeout */
            if((t - pudp_inodes[i].lt) > pudp_inodes[i].ttl) {

                // if(pudp_inodes[i].cb != NULL)
                //     pudp_inodes[i].cb(pudp_inodes[i].pass, P67_PDP_EVT_TIMEOUT, NULL);
                if(pudp_inodes[i].termsig != NULL)
                    p67_mutex_set_state(
                        pudp_inodes[i].termsig, 
                        P67_PDP_EVT_NONE, 
                        P67_PDP_EVT_TIMEOUT);

                p67_addr_free(pudp_inodes[i].addr);

                p67_pdp_must_set_state(
                    pudp_inodes[i], P67_PDP_ISTATE_PASS, P67_PDP_ISTATE_FREE);

                continue;

            } else if(!pudp_inodes[i].preacked) {

                // if(pudp_inodes[i]._no > 1) {
                //     printf("retransmission\n");
                // }

                err = p67_conn_write_once(
                        pudp_inodes[i].addr, 
                        pudp_data[i], 
                        pudp_inodes[i].size);
                // if(err == 0 && pudp_inodes[i].size != (unsigned int)wr)
                //     err = p67_err_eagain;
                // if(err != 0) {
                //     if(pudp_inodes[i].cb != NULL)
                //         pudp_inodes[i].cb(pudp_inodes[i].pass, P67_PDP_EVT_ERROR, &err);
                // }

            }

            p67_pdp_must_set_state(
                pudp_inodes[i], P67_PDP_ISTATE_PASS, P67_PDP_ISTATE_ACTV);
        }
    }

end:
    if(err != 0)
        p67_err_print_err("error/s occured in PDP loop: ", err);
    pudp.state = P67_THREAD_SM_STATE_STOP;
    return NULL;
}


const p67_pdp_urg_hdr_t *
p67_pdp_generate_urg_for_msg(
    p67_pckt_t * urg_payload, int urg_payload_l,
    p67_pckt_t * dst_msg, int dst_msg_l,
    uint8_t urg_utp)
{
    p67_pdp_urg_hdr_t * urghdr;

    if((size_t)dst_msg_l < (sizeof(*urghdr) + urg_payload_l)) return NULL;

    urghdr = (p67_pdp_urg_hdr_t *)dst_msg;

    urghdr->urg_mid = p67_cmn_htons(p67_pdp_mid);
    urghdr->urg_stp = P67_DML_STP_PDP_URG;
    urghdr->urg_utp = urg_utp;
    if(dst_msg_l > 0) {
        if(dst_msg == NULL) return NULL;
        memcpy(dst_msg+sizeof(*urghdr), urg_payload, urg_payload_l);
    }
    return urghdr;
}

p67_err
p67_pdp_generate_ack_from_hdr(
        const p67_pdp_urg_hdr_t * srchdr,
        const p67_pckt_t * ackpayload, int ackpayloadl,
        p67_pckt_t * dstmsg, int dstmsgl)
{
    p67_pdp_ack_hdr_t * dsthdr = (p67_pdp_ack_hdr_t *)dstmsg;

    if((long unsigned)dstmsgl < sizeof(*dsthdr)) return p67_err_epdpf;

    dsthdr->ack_utp = srchdr->urg_utp;
    dsthdr->ack_mid = srchdr->urg_mid;
    dsthdr->ack_stp = P67_DML_STP_PDP_ACK; 

    if(ackpayloadl > 0) {
        if(ackpayload == NULL) return p67_err_einval;
        memcpy(
            dstmsg+sizeof(*dsthdr), 
            ackpayload, ackpayloadl);
    }

    return 0;
}

p67_err
p67_pdp_generate_ack(
        const p67_pckt_t * srcmsg, int srcmsgl,
        const p67_pckt_t * ackpayload, int ackpayloadl,
        p67_pckt_t * dstmsg, int dstmsgl)
{
    const p67_pdp_urg_hdr_t * srchdr = (const p67_pdp_urg_hdr_t *)srcmsg;
    
    if((long unsigned)srcmsgl < sizeof(*srchdr)) return p67_err_epdpf;

    if(srchdr->urg_stp != P67_DML_STP_PDP_URG)
        return p67_err_epdpf;
    
    return p67_pdp_generate_ack_from_hdr(
        srchdr, 
        ackpayload, ackpayloadl,
        dstmsg, dstmsgl);
}

p67_err
p67_pdp_write_ack_for_urg(
    p67_addr_t * addr, 
    const p67_pdp_urg_hdr_t * urg_hdr)
{
    p67_pdp_ack_hdr_t ack;
    p67_err err;

    ack.ack_mid = urg_hdr->urg_mid;
    ack.ack_stp = P67_DML_STP_PDP_ACK;
    ack.ack_utp = urg_hdr->urg_utp;

    err = p67_pdp_generate_ack_from_hdr(
        urg_hdr,
        NULL, 0,
        (p67_pckt_t *)&ack, sizeof(ack));

    if(err != 0)
        return err;

    return p67_conn_write_once(addr, (p67_pckt_t *)&ack, sizeof(ack));
}

p67_err
p67_pdp_run_keepalive_loop(p67_pdp_keepalive_ctx_t * ctx)
{
    p67_err err;
    p67_pdp_urg_hdr_t urg;
    urg.urg_stp = P67_DML_STP_PDP_URG;
    urg.urg_utp = 0;
    p67_async_t evt = P67_ASYNC_INTIIALIZER;
        
    while(1) {
        if(ctx->th.state != P67_THREAD_SM_STATE_RUNNING) {
            break;
        }
        
        //p67_log("ping %s:%s\n", ctx->addr->hostname, ctx->addr->service);

        urg.urg_mid = p67_pdp_mid;    
        err = p67_pdp_write_urg(
                ctx->addr, 
                (uint8_t *)&urg, 
                sizeof(urg), 
                1000, 
                &evt, 
                NULL, NULL);
        if(err != 0) {
            p67_err_print_err("Error/s in keepalive loop: ", err);
            //return err;
        }
        
        err = p67_mutex_wait_for_change(
            &ctx->th.state, P67_THREAD_SM_STATE_RUNNING, 5000);
        if(ctx->th.state != P67_THREAD_SM_STATE_RUNNING)
            break;
        if(err == p67_err_eerrno)
            break;
    }

    ctx->th.state = P67_THREAD_SM_STATE_STOP;
    return 0;
}

void *
__p67_pdp_run_keepalive_loop(void * args)
{
    p67_pdp_keepalive_ctx_t * ctx = (p67_pdp_keepalive_ctx_t *)args;
    if(!ctx) return NULL;
    
    p67_err err;

    if((err = p67_pdp_run_keepalive_loop(ctx)) != 0) {
        p67_err_print_err("run keepalive loop: ", err);
    }
    
    return NULL;
}

p67_err
p67_pdp_start_keepalive_loop(p67_pdp_keepalive_ctx_t * ctx)
{
    return p67_thread_sm_start(
        &ctx->th, __p67_pdp_run_keepalive_loop, ctx);
}
