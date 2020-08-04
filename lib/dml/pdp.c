#include "../net.h"
#include "../log.h"
#include "pdp.h"
#include "dml.h"

#include <string.h>

#define P67_PUDP_INODE_LEN 101
#define P67_PUDP_CHUNK_LEN 256

#define pudp_hashin(ix) ((ix) % P67_PUDP_INODE_LEN)

typedef struct p67_pdp_inode {
    /* index in the underlying hash table */
    size_t index; 
    /* id of this message. */
    unsigned int iid;
    unsigned int size; /* size of the pudp_data chunk */
    unsigned int ttl;  /* inode timeout ( in miliseconds ) */
    unsigned long long lt; /* time when inode was initialized */
    int * termsig; /* notify user about termination with error code (EVT) */
    
    void ** res;
    int * resl;

    p67_addr_t * addr;
    /* callback used to notify user about state changes and errors such as timeouts */
    /* p67_pdp_callback_t cb; */
    int istate; /* occupation of this inode */
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
    default:
        snprintf(buff, buffl, "Unknown EVT code: %d\n", evt);
        break;
    }
    return buff;
}

p67_err
p67_pdp_write_urg(
    p67_addr_t * addr, 
    const uint8_t * msg, 
    int msgl, 
    int ttl,
    int * evt_termsig,
    void ** res,
    int * resl)

{
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

        if((err = p67_mutex_set_state(
                &pudp_inodes[i].istate, 
                P67_PDP_ISTATE_FREE, 
                P67_PDP_ISTATE_PASS)) != 0)
            goto LOOPEND;

        if((err = p67_cmn_time_ms(&pudp_inodes[i].lt)) != 0) {
                p67_mutex_set_state(
                    &pudp_inodes[i].istate, 
                    P67_PDP_ISTATE_PASS, 
                    P67_PDP_ISTATE_FREE);
                return err;
        }
        pudp_inodes[i].addr = addr;
        pudp_inodes[i].size = msgl;

        pudp_inodes[i].res = res;
        pudp_inodes[i].resl = resl;

        pudp_inodes[i].index = i;
        pudp_inodes[i].iid = mid;
        if(ttl <= 0)
            pudp_inodes[i].ttl = P67_PDP_TTL_DEF;
        else
            pudp_inodes[i].ttl = ttl;
        memcpy(pudp_data[i], msg, msgl);

        if((err = p67_mutex_set_state(
                    &pudp_inodes[i].istate, 
                    P67_PDP_ISTATE_PASS, 
                    P67_PDP_ISTATE_ACTV)) != 0) {
            /* this really shouldnt happen */
            return p67_err_easync;
        }

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
    p67_err err;

    if(pudp.state != P67_THREAD_SM_STATE_STOP)
        return p67_err_eaconn;
    
    if((err = p67_mutex_set_state(
            &pudp.state, 
            P67_THREAD_SM_STATE_STOP, 
            P67_THREAD_SM_STATE_RUNNING)) != 0)
        return err;

    if((err = p67_cmn_thread_create(&pudp.thr, pdp_loop, &pudp)) != 0) {
        p67_mutex_set_state(
            &pudp.state, 
            P67_THREAD_SM_STATE_RUNNING, 
            P67_THREAD_SM_STATE_STOP);
    }

    return err;
}

p67_err
p67_pdp_urg_remove(
    uint32_t id, 
    unsigned char * msg, int msgl)
{
    int state;
    size_t hash, i;
    int handled = 0;

    hash = pudp_hashin(id);

    i = hash;

    while(1) {

        if(pudp_inodes[i].istate != P67_PDP_ISTATE_ACTV)
            goto LOOPEND;

        if(pudp_inodes[i].iid != id)
            goto LOOPEND;

        state = P67_PDP_ISTATE_ACTV;

        if(!p67_atomic_set_state(&pudp_inodes[i].istate, &state, P67_PDP_ISTATE_PASS)) {
            return p67_err_easync;
        }

        state = P67_PDP_ISTATE_PASS;

        if(pudp_inodes[i].res != NULL && pudp_inodes[i].resl != NULL) {
            if((*pudp_inodes[i].res = malloc(msgl)) == NULL)
                return p67_err_eerrno;
            memcpy(*pudp_inodes[i].res, msg, msgl);
            *pudp_inodes[i].resl = msgl;
        }

        if(pudp_inodes[i].termsig != NULL)
            p67_mutex_set_state(pudp_inodes[i].termsig, 0, P67_PDP_EVT_GOT_ACK);

        if(!p67_atomic_set_state(&pudp_inodes[i].istate, &state, P67_PDP_ISTATE_FREE)) {
            return p67_err_easync;
        }

        if(handled) 
            return 0;
        else 
            return p67_err_eagain;

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
    int i, state, wr;
    unsigned long long t;
    p67_thread_sm_t * _pudp = (p67_thread_sm_t *)args;

    while(1) {
        err = p67_mutex_wait_for_change(&pudp_wakeup, 0, P67_PDP_INTERV);
        if(err == p67_err_eerrno)
            goto end;
        
        pudp_wakeup = 0;

        for(i = 0; i < P67_PUDP_INODE_LEN; i++) {
            if(pudp_inodes[i].istate != P67_PDP_ISTATE_ACTV)
                continue;
            if((err = p67_cmn_time_ms(&t)) != 0)
                goto end;

            /* timeout */
            if((t - pudp_inodes[i].lt) > pudp_inodes[i].ttl) {

                state = pudp_inodes[i].istate;
                if(!p67_atomic_set_state(&pudp_inodes[i].istate, &state, P67_PDP_ISTATE_FREE))
                    continue;
                // if(pudp_inodes[i].cb != NULL)
                //     pudp_inodes[i].cb(pudp_inodes[i].pass, P67_PDP_EVT_TIMEOUT, NULL);
                if(pudp_inodes[i].termsig != NULL)
                    p67_mutex_set_state(
                        pudp_inodes[i].termsig, 
                        P67_PDP_EVT_NONE, 
                        P67_PDP_EVT_TIMEOUT);

            } else {

                wr = pudp_inodes[i].size;
                err = p67_net_write(pudp_inodes[i].addr, pudp_data[i], &wr);
                // if(err == 0 && pudp_inodes[i].size != (unsigned int)wr)
                //     err = p67_err_eagain;
                // if(err != 0) {
                //     if(pudp_inodes[i].cb != NULL)
                //         pudp_inodes[i].cb(pudp_inodes[i].pass, P67_PDP_EVT_ERROR, &err);
                // }

            }
        }
    }

end:
    if(err != 0)
        p67_err_print_err("error[s] occured in PDP loop: ", err);
    p67_mutex_set_state(&_pudp->state, P67_THREAD_SM_STATE_SIG_STOP, P67_THREAD_SM_STATE_STOP);
    p67_mutex_set_state(&_pudp->state, P67_THREAD_SM_STATE_RUNNING, P67_THREAD_SM_STATE_STOP);
    return NULL;
}


const p67_pdp_urg_hdr_t *
p67_pdp_generate_urg_for_msg(
    char * urg_payload, int urg_payload_l,
    char * dst_msg, int dst_msg_l,
    uint16_t urg_utp)
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
        const unsigned char * ackpayload, int ackpayloadl,
        char * dstmsg, int dstmsgl)
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
        const unsigned char * srcmsg, int srcmsgl,
        const unsigned char * ackpayload, int ackpayloadl,
        char * dstmsg, int dstmsgl)
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
    p67_conn_t * conn, 
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
        (char *)&ack, sizeof(ack));

    if(err != 0)
        return err;

    return p67_net_must_write_conn(conn, &ack, sizeof(ack));
}
