#include "net.h"
#include "pudp.h"
#include "log.h"

#include <string.h>

#define P67_PUDP_INODE_LEN 101
#define P67_PUDP_CHUNK_LEN 512

#define P67_PUDP_INTERV 2000
#define P67_PUDP_TTL_DEF 5000

#define pudp_hashin(ix) ((ix) % P67_PUDP_INODE_LEN)

typedef struct p67_pudp_inode {
    size_t index; /* index in the underlying hash table */
    unsigned int iid; /* id of this message */
    unsigned int size; /* size of the pudp_data chunk */
    unsigned int ttl;  /* inode timeout ( in miliseconds ) */
    unsigned long long lt; /* time when inode was initialized */
    int * termsig; /* notify user about termination with error code (EVT) */ 
    p67_conn_pass_t * pass;
    /* callback used to notify user about state changes and errors such as timeouts */
    p67_pudp_callback_t cb;
    int istate; /* occupation of this inode */
} p67_pudp_inode_t;

static uint8_t pudp_data[P67_PUDP_INODE_LEN][P67_PUDP_CHUNK_LEN];
static p67_pudp_inode_t pudp_inodes[P67_PUDP_INODE_LEN];

static int pudp_wakeup = 0; 

/* main async loop handler */
static p67_thread_sm_t pudp = P67_THREAD_SM_INITIALIZER;

static __thread uint32_t __mid = 0;

/****BEGIN PRIVATE PROTOTYPES****/

p67_err
p67_pudp_remove(const uint8_t * msg, int msgl);

static void *
pudp_loop(void * args);

p67_err
proto_handle_msg(p67_conn_t * conn, const char * msg, int msgl, void * args);

/****END PRIVATE PROTOTYPES****/

uint32_t *
p67_pudp_mid_location(void)
{
    __mid++;
    return &__mid;
}

#define P67_PUDP_EVT_GOT_ACK 1
#define P67_PUDP_EVT_TIMEOUT 2
#define P67_PUDP_EVT_ERROR   3

char *
p67_pudp_evt_str(char * buff, int buffl, int evt)
{
    if(buff == NULL)
        return NULL;
    switch(evt) {
    case P67_PUDP_EVT_GOT_ACK:
        snprintf(buff, buffl, "Received ACK");
        break;
    case P67_PUDP_EVT_TIMEOUT:
        snprintf(buff, buffl, "Timeout");
        break;
    case P67_PUDP_EVT_ERROR:
        snprintf(buff, buffl, "Error occurred");
        break;
    default:
        snprintf(buff, buffl, "Unknown EVT code: %d\n", evt);
        break;
    }
    return buff;
}


void * p67_pudp_loop(void * args);

#define pudp_msg_to_id(msg, idval) \
    { (idval) = ((msg)[1] >> 24) + ((msg)[2] >> 16) + ((msg)[3] >> 8) + (msg)[4]; }

p67_err
p67_pudp_write_urg(
    p67_conn_pass_t * pass, 
    const uint8_t * msg, 
    int msgl, 
    int ttl,
    int * evt_termsig,
    p67_pudp_callback_t cb)
{
    p67_err err;
    uint32_t id;
    size_t hash, i;

    if(!(msg[0] & P67_PUDP_HDR_URG))
        return p67_err_einval;

    if(pudp.state == P67_THREAD_SM_STATE_STOP)
        if((err = p67_pudp_start_loop()) != 0 && err != p67_err_eaconn)
            return err;

    if(msgl > P67_PUDP_CHUNK_LEN) return p67_err_einval;

    pudp_msg_to_id(msg, id);
    hash = pudp_hashin(id);

    i = hash;

    while(1) {
        if(pudp_inodes[i].istate != P67_PUDP_ISTATE_FREE)
            goto LOOPEND;

        if((err = p67_mutex_set_state(
                &pudp_inodes[i].istate, 
                P67_PUDP_ISTATE_FREE, 
                P67_PUDP_ISTATE_PASS)) != 0)
            goto LOOPEND;

        if((err = p67_cmn_time_ms(&pudp_inodes[i].lt)) != 0) {
                p67_mutex_set_state(
                    &pudp_inodes[i].istate, 
                    P67_PUDP_ISTATE_PASS, 
                    P67_PUDP_ISTATE_FREE);
                return err;
        }
        pudp_inodes[i].pass = pass;
        pudp_inodes[i].size = msgl;
        pudp_inodes[i].cb = cb;
        pudp_inodes[i].index = i;
        pudp_inodes[i].iid = id;
        if(ttl <= 0)
            pudp_inodes[i].ttl = P67_PUDP_TTL_DEF;
        else
            pudp_inodes[i].ttl = ttl;
        memcpy(pudp_data[i], msg, msgl);

        if((err = p67_mutex_set_state(
                    &pudp_inodes[i].istate, 
                    P67_PUDP_ISTATE_PASS, 
                    P67_PUDP_ISTATE_ACTV)) != 0) {
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
p67_pudp_start_loop(void)
{
    p67_err err;

    if(pudp.state != P67_THREAD_SM_STATE_STOP)
        return p67_err_eaconn;
    
    if((err = p67_mutex_set_state(
            &pudp.state, 
            P67_THREAD_SM_STATE_STOP, 
            P67_THREAD_SM_STATE_RUNNING)) != 0)
        return err;

    if((err = p67_cmn_thread_create(&pudp.thr, pudp_loop, &pudp)) != 0) {
        p67_mutex_set_state(
            &pudp.state, 
            P67_THREAD_SM_STATE_RUNNING, 
            P67_THREAD_SM_STATE_STOP);
    }

    return err;
}

p67_err
p67_pudp_remove(const unsigned char * msg, int msgl)
{
    uint32_t id;
    int state;
    size_t hash, i;

    if(msgl < 5)
        return p67_err_einval;

    if(!(msg[0] & P67_PUDP_HDR_ACK))
        return p67_err_einval;

    pudp_msg_to_id(msg, id);

    hash = pudp_hashin(id);

    i = hash;

    while(1) {

        if(pudp_inodes[i].istate != P67_PUDP_ISTATE_ACTV)
            goto LOOPEND;

        if(pudp_inodes[i].iid != id)
            goto LOOPEND;

        state = P67_PUDP_ISTATE_ACTV;

        if(!p67_atomic_set_state(&pudp_inodes[i].istate, &state, P67_PUDP_ISTATE_PASS)) {
            return p67_err_easync;
        }

        state = P67_PUDP_ISTATE_PASS;

        if(pudp_inodes[i].cb != NULL)
            pudp_inodes[i].cb(pudp_inodes[i].pass, P67_PUDP_EVT_GOT_ACK, NULL);

        if(pudp_inodes[i].termsig != NULL)
            p67_mutex_set_state(pudp_inodes[i].termsig, 0, P67_PUDP_EVT_GOT_ACK);

        if(!p67_atomic_set_state(&pudp_inodes[i].istate, &state, P67_PUDP_ISTATE_FREE)) {
            return p67_err_easync;
        }

        return 0;

LOOPEND:
        
        i=(i+1)%P67_PUDP_INODE_LEN;
        if(i == hash) return p67_err_enconn;
    }
}

void *
pudp_loop(void * args)
{
    p67_err err;
    int i, state, wr;
    unsigned long long t;
    p67_thread_sm_t * _pudp = (p67_thread_sm_t *)args;

    while(1) {
        err = p67_mutex_wait_for_change(
            &pudp_wakeup, 0, P67_PUDP_INTERV);
        if(err == p67_err_eerrno)
            goto end;
        
        pudp_wakeup = 0;

        for(i = 0; i < P67_PUDP_INODE_LEN; i++) {
            if(pudp_inodes[i].istate != P67_PUDP_ISTATE_ACTV)
                continue;
            if((err = p67_cmn_time_ms(&t)) != 0)
                goto end;

            /* timeout */
            if((t - pudp_inodes[i].lt) > pudp_inodes[i].ttl) {

                state = pudp_inodes[i].istate;
                if(!p67_atomic_set_state(&pudp_inodes[i].istate, &state, P67_PUDP_ISTATE_FREE))
                    continue;
                if(pudp_inodes[i].cb != NULL)
                    pudp_inodes[i].cb(pudp_inodes[i].pass, P67_PUDP_EVT_TIMEOUT, NULL);
                if(pudp_inodes[i].termsig != NULL)
                    p67_mutex_set_state(
                        pudp_inodes[i].termsig, 
                        P67_PUDP_EVT_NONE, 
                        P67_PUDP_EVT_TIMEOUT);

            } else {

                wr = pudp_inodes[i].size;
                err = p67_net_write(&pudp_inodes[i].pass->remote, pudp_data[i], &wr);
                if(err == 0 && pudp_inodes[i].size != (unsigned int)wr)
                    err = p67_err_eagain;
                if(err != 0) {
                    if(pudp_inodes[i].cb != NULL)
                        pudp_inodes[i].cb(pudp_inodes[i].pass, P67_PUDP_EVT_ERROR, &err);
                }

            }
        }
    }

end:
    if(err != 0)
        p67_err_print_err("pUdp loop: ", err);
    p67_mutex_set_state(&_pudp->state, P67_THREAD_SM_STATE_SIG_STOP, P67_THREAD_SM_STATE_STOP);
    p67_mutex_set_state(&_pudp->state, P67_THREAD_SM_STATE_RUNNING, P67_THREAD_SM_STATE_STOP);
    return NULL;
}

char *
p67_pudp_urg(char * msg)
{
    uint32_t mid = ntohl(p67_pudp_mid);
    msg[0] = P67_PUDP_HDR_URG;
    memcpy(msg + 1, (char *)&mid, 4);
    return msg+5;
}

p67_err
p67_pudp_generate_ack(
        const unsigned char * srcmsg, int srcmsgl, 
        const unsigned char * ackmsg, int ackmsgl,
        char * dstmsg)
{
    if(srcmsgl < 5 || srcmsg[0] != P67_PUDP_HDR_URG)
        return p67_err_eagain;
    
    const p67_pudp_hdr_t * srchdr = (const p67_pudp_hdr_t *)srcmsg;
    p67_pudp_hdr_t * dsthdr = (p67_pudp_hdr_t *)dstmsg;
    dsthdr->type = P67_PUDP_HDR_ACK;
    dsthdr->mid = srchdr->mid;

    if(ackmsgl > 0) {
        if(ackmsg == NULL) return p67_err_einval;
        memcpy(dstmsg+sizeof(p67_pudp_hdr_t), ackmsg, ackmsgl);
    }

    return 0;
}

p67_err
p67_pudp_handle_msg(p67_conn_t * conn, const char * msg, int msgl, void * args)
{
    p67_err err = 0;
    int wh = 0;
    (void)args;

    /* ACKs remove messages from pending cache */
    if(msg[0] == P67_PUDP_HDR_ACK) {
        err = p67_pudp_remove((const unsigned char *)msg, msgl);
        if(msgl == 5) wh = 1;
    }

    /* URGent messages are ACKed and forwarded to user */
    if(msg[0] == P67_PUDP_HDR_URG) {
        unsigned char ack[5];
        int wrote;
        ack[0] = P67_PUDP_HDR_ACK;
        memcpy(ack + 1, msg + 1, 4);
        wrote = sizeof(ack);
        err = p67_net_write_conn(conn, ack, &wrote);
    }

    if(err != 0){
        p67_err_print_err("PUDP handle: ", err);
        return 0;
    }

    if(wh == 1)
        return 0;

    // signal that message still needs to be processed.
    return p67_err_eagain;
}
