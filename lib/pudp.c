#include "net.h"
#include "pudp.h"
#include "log.h"

#include <string.h>

#define P67_PUDP_INODE_LEN 101
#define P67_PUDP_CHUNK_LEN 256

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
p67_pudp_urg_remove(uint32_t id);

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
    size_t hash, i;
    p67_pudp_urg_hdr_t uhdr;

    if(msgl > P67_PUDP_CHUNK_LEN) return p67_err_einval;

    if((err = p67_pudp_parse_msg_hdr(
            msg, msgl, (p67_pudp_hdr_t *)&uhdr, &(int){sizeof(uhdr)}, 1)) != 0)
        return err;

    if(uhdr.urg_shdr != P67_PUDP_HDR_URG)
        return p67_err_einval;

    uint32_t mid = uhdr.urg_mid;

    if(pudp.state == P67_THREAD_SM_STATE_STOP)
        if((err = p67_pudp_start_loop()) != 0 && err != p67_err_eaconn)
            return err;

    hash = pudp_hashin(mid);

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
        pudp_inodes[i].iid = mid;
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
p67_pudp_urg_remove(uint32_t id)
{
    int state;
    size_t hash, i;

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
p67_pudp_urg(char * msg, uint16_t urg_uhdr)
{
    p67_pudp_urg_hdr_t urghdr;
    urghdr.urg_mid = p67_cmn_ntohl(p67_pudp_mid);
    urghdr.urg_shdr = p67_cmn_htons(P67_PUDP_HDR_URG);
    urghdr.urg_uhdr = p67_cmn_htons(urg_uhdr);
    memcpy(msg, (char *)&urghdr, sizeof(urghdr));
    return msg+sizeof(urghdr);
}

p67_err
p67_pudp_parse_msg_hdr(
    const unsigned char * const msg, const int msg_size,
    p67_pudp_hdr_t * hdr, int * hdr_size, 
    int reverse_endian)
{
    if(msg == NULL) return p67_err_einval;
    if((unsigned long)msg_size < sizeof(p67_pudp_hdr_t)) return p67_err_epudpf;

    p67_pudp_all_hdr_t * __hdr = (p67_pudp_all_hdr_t *)msg;
    int __hdr_size;
    uint16_t tmp = p67_cmn_ntohs(__hdr->hdr.cmn_shdr);

    switch(tmp) {
    case P67_PUDP_HDR_DAT:
        __hdr_size = sizeof(p67_pudp_dat_hdr_t);
        break;
    case P67_PUDP_HDR_ACK:
        __hdr_size = sizeof(p67_pudp_ack_hdr_t);
        if(reverse_endian) __hdr->ack.ack_mid = p67_cmn_ntohl(__hdr->ack.ack_mid);
        break;
    case P67_PUDP_HDR_URG:
        __hdr_size = sizeof(p67_pudp_urg_hdr_t);
        if(reverse_endian) __hdr->urg.urg_mid = p67_cmn_ntohl(__hdr->urg.urg_mid);
        break;
    default:
        return p67_err_epudpf;
    }

    if(*hdr_size < __hdr_size)
        return p67_err_enomem;
    if(msg_size < __hdr_size)
        return p67_err_epudpf;

    if(reverse_endian) {
        __hdr->hdr.cmn_shdr = tmp;
        __hdr->hdr.cmn_uhdr = p67_cmn_ntohs(__hdr->hdr.cmn_uhdr);
    }

    memcpy(hdr, __hdr, __hdr_size);

    return 0;
}

p67_err
p67_pudp_generate_ack(
        const unsigned char * srcmsg, int srcmsgl, 
        const unsigned char * ackmsg, int ackmsgl,
        char * dstmsg)
{
    if((unsigned long)srcmsgl < sizeof(p67_pudp_urg_hdr_t))
        return p67_err_einval;

    const p67_pudp_urg_hdr_t * srchdr = (const p67_pudp_urg_hdr_t *)srcmsg;
    p67_pudp_ack_hdr_t * ackhdr = (p67_pudp_ack_hdr_t *)dstmsg;

    if(srchdr->urg_shdr != P67_PUDP_HDR_URG)
        return p67_err_einval;

    ackhdr->ack_shdr = p67_cmn_htons(P67_PUDP_HDR_ACK);
    ackhdr->ack_uhdr = srchdr->urg_uhdr;
    ackhdr->ack_mid = srchdr->urg_mid;

    if(ackmsgl > 0) {
        if(ackmsg == NULL) return p67_err_einval;
        memcpy(dstmsg+sizeof(p67_pudp_ack_hdr_t), ackmsg, ackmsgl);
    }

    return 0;
}

p67_err
p67_pudp_handle_msg(
    p67_conn_t * conn, 
    const char * msg, int msgl, 
    void * args)
{
    (void)args;
    p67_err err;
    int wh = 0;
    p67_pudp_all_hdr_t allhdr;
    p67_pudp_ack_hdr_t ackmsg;
    int size = sizeof(allhdr);

    if((err = p67_pudp_parse_msg_hdr(
            (unsigned char *)msg, msgl, (p67_pudp_hdr_t *)&allhdr, &size, 1)) == 0) {

        switch(allhdr.hdr.cmn_shdr) {
        case P67_PUDP_HDR_ACK:
            /* ACKs remove URG messages which are currently queued*/
            err = p67_pudp_urg_remove(allhdr.ack.ack_mid);
            if(msgl == sizeof(p67_pudp_urg_hdr_t)) wh = 1;
            break;
        case P67_PUDP_HDR_URG:
            /* URGent messages are ACKed and forwarded to user */
            if((err = p67_pudp_generate_ack(
                    (unsigned char *)msg, msgl, NULL, 0, (char *)&ackmsg)) != 0)
                break;
            err = p67_net_must_write_conn(conn, (char *)&ackmsg, sizeof(ackmsg));
            break;
        case P67_PUDP_HDR_DAT:
            /* nothing to be done with DAT */
            break;
        default:
            err = p67_err_epudpf;
            break;
        }
    }

    if(err != 0){
        p67_err_print_err("ERR in pudp handle message: ", err);
        return 0;
    }

    if(wh == 1)
        return 0;

    // signal that message still needs to be processed.
    return p67_err_eagain;
}
