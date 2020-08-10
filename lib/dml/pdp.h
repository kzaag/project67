#if !defined(P67_PDP_H)
#define P67_PDP_H 1

/*
    persistent datagrams protocol (pdp) implementation
*/

#include "../cmn.h"
#include "../async.h"
#include "../sfd.h"

#include "base.h"

#include <stdint.h>

#define __p67_pdp_message_id(prefix) \
    uint16_t prefix##mid;

/*
    acknowledgement message header. 
*/
typedef struct p67_pdp_ack_hdr {
    __p67_dml_hdr_common(ack_)
    __p67_pdp_message_id(ack_)
} p67_pdp_ack_hdr_t;

#define P67_PDP_ACK_OFFSET (sizeof(p67_pdp_ack_hdr_t))

/*
    URG ( urgent ) message header
*/
typedef struct p67_pdp_urg_hdr {
    __p67_dml_hdr_common(urg_)
    __p67_pdp_message_id(urg_)
} p67_pdp_urg_hdr_t;

#define P67_PDP_URG_OFFSET (sizeof(p67_pdp_urg_hdr_t))

extern uint16_t * p67_pdp_mid_location(void) __attribute_const__;

#define p67_pdp_mid (*p67_pdp_mid_location())

/*
    pudp event types used in URG-ACK communication model
*/
#define P67_PDP_EVT_NONE    0
#define P67_PDP_EVT_GOT_ACK 1
#define P67_PDP_EVT_TIMEOUT 2
#define P67_PDP_EVT_ERROR   3

/*
    pudp message queue inode statuses
    message queue is used to keep URG messages and rretransmission them when needed.
*/
#define P67_PDP_ISTATE_FREE 0
#define P67_PDP_ISTATE_PASS 1
#define P67_PDP_ISTATE_ACTV 2

/*
    callback of this type, can be optionally passed when sending URG message
    so user can be asynchronously notified about any events 
        ( P67_PUDP_EVT_* ) concerning URG packet.
    arg value will vary depending on EVT, 
        for P67_PUDP_EVT_ERROR this will be pointer to p67_err value with details.
*/
// typedef void (* p67_pdp_callback_t)(
//         p67_conn_pass_t * pass, int p67_pudp_evt, void * arg);

/*
    retransmission loop will be awoken at least P67_PUDP_INTERV miliseconds.
    can be more often depending on messages registrations.
*/
#define P67_PDP_INTERV 200
#define P67_PDP_TTL_DEF 2500

p67_err
p67_pdp_write_urg(
            /* context */
            p67_addr_t * addr, 
            const uint8_t * msg, 
            int msgl, 
            /* 
                how long message is to be retained in buffer in miliseconds.
                if lower or equal to 0 then it will default to P67_PUDP_TTL_DEF
            */
            int ttl,
            /*
                async handler which user can use to await for message being rejected or sent.
            */
            p67_async_t * termsig,
            
            void ** res,
            int * resl);

p67_err
p67_pdp_start_loop(void);

p67_err
p67_pdp_generate_ack_from_hdr(
        const p67_pdp_urg_hdr_t * srchdr,
        const unsigned char * ackpayload, int ackpayloadl,
        char * dstmsg, int dstmsgl);

p67_err
p67_pdp_generate_ack(
        /* URG message */
        const unsigned char * srcmsg, int srcmsgl, 
        /* optional ACK message payload, pass NULL and 0 to ignore */
        const unsigned char * ackpayload, int ackpayloadl,
        /* destination message */
        char * dstmsg, int dstmsgl);

/*
    return pointer pointing to header of the message, 
        or null on error ( p67_err_einval )
*/
const p67_pdp_urg_hdr_t *
p67_pdp_generate_urg_for_msg(
    char * urg_payload, int urg_payload_l,
    char * dst_msg, int dst_msg_l,
    uint8_t urg_utp);

/*
    returns human representation of P67_PUDP_EVT_*
    make buff about 32 bytes should be enough.
*/
char *
p67_pdp_evt_str(char * buff, int buffl, int evt);

p67_err
p67_pdp_write_ack_for_urg(
    p67_addr_t* addr, 
    const p67_pdp_urg_hdr_t * urg_hdr);

p67_err
p67_pdp_urg_remove(
    uint16_t id, unsigned char * msg, int msgl, int preack);

typedef struct p67_pdp_keepalive_ctx {
    p67_thread_sm_t th;
    p67_addr_t * addr;
} p67_pdp_keepalive_ctx_t;

p67_err
p67_pdp_start_keepalive_loop(p67_pdp_keepalive_ctx_t * ctx);

#endif
