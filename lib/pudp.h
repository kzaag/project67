#if !defined(P67_PUDP_H)
#define P67_PUDP_H 1

#include "net.h"
#include <stdint.h>

#define p67_static_assert(test) typedef char __p67sa[( !!(test) )*2-1 ]

#define __p67_pudp_hdr_common(prefix) \
    uint16_t prefix##shdr; \
    uint16_t prefix##uhdr;

#define __p67_pudp_hdr_id(prefix) \
    uint32_t prefix##mid;

#define P67_NET_STRUCT struct __attribute__((packed))

/*
    generic message header. 
*/
typedef P67_NET_STRUCT p67_pudp_hdr {
    __p67_pudp_hdr_common(cmn_)
} p67_pudp_hdr_t;

p67_static_assert(sizeof(p67_pudp_hdr_t) == (2*2));

/*
    ACK ( acknowledgement ) message header. 
*/
typedef P67_NET_STRUCT p67_pudp_ack_hdr {
    __p67_pudp_hdr_common(ack_)
    __p67_pudp_hdr_id(ack_)
} p67_pudp_ack_hdr_t;

/*
    URG ( urgent ) message header
*/
typedef P67_NET_STRUCT p67_pudp_urg_hdr {
    __p67_pudp_hdr_common(urg_)
    __p67_pudp_hdr_id(urg_)
} p67_pudp_urg_hdr_t;

/*
    DAT ( data ) message header.
*/
typedef P67_NET_STRUCT p67_pudp_dat_hdr {
    __p67_pudp_hdr_common(dat_)
} p67_pudp_dat_hdr_t;

/*
    BAT ( batch ) message header.
    ...
    work in progress
*/

typedef union p67_pudp_all_hdr {
    p67_pudp_hdr_t hdr;
    p67_pudp_ack_hdr_t ack;
    p67_pudp_urg_hdr_t urg;
    p67_pudp_dat_hdr_t dat;
} p67_pudp_all_hdr_t;


extern uint32_t * p67_pudp_mid_location(void) __attribute_const__;

#define p67_pudp_mid (*p67_pudp_mid_location())

/*
    message protocols and types
*/
#define P67_PUDP_HDR_DAT 0
#define P67_PUDP_HDR_URG 1
#define P67_PUDP_HDR_ACK 2

/*
    pudp event types used in URG-ACK communication model
*/
#define P67_PUDP_EVT_NONE    0
#define P67_PUDP_EVT_GOT_ACK 1
#define P67_PUDP_EVT_TIMEOUT 2
#define P67_PUDP_EVT_ERROR   3

/*
    pudp message queue inode statuses
    message queue is used to keep URG messages and rretransmission them when needed.
*/
#define P67_PUDP_ISTATE_FREE 0
#define P67_PUDP_ISTATE_PASS 1
#define P67_PUDP_ISTATE_ACTV 2

/*
    callback of this type, can be optionally passed when sending URG message
    so user can be asynchronously notified about any events 
        ( P67_PUDP_EVT_* ) concerning URG packet.
    arg value will vary depending on EVT, 
        for P67_PUDP_EVT_ERROR this will be pointer to p67_err value with details.
*/
typedef void (* p67_pudp_callback_t)(
        p67_conn_pass_t * pass, int p67_pudp_evt, void * arg);

/*
    retransmission loop will be awoken at least P67_PUDP_INTERV miliseconds.
    can be more often depending on messages registrations.
*/
#define P67_PUDP_INTERV 100
#define P67_PUDP_TTL_DEF 5000

p67_err
p67_pudp_write_urg(
            /* context */
            p67_conn_pass_t * pass, 
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
            /*
                see p67_pudp_callback_t comment
            */
            p67_pudp_callback_t cb);

p67_err
p67_pudp_start_loop(void);

p67_err
p67_pudp_handle_msg(
        p67_conn_t * conn, 
        const char * msg, 
        int msgl, 
        void * args);

/*
    dstmsg must be at least sizeof(p67_pudp_ack_hdr_t) + ackmsgl bytes long.
*/
p67_err
p67_pudp_generate_ack(
        const unsigned char * srcmsg, int srcmsgl, 
        const unsigned char * ackmsg, int ackmsgl,
        char * dstmsg);

/*
    sets the URG header for pudp packet
*/
char *
p67_pudp_urg(char * msg, uint16_t urg_uhdr);

/*
    returns human representation of P67_PUDP_EVT_*
    make buff about 32 bytes should be enough.
*/
char *
p67_pudp_evt_str(char * buff, int buffl, int evt);


p67_err
p67_pudp_parse_msg_hdr(
    const unsigned char * const msg, const int msg_size,
    p67_pudp_hdr_t * hdr, int * hdr_size, 
    int reverse_endian);

#endif
