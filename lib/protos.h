#if !defined(PROTOS_H)
#define PROTOS_H 1

#include "net.h"
#include <stdint.h>

extern uint32_t * p67_proto_mid_location(void) __attribute_const__;

#define p67_protos_mid (*p67_proto_mid_location())

/*
    message protocols and types
*/
#define P67_PROTO_HDR_DATA 0
#define P67_PROTO_HDR_URG 1
#define P67_PROTO_HDR_ACK 2

#define P67_PROTO_HDR_DATA_SIZE 1
#define P67_PROTO_HDR_ACK_SIZE 5
#define P67_PROTO_HDR_URG_SIZE 5

#define p67_proto_data_payload_ptr(msg) ((msg) + P67_PROTO_HDR_DATA_SIZE)
#define p67_proto_urg_payload_ptr(msg) ((msg) + P67_PROTO_HDR_URG_SIZE)
#define p67_proto_ack_payload_ptr(msg) ((msg) + P67_PROTO_HDR_ACK_SIZE)

#define P67_PUDP_EVT_GOT_ACK 1
#define P67_PUDP_EVT_TIMEOUT 2
#define P67_PUDP_EVT_ERROR   3

#define P67_PUDP_ISTATE_FREE 0
#define P67_PUDP_ISTATE_PASS 1
#define P67_PUDP_ISTATE_ACTV 2

typedef void (* p67_pudp_callback_t)(
        p67_conn_pass_t * pass, int p67_pudp_evt, void * arg);

p67_err
p67_proto_write_urg(
            p67_conn_pass_t * pass, 
            const uint8_t * msg, 
            int msgl, 
            int ttl,
            int * termsig,
            p67_pudp_callback_t cb);

p67_err
p67_pudp_start_loop(void);

typedef struct p67_proto_rpass {
    p67_conn_callback_t ucb;
    void * uarg;
} p67_proto_rpass_t;

p67_err
p67_proto_handle_msg(
        p67_conn_t * conn, 
        const char * msg, 
        int msgl, 
        void * args);


char *
p67_pudp_urg(char * msg);

#endif
