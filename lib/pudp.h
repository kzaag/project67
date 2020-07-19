#if !defined(P67_PUDP_H)
#define P67_PUDP_H 1

#include "net.h"
#include <stdint.h>

/*

*/
struct p67_pudp_pudp_hdr {
    uint8_t type;
    uint32_t mid;
};

extern uint32_t * p67_pudp_mid_location(void) __attribute_const__;

#define p67_pudp_mid (*p67_pudp_mid_location())

/*
    message protocols and types
*/
#define P67_PUDP_HDR_URG 1
#define P67_PUDP_HDR_ACK 2

#define P67_PUDP_EVT_NONE    0
#define P67_PUDP_EVT_GOT_ACK 1
#define P67_PUDP_EVT_TIMEOUT 2
#define P67_PUDP_EVT_ERROR   3

#define P67_PUDP_ISTATE_FREE 0
#define P67_PUDP_ISTATE_PASS 1
#define P67_PUDP_ISTATE_ACTV 2

typedef void (* p67_pudp_callback_t)(
        p67_conn_pass_t * pass, int p67_pudp_evt, void * arg);

p67_err
p67_pudp_write_urg(
            p67_conn_pass_t * pass, 
            const uint8_t * msg, 
            int msgl, 
            int ttl,
            int * termsig,
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
    sets the URG header for pudp packet
*/
char *
p67_pudp_urg(char * msg);

char *
p67_pudp_evt_str(char * buff, int buffl, int evt);

#endif
