#if !defined(P67_DML_DML_H)
#define P67_DML_DML_H

#include <stdint.h>

#include "../cmn.h"

#include "base.h"
#include "pdp.h"

/*
    datagrams multiplexing layer

    used to add certain TCP/SCTP-like functionalities to udp
      
*/

/*
    maxminum "safe" mtu for pdp payload.
*/
#define P67_DML_SAFE_PAYLOAD_SIZE 496

int
p67_dml_get_max_payload_size(void);

/*
    generic message header. 
*/
typedef struct p67_dml_hdr {
    __p67_dml_hdr_common(cmn_)
} p67_dml_hdr_t;

#define P67_DML_HDR_OFFSET (sizeof(p67_dml_hdr_t))

p67_cmn_static_assert(p67_dml_hdr_t, sizeof(p67_dml_hdr_t) == (2));

/*
    DAT ( data ) message header.
*/
typedef struct p67_dml_dat_hdr {
    __p67_dml_hdr_common(dat_)
} p67_dml_dat_hdr_t;

#define P67_PUDP_DAT_HDR_OFFSET (sizeof(p67_dmp_dat_hdr_t))

typedef union p67_dml_hdr_store {
    p67_dml_hdr_t      cmn;
    p67_dml_dat_hdr_t  dat;
    p67_pdp_ack_hdr_t ack;
    p67_pdp_urg_hdr_t urg;
} p67_dml_hdr_store_t;

/*
    parse and validate dmp header
*/
const p67_dml_hdr_store_t *
p67_dml_parse_hdr(
    const p67_pckt_t * const msg,
    const int msg_size, 
    p67_err * err);

p67_err
p67_dml_handle_msg(
        p67_addr_t * addr, 
        const p67_pckt_t * msg, 
        int msgl, 
        void * args);

p67_err
p67_dml_pretty_print(const char * msgh, const unsigned char * msg, int msgl);

#endif