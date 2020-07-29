#if !defined(P67_DMP_H)
#define P67_DMP_H

#include <stdint.h>
#include "../cmn.h"
#include "base.h"

#include "pdp.h"

/*
    datagrams multiplexing protocol

    used to add certain TCP/SCTP-like functionalities 
      
*/


/*
    generic message header. 
*/
typedef struct p67_dmp_hdr {
    __p67_dmp_hdr_common(cmn_)
} p67_dmp_hdr_t;

#define P67_DMP_HDR_OFFSET (sizeof(p67_dmp_hdr_t))

p67_cmn_static_assert(sizeof(p67_dmp_hdr_t) == (2+2));

/*
    DAT ( data ) message header.
*/
typedef struct p67_dmp_dat_hdr {
    __p67_dmp_hdr_common(dat_)
} p67_dmp_dat_hdr_t;

#define P67_PUDP_DAT_HDR_OFFSET (sizeof(p67_dmp_dat_hdr_t))

typedef union p67_dmp_hdr_store {
    p67_dmp_hdr_t      cmn;
    p67_dmp_dat_hdr_t  dat;
    p67_dmp_pdp_ack_hdr_t ack;
    p67_dmp_pdp_urg_hdr_t urg;
} p67_dmp_hdr_store_t;

/*
    parse and validate dmp header
*/
const p67_dmp_hdr_store_t *
p67_dmp_parse_hdr(
    const unsigned char * const msg,
    const int msg_size, 
    p67_err * err);

p67_err
p67_dmp_handle_msg(
        p67_conn_t * conn, 
        const char * msg, 
        int msgl, 
        void * args);

#endif