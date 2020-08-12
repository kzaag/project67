#if !defined(P67_WEB_TLV_H)
#define P67_WEB_TLV_H 1

/*
    common tlv fragments
*/

#include "status.h"

#include "../tlv.h"
#include "../dml/dml.h"

#define P67_WEB_TLV_STATUS_TAG (unsigned char *)"s"

#define P67_WEB_TLV_STATUS_BUFFL (P67_WEB_STATUS_STR_BUFFL + 32)

struct p67_web_tlv_status_fragment {
    p67_tlv_header_fields()
    p67_web_status status;
} p67_web_tlv_status_fragment_t;

#define p67_web_tlv_add_status_fragment(msg, msgl, status) \
    p67_tlv_add_fragment(                                 \
        msg, msgl,                                  \
        P67_WEB_TLV_STATUS_TAG,                          \
        (unsigned char *)&(p67_web_status){p67_cmn_htons(status)}, \
        sizeof(status));

/*
    generate ack message and write status_fragment fragment into it
*/
p67_err
p67_web_tlv_respond_with_status(
    const p67_pdp_urg_hdr_t * urg,
    p67_addr_t * addr,
    p67_web_status status);

p67_err
p67_web_tlv_status_str(
    const p67_pckt_t * msg, int msgl,
    char * buff, int buffl);


#endif
