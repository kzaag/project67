#if !defined(P67_DML_BASE_H)
#define P67_DML_BASE_H

/* raw udp packet */
#define P67_DML_STP_DAT 0
/* udp packet with retransmission request */
#define P67_DML_STP_PDP_URG 1
/* udp packet with retransmission response */
#define P67_DML_STP_PDP_ACK 2
/* pre-ack */
#define P67_DML_STP_PDP_PACK 3
/* qdp data packet */
#define P67_DML_STP_QDP_DAT 4

#define __p67_dml_hdr_common(prefix) \
    uint8_t prefix##stp; \
    uint8_t prefix##utp;

#endif
