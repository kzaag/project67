#if !defined(P67_DML_BASE_H)
#define P67_DML_BASE_H

/* raw udp packet */
#define P67_DML_STP_DAT 0
/* udp packet with retransmission request */
#define P67_DML_STP_PDP_URG 1
/* udp packet with retransmission response */
#define P67_DML_STP_PDP_ACK 2

#define __p67_dml_hdr_common(prefix) \
    uint8_t prefix##stp; \
    uint8_t prefix##utp;

#endif
