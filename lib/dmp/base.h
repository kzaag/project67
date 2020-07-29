#if !defined(P67_DMP_BASE_H)
#define P67_DMP_BASE_H

/* raw udp packet */
#define P67_DMP_STP_DAT 0
/* udp packet with retransmission request */
#define P67_DMP_STP_PDP_URG 1
/* udp packet with retransmission response */
#define P67_DMP_STP_PDP_ACK 2

#define __p67_dmp_hdr_common(prefix) \
    uint16_t prefix##stp; \
    uint16_t prefix##utp;

#endif
