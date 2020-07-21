
#if !defined(P67_PROTOS_H)
#define P67_PROTOS_H 1

#define P67_PROTO_UNDEFINED 0
#define P67_PROTO_PUDP_URG 1
#define P67_PROTO_PUDP_ACK 2
#define P67_PROTO_STREAM_DATA 3

struct __attribute__((packed)) p67_proto_hdr {
    unsigned char h_val;
};

#endif
