
#if !defined(P67_PROTO_H)
#define P67_PROTO_H 1

#define P67_PROTO_UNDEFINED 0
#define P67_PROTO_UNDEFINED_S "\0"
#define P67_PROTO_PUDP_URG 1
#define P67_PROTO_PUDP_ACK 2
#define P67_PROTO_STREAM_DATA 3

typedef struct __attribute__((packed)) p67_proto_hdr {
    unsigned char h_val;
} p67_proto_hdr_t;

p67_proto_hdr_t * 
p67_proto_get_hdr_from_msg(const char * msg, int msgl);

#endif
