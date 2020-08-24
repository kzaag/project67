#if !defined(P67_TLV_H)
#define P67_TLV_H 1

#include "err.h"
#include <stdint.h>
#include <limits.h>

#include "cmn.h"
#include "net.h"

/*
    p67 tlv fragment:
    message can contain 0 - N such TLV fragments.

    |---|---|--------------------------------------|
    | 1 | 1 |               0 - 255                | 
    |---|---|--------------------------------------|
      |   |                   |
      |   |                   |
      |   |                   ------> [ VALUE: length specified by VLENGTH ]
      |   |
      |   -----> [ VLENGTH : 1 byte value length, allowed values e [0, 255] ]
      |
      ---> [ KEY: 1 byte key. ]

    KEY + VLENGTH fields create HEADER

*/

#define P67_TLV_KEY_LENGTH 1
#define P67_TLV_VLENGTH_LENGTH 1

#define p67_tlv_header_fields()        \
    uint8_t tlv_key[P67_TLV_KEY_LENGTH]; \
    uint8_t tlv_vlength;

typedef struct p67_tlv_header {
    p67_tlv_header_fields()
} p67_tlv_header_t;

p67_cmn_static_assert(p67_tlv_header_t, sizeof(p67_tlv_header_t) == 2);

#define P67_TLV_HEADER_LENGTH \
    (P67_TLV_VLENGTH_LENGTH + P67_TLV_KEY_LENGTH)

#define P67_TLV_VALUE_MIN_LENGTH 0

#define P67_TLV_FRAGMENT_MIN_LENGTH \
    (P67_TLV_KEY_LENGTH + P67_TLV_VLENGTH_LENGTH + P67_TLV_VALUE_MIN_LENGTH)

#define P67_TLV_VALUE_MAX_LENGTH UCHAR_MAX

#define P67_TLV_FRAGMENT_MAX_LENGTH \
    (P67_TLV_KEY_LENGTH + P67_TLV_VALUE_LENGTH_LENGTH + P67_TLV_VALUE_MAX_LENGTH)

// p67_err
// p67_tlv_get_next_fragment(
//             const unsigned char ** msg, int * msgl, 
//             unsigned char * key,
//             unsigned char * value, unsigned char * vlength)
//     __nonnull((1, 2));

p67_err
p67_tlv_next(
    const p67_pckt_t ** msg, int * msgl,
    const p67_tlv_header_t ** header, 
    const p67_pckt_t ** value);

int
p67_tlv_add_fragment(
            unsigned char * msg, int msgl,
            const unsigned char * key,
            const unsigned char * value, 
            unsigned char vlength);

p67_err
p67_tlv_pretty_print_fragment(
    const p67_tlv_header_t * header, 
    const unsigned char * value);

const p67_pckt_t *
p67_tlv_get_arr(
    const p67_tlv_header_t * __restrict__ const hdr, 
    const p67_pckt_t * __restrict__ const value, 
    const int expected_length);

const char *
p67_tlv_get_cstr(
    const p67_tlv_header_t * __restrict__ const hdr, 
    const p67_pckt_t * __restrict__ const value);

#endif