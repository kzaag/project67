#if !defined(P67_TLV_H)
#define P67_TLV_H 1

#include "err.h"
#include <stdint.h>
#include <limits.h>

/*
    p67 tlv fragment:
    message can contain 0 - N such TLV fragments.

    |---|---|--------------------------------------|
    | 3 | 1 |               0 - 255                | 
    |---|---|--------------------------------------|
      |   |                   |
      |   |                   |
      |   |                   ------> [ VALUE: length specified by VLENGTH ]
      |   |
      |   -----> [ VLENGTH : 1 byte value length, allowed values e [0, 255] ]
      |
      ---> [ KEY: 3 byte key. ]

    KEY + VLENGTH fields create HEADER

*/

typedef struct p67_tlv_header {
    uint8_t key[3];
    uint8_t vlength;
} p67_tlv_header_t;

#define P67_TLV_KEY_LENGTH 3
#define P67_TLV_VLENGTH_LENGTH 1

#define P67_TLV_HEADER_LENGTH \
    (P67_TLV_VLENGTH_LENGTH + P67_TLV_KEY_LENGTH)

#define P67_TLV_VALUE_MIN_LENGTH 0

#define P67_TLV_FRAGMENT_MIN_LENGTH \
    (P67_TLV_KEY_LENGTH + P67_TLV_VLENGTH_LENGTH + P67_TLV_VALUE_MIN_LENGTH)

#define P67_TLV_VALUE_MAX_LENGTH UCHAR_MAX

#define P67_TLV_FRAGMENT_MAX_LENGTH \
    (P67_TLV_KEY_LENGTH + P67_TLV_VALUE_LENGTH_LENGTH + P67_TLV_VALUE_MAX_LENGTH)

p67_err
p67_tlv_get_next_fragment(
            const unsigned char ** msg, int * msgl, 
            unsigned char * key,
            unsigned char * value, unsigned char * vlength)
    __nonnull((1, 2));

int
p67_tlv_add_fragment(
            unsigned char * msg, int msgl,
            const unsigned char * key,
            const unsigned char * value, 
            unsigned char vlength);

#endif