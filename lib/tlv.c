#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include "conn.h"
#include "tlv.h"

/*
    if return > 0 then its written offset
    return < 0 is error (-p67_err)
*/
int
p67_tlv_add_fragment(
    unsigned char * msg, int msgl,
    const unsigned char * key,
    const unsigned char * value, unsigned char vlength)
{
    if(msg == NULL || key == NULL)
        return -p67_err_einval;

    if(msgl < (vlength + P67_TLV_HEADER_LENGTH))
        return -p67_err_einval;

    memcpy(msg, key, P67_TLV_KEY_LENGTH);
    *(msg+P67_TLV_KEY_LENGTH) = vlength;
    if(vlength > 0) {
        if(value == NULL) return p67_err_einval;
        memcpy(msg+P67_TLV_HEADER_LENGTH, value, vlength);
    }

    return vlength+P67_TLV_HEADER_LENGTH;
}

/*
    parse current tlv fragment and move to next one.
*/
p67_err
p67_tlv_next(
    const p67_pckt_t ** msg, int * msgl,
    const p67_tlv_header_t ** header, 
    const p67_pckt_t ** value)
{
    if(msg == NULL || *msg == NULL || msgl == NULL)
        return p67_err_einval;
    if(*msgl == 0)
        return p67_err_eot;
    if(*msgl < P67_TLV_FRAGMENT_MIN_LENGTH)
        return p67_err_etlvf;
    
    unsigned char __vlength = *(*msg+P67_TLV_KEY_LENGTH);

    if((*msgl - P67_TLV_HEADER_LENGTH) < __vlength)
        return p67_err_etlvf;

    if(header != NULL) {
        *header = (p67_tlv_header_t *)*msg;
    }

    if(value != NULL) {
        *value = *msg + P67_TLV_HEADER_LENGTH;
    }

    *msg += (__vlength + P67_TLV_HEADER_LENGTH);
    *msgl -= (__vlength + P67_TLV_HEADER_LENGTH);
    
    return 0;
}

p67_err
p67_tlv_pretty_print_fragment(
    const p67_tlv_header_t * header, const unsigned char * value)
{
    const int buffl = 120;
    char buff[buffl];
    int buffix = 0, i, is_printable = 1;
    buffix += snprintf(
        buff+buffix, buffl-buffix, 
        "tlv: key=%u ", header->tlv_key[0]);
    if(buffl-buffix < 0) return p67_err_enomem;

    #define is_byte_printable(x) ((x) >= 33 && (x) <= 126)

    if(is_byte_printable(header->tlv_key[0])) {
        buffix += snprintf(
            buff+buffix, buffl-buffix, 
            "\"%c\" ", header->tlv_key[0]);
        if(buffl-buffix < 0) return p67_err_enomem;
    }
    buffix += snprintf(
        buff+buffix, buffl-buffix, 
        "vlength=%u", header->tlv_vlength);
    if(buffl-buffix < 0) return p67_err_enomem;
    if(header->tlv_vlength > 0) {
        buffix += snprintf(buff+buffix, buffl-buffix, " value=\"");
        if(buffl-buffix < 0) return p67_err_enomem;
        if(header->tlv_vlength > 10) {
            i = 10;
        } else {
            i = header->tlv_vlength;
        }
        while(i-->0) {
            buffix += snprintf(
                buff+buffix, buffl-buffix, 
                "%02hhx ", *value);
            if(buffl-buffix < 0) return p67_err_enomem;
            if(!is_byte_printable(*value))
                is_printable = 0;
            value++;
        }
        buff[buffix-1] = '"';
    }

    if(is_printable) {
        buffix += snprintf(
            buff+buffix, buffl-buffix, 
            "\"%*.s\"", header->tlv_vlength, value);
        if(buffl-buffix < 0) return p67_err_enomem;
    }

    printf("%.*s\n", buffix, buff);

    return 0;
}

// p67_err
// p67_tlv_get_next_fragment(
//     const unsigned char ** msg, int * msgl,
//     const unsigned char * key,
//     const unsigned char * value, unsigned char * vlength)
// {
//     if(msg == NULL || *msg == NULL || msgl == NULL)
//         return p67_err_einval;

//     /* validate at least length + key */

//     if(*msgl == 0)
//         return p67_err_eot;

//     if(*msgl < P67_TLV_FRAGMENT_MIN_LENGTH)
//         return p67_err_etlvf;

//     unsigned char __vlength = *(*msg+P67_TLV_KEY_LENGTH);

//     /* validate at least length + key */

//     if((*msgl - P67_TLV_HEADER_LENGTH) < __vlength)
//         return p67_err_etlvf;

//     if(key != NULL)
//         memcpy(key, *msg, P67_TLV_KEY_LENGTH);

//     if(vlength != NULL) {
//         if(*vlength < __vlength)
//             return p67_err_enomem;
//         *vlength = __vlength;

//         if(value != NULL) {
//             memcpy(value, *msg+P67_TLV_HEADER_LENGTH, __vlength);
//         }
//     }

//     *msg += (__vlength + P67_TLV_HEADER_LENGTH);
//     *msgl -= (__vlength + P67_TLV_HEADER_LENGTH);

//     return 0;
// }

