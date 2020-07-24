#include "proto.h"
#include <stdlib.h>

p67_proto_hdr_t * 
p67_proto_get_hdr_from_msg(const char * msg, int msgl)
{
    if((unsigned long)msgl < sizeof(p67_proto_hdr_t))
        return NULL;
    
    p67_proto_hdr_t * hdr = (p67_proto_hdr_t *)msg;

    return hdr;
}
