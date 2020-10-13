#if !defined(P67_CERT_H)
#define P67_CERT_H 1

#include "err.h"
#include "sfd.h"

p67_err
p67_cert_create_from_key(const char * path, const char * address);

p67_err
p67_cert_new_key(char * path);

p67_err
p67_cert_new_cert(const char * path, const char * address);

p67_err
p67_cert_trust_address(p67_addr_t * addr, const char * path);

p67_err
p67_cert_get_pk(const char * path, char ** pk,  int * pkl);

#endif
