#if !defined(P67RS_ERR_H)
#define P67RS_ERR_H 1

#include <p67/err.h>

enum p67rs_err {
    p67rs_err_base = p67_err__prev__,
    p67rs_err_pq = p67_err__next__
};

typedef enum p67rs_err p67rs_err;

void
p67rs_err_print_err(const char * hdr, p67rs_err err);

#endif
