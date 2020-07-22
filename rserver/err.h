#if !defined(P67RS_ERR_H)
#define P67RS_ERR_H 1

#include <p67/err.h>

enum p67rs_err {
    p67rs_err_base    = p67_err__prev__,
    p67rs_err_pq      = p67_err__next__,        /* postgresql driver / dbms error */
    p67rs_err_bwt_sig = p67_err__next__ << 1,   /* bwt signature validation error */
    p67rs_err_bwt_exp = p67_err__next__ << 2,   /* bwt token expiration error */
};

typedef enum p67rs_err p67rs_err;

void
p67rs_err_print_err(const char * hdr, p67rs_err err);

#endif
