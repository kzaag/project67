#if !defined(P67RS_ERR_H)
#define P67RS_ERR_H 1

#include <p67/err.h>

enum p67_ws_err {
    p67_ws_err_base    = p67_err__prev__,
    p67_ws_err_pq      = p67_err__next__,        /* postgresql driver / dbms error */
    p67_ws_err_bwt_sig = p67_err__next__ << 1,   /* bwt signature validation error */
    p67_ws_err_bwt_exp = p67_err__next__ << 2,   /* bwt token expiration error */
};

typedef enum p67_ws_err p67_ws_err;

void
p67_ws_err_print_err(const char * hdr, p67_ws_err err);

#endif
