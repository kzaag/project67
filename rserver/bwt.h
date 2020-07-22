#if !defined(P67RS_BWT_H)
#define P67RS_BWT_H 1

#include <p67/cmn.h>
#include "db.h"

#define P67RS_BWT_KEY_SIZE 32
#define P67RS_BWT_SIG_SIZE 32

typedef struct __attribute__((packed)) p67rs_bwt_payload {
    unsigned char sub[P67RS_DB_ID_SIZE];
    uint_least64_t exp;
} p67rs_bwt_payload_t;

typedef struct __attribute__((packed)) p67rs_bwt {
    p67rs_bwt_payload_t payload;
    unsigned char sig[P67RS_BWT_SIG_SIZE];
} p67rs_bwt_t;

p67rs_err
p67rs_bwt_create_for_user(
    const p67rs_db_user_t * user, p67_epoch_t valid_to, p67rs_bwt_t * bwt);

p67rs_err
p67rs_bwt_create_for_user_days(
    const p67rs_db_user_t * user, int days, p67rs_bwt_t * bwt);

p67rs_err
p67rs_bwt_validate(p67rs_bwt_t * bwt);

#endif