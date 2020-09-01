#if !defined(P67_BWT_H)
#define P67_BWT_H 1

#include <p67/cmn.h>

#include "db.h"

#define P67_BWT_KEY_SIZE 32
#define P67_BWT_SIG_SIZE 32

typedef struct __attribute__((packed)) p67_bwt_payload {
    unsigned char sub[P67_DB_ID_SIZE];
    uint_least64_t exp;
} p67_bwt_payload_t;

typedef struct __attribute__((packed)) p67_bwt {
    p67_bwt_payload_t payload;
    unsigned char sig[P67_BWT_SIG_SIZE];
} p67_bwt_t;

p67_ws_err
p67_bwt_create_for_user(
    const p67_db_user_t * user, p67_cmn_epoch_t exp, p67_bwt_t * bwt);

p67_ws_err
p67_bwt_create_for_user_days(
    const p67_db_user_t * user, int days, p67_bwt_t * bwt);

p67_ws_err
p67_bwt_validate(p67_bwt_t * bwt);

p67_ws_err
p67_bwt_login_user(
    p67_db_ctx_t * ctx,
    const char * username,
    const char * password,
    p67_bwt_t * bwt);

#endif