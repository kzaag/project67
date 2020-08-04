/*
    binary web token implementation
*/

#include <string.h>
#include <p67/err.h>
#include <openssl/hmac.h>

#include "db.h"
#include "bwt.h"
#include "err.h"

/*
    may be unsafe to keep this variable constantly in memory
*/
static unsigned char p67rs_bwt_hmac_key[] = {
    #include "hmac.h"
};

p67rs_err
p67rs_bwt_create_for_user(
    const p67rs_db_user_t * user, p67_epoch_t exp, p67rs_bwt_t * bwt)
{
    if(bwt == NULL) return p67_err_einval;

    unsigned int mdlen = P67RS_BWT_SIG_SIZE;
    bwt->payload.exp = p67_cmn_hton64(exp);
    memcpy(bwt->payload.sub, user->u_id, P67RS_DB_ID_SIZE);

    if(HMAC(
            EVP_sha3_256(), 
            p67rs_bwt_hmac_key, 
            P67RS_BWT_KEY_SIZE,
            (const unsigned char *)&bwt->payload, 
            sizeof(p67rs_bwt_payload_t),
            bwt->sig,
            &mdlen) == NULL)
        return p67_err_essl;

    return 0;
}

p67rs_err
p67rs_bwt_create_for_user_days(
    const p67rs_db_user_t * user, int days, p67rs_bwt_t * bwt)
{
    p67rs_err err;
    p67_epoch_t exp;
    
    if((err = p67_cmn_time_ms(&exp)) != 0) return err;

    exp+=(days * 24 * 60 * 60 * 1000);

    return p67rs_bwt_create_for_user(user, exp, bwt);
}

p67rs_err
p67rs_bwt_validate(p67rs_bwt_t * bwt)
{
    if(bwt == NULL) return p67_err_einval;

    p67_err err;
    unsigned  int mdlen = P67RS_BWT_SIG_SIZE;
    unsigned char sig[P67RS_BWT_SIG_SIZE];

    if(HMAC(
            EVP_sha3_256(), 
            p67rs_bwt_hmac_key, 
            P67RS_BWT_KEY_SIZE,
            (const unsigned char *)&bwt->payload, 
            sizeof(p67rs_bwt_payload_t),
            sig,
            &mdlen) == NULL)
        return p67_err_essl;

    if(memcmp(sig, bwt->sig, mdlen) != 0)
        return p67rs_err_bwt_sig;

    p67_epoch_t now;

    if((err = p67_cmn_time_ms(&now)) != 0)
        return err;

    if(now > bwt->payload.exp)  
        return p67rs_err_bwt_exp;

    return 0;
}

p67rs_err
p67rs_bwt_login_user(
    p67rs_db_ctx_t * ctx,
    const char * username,
    const char * password,
    p67rs_bwt_t * bwt)
{
    p67rs_db_user_hint_t hint;
    unsigned char hash[P67RS_DB_PASS_HASH_SIZE];
    p67rs_err err;
    p67rs_db_user_t * users = NULL;
    int usersl;
    
    if((err = p67rs_db_hash_pass(password, strlen(password), hash)) != 0)
        return err;

    hint.u_pwd_hash = hash;
    hint.u_name = (char *)username;
    hint.u_name_l = strlen(username);
    hint.u_id = NULL;

    if((err = p67rs_db_user_read(ctx, &hint, &users, &usersl)) != 0)
        return err;

    if(usersl != 1) {
        free(users);
        return p67_err_einval;
    }

    if((err = p67rs_bwt_create_for_user_days(users, 1, bwt)) != 0) {
        free(users);
        return p67_err_einval;
    }

    free(users);

    return 0;
}
