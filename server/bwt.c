/*
    binary web token implementation
*/

#include <string.h>
#include <openssl/hmac.h>

#include <server/err.h>
#include <server/bwt.h>

/*
    may be unsafe to keep this variable constantly in memory
*/
static unsigned char p67_bwt_hmac_key[] = {
    #include <server/hmac.h>
};

p67_ws_err
p67_bwt_create_for_user(
    const p67_db_user_t * user, p67_cmn_epoch_t exp, p67_bwt_t * bwt)
{
    if(bwt == NULL) return p67_err_einval;

    unsigned int mdlen = P67_BWT_SIG_SIZE;
    bwt->payload.exp = p67_cmn_hton64(exp);
    memcpy(bwt->payload.sub, user->u_id, P67_DB_ID_SIZE);

    if(HMAC(
            EVP_sha3_256(), 
            p67_bwt_hmac_key, 
            P67_BWT_KEY_SIZE,
            (const unsigned char *)&bwt->payload, 
            sizeof(p67_bwt_payload_t),
            bwt->sig,
            &mdlen) == NULL)
        return p67_err_essl;

    return 0;
}

p67_ws_err
p67_bwt_create_for_user_days(
    const p67_db_user_t * user, int days, p67_bwt_t * bwt)
{
    p67_err err;
    p67_cmn_epoch_t exp;
    
    if((err = p67_cmn_epoch_ms(&exp)) != 0) return err;

    exp+=(days * 24 * 60 * 60 * 1000);

    return p67_bwt_create_for_user(user, exp, bwt);
}

p67_ws_err
p67_bwt_validate(p67_bwt_t * bwt)
{
    if(bwt == NULL) return p67_err_einval;

    p67_err err;
    unsigned  int mdlen = P67_BWT_SIG_SIZE;
    unsigned char sig[P67_BWT_SIG_SIZE];

    if(HMAC(
            EVP_sha3_256(), 
            p67_bwt_hmac_key, 
            P67_BWT_KEY_SIZE,
            (const unsigned char *)&bwt->payload, 
            sizeof(p67_bwt_payload_t),
            sig,
            &mdlen) == NULL)
        return p67_err_essl;

    if(memcmp(sig, bwt->sig, mdlen) != 0)
        return p67_ws_err_bwt_sig;

    p67_cmn_epoch_t now;

    if((err = p67_cmn_epoch_ms(&now)) != 0)
        return err;

    if(now > bwt->payload.exp)  
        return p67_ws_err_bwt_exp;

    return 0;
}

p67_ws_err
p67_bwt_login_user(
    p67_db_ctx_t * ctx,
    const char * username,
    const char * password,
    p67_bwt_t * bwt)
{
    p67_db_user_hint_t hint;
    unsigned char hash[P67_DB_PASS_HASH_SIZE];
    p67_err err;
    p67_db_user_t * users = NULL;
    int usersl;
    
    if((err = p67_db_hash_pass(password, strlen(password), hash)) != 0)
        return err;

    hint.u_pwd_hash = hash;
    hint.u_name = (char *)username;
    hint.u_name_l = strlen(username);
    hint.u_id = NULL;

    if((err = p67_db_user_read(ctx, &hint, &users, &usersl)) != 0)
        return err;

    if(usersl != 1) {
        free(users);
        return p67_err_einval;
    }

    if((err = p67_bwt_create_for_user_days(users, 1, bwt)) != 0) {
        free(users);
        return p67_err_einval;
    }

    free(users);

    return 0;
}
