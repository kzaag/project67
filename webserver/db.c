#include <postgresql/libpq-fe.h>
#include <postgresql/12/server/catalog/pg_type_d.h>
#include <stdio.h>
#include <string.h>
#include <limits.h>
#include <stdlib.h>
#include <strings.h>

#include <openssl/evp.h>
#include <openssl/rand.h>

#include "db.h"

static char * errstr = NULL; 

struct p67_db_ctx {
    PGconn * conn;
};

#define p67_db_PQFMT_TEXT   0
#define p67_db_PQFMT_BINARY 1

void
p67_db_err_set(PGconn * conn);

p67_ws_err
p67rs_parse_cs(const char * path, char ** cs, int * len);

void
p67_db_err_set(PGconn * conn)
{
    errstr = PQerrorMessage(conn);
}

char *
p67_db_err_get(void)
{
    return errstr;
}

p67_err
p67_db_hash_pass(const char * password, int passwordl, unsigned char * hash)
{
    static const unsigned char p67_db_salt[] = {
        #include "salt.h"
    };

    // printf("hashing bytes:\n");
    // int i = 0;
    // while(password[i]) {
    //     printf("%d\n", password[i]);
    //     i++;
    // }
    // printf("done hashing bytes\n");

    if(!PKCS5_PBKDF2_HMAC(
                password, passwordl, 
                p67_db_salt, sizeof(p67_db_salt),
                1000,
                EVP_sha3_256(), 
                P67_DB_PASS_HASH_SIZE, hash))
        return p67_err_essl;

    return 0;
}

/*
    get connection string from dp config
*/
p67_ws_err
p67rs_parse_cs(const char * path, char ** cs, int * len)
{
    FILE * fp = NULL;
    fpos_t eix;
    p67_ws_err err = p67_err_eerrno;
    char * buf = NULL, * line = NULL;
    int ix = 0, lix = 0, epos, ilix, cslen = 0;

    if((fp = fopen(path, "r")) == NULL)
        return p67_err_eerrno;

    if(fseek(fp, 0, SEEK_END) != 0) goto end;

    if(fgetpos(fp, &eix) != 0) goto end;

    if(eix.__pos > INT_MAX)
        return p67_err_einval;

    epos = (int)eix.__pos;

    if((buf = malloc(epos)) == NULL) goto end;
    if((line = malloc(epos)) == NULL) goto end;
    if((*cs = malloc(epos)) == NULL) goto end;

    rewind(fp);

    if(fread(buf, 1, epos, fp) != (size_t)epos) goto end;

    while(ix < epos) {
        if(buf[ix] == '\n' || (ix + 1) == epos) {
            
            ilix = 0;
            while(ilix<lix) {
                if(line[ilix] == '=') {
                    //printf("%.*s\n", (int)(lix-ilix), line+ilix);
                    if(memcmp(line, "server", sizeof("server")-1) == 0)
                        cslen+=sprintf(*cs+cslen, "host%.*s ", lix-ilix, line+ilix);
                    else if(memcmp(line, "database", sizeof("database")-1) == 0)
                        cslen+=sprintf(*cs+cslen, "dbname%.*s ", lix-ilix, line+ilix);
                    else if(memcmp(line, "password", sizeof("password")-1) == 0)
                        cslen+=sprintf(*cs+cslen, "password%.*s ", lix-ilix, line+ilix);
                    else if(memcmp(line, "user", sizeof("user")-1) == 0)
                        cslen+=sprintf(*cs+cslen, "user%.*s ", lix-ilix, line+ilix);
                    break;
                }
                ilix++;
            }

            lix = 0;
        } else {
            line[lix] = buf[ix];
            lix++;
        }
        ix++;
    }

    if(len != NULL) *len = cslen;
    (*cs)[cslen] = 0;

    err = 0;

end:
    if(fp != NULL) fclose(fp);
    free(buf);
    free(line);
    if(err != 0)
        free(cs);
    return err;
}

void
p67_db_ctx_free(p67_db_ctx_t * ctx)
{
    if(ctx == NULL)
        return;

    if(ctx->conn != NULL)
        PQfinish(ctx->conn);
    
    free(ctx);
}

p67_ws_err
p67_db_ctx_create_from_dp_config(p67_db_ctx_t ** ctx, const char * config_path)
{
    if(ctx == NULL) return p67_err_eerrno;

    char * cs = NULL;
    *ctx = NULL;
    p67_ws_err err = (p67_ws_err)p67_err_eerrno;

    if((*ctx = calloc(1, sizeof(**ctx))) == NULL)
        return p67_err_eerrno;

    if((err = p67rs_parse_cs(config_path, &cs, NULL)) != 0)
        goto end;

    (*ctx)->conn = PQconnectdb(cs);

    if(PQstatus((*ctx)->conn) != CONNECTION_OK) {
        err = p67_ws_err_pq;
        p67_db_err_set((*ctx)->conn);
        goto end;
    }

    err = 0;

end:
    free(cs);
    if(err != 0) {
        free(*ctx);
        *ctx = NULL;
    }

    return err;
}

p67_ws_err
p67_db_user_create(
    p67_db_ctx_t * ctx, p67_db_user_t * user)
{
    unsigned char id[P67_DB_ID_SIZE];
    unsigned char hash[P67_DB_PASS_HASH_SIZE];
    PGresult * res;
    p67_ws_err err;

    if(user->pass_cstr == NULL || user->u_name == NULL)
        return p67_err_einval;

    if(!RAND_bytes(id, sizeof(id)))
        return p67_err_essl | p67_err_eerrno;

    if((err  = p67_db_hash_pass(
                user->pass_cstr, strlen(user->pass_cstr), hash)) != 0)
        return err;
    
    const char * parameters[] = {
        (char *)id,
        user->u_name,
        (char *)hash
    };

    Oid types[] = {
        BYTEAOID,
        TEXTOID,
        BYTEAOID
    };

    const int fmts[] = {
        p67_db_PQFMT_BINARY,
        p67_db_PQFMT_TEXT,
        p67_db_PQFMT_BINARY
    };

    const int lengths[] = {
        P67_DB_ID_SIZE,
        strlen(user->u_name),
        P67_DB_PASS_HASH_SIZE
    };

    res = PQexecParams(
        ctx->conn,
        "insert into users (u_id, u_name, u_pwd_hash) values ($1, $2, $3)",
        3,
        types,
        parameters,
        lengths,
        fmts,
        p67_db_PQFMT_BINARY);

    if (PQresultStatus(res) != PGRES_COMMAND_OK) {
        p67_db_err_set(ctx->conn);
        PQclear(res);
        return p67_ws_err_pq;
    }

    memcpy(user->u_pwd_hash, hash, P67_DB_PASS_HASH_SIZE);
    memcpy(user->u_id, id, P67_DB_ID_SIZE);

    PQclear(res);

    return 0;
}

p67_ws_err
p67_db_user_read(
    p67_db_ctx_t * ctx, 
    p67_db_user_hint_t * hint, 
    p67_db_user_t ** users, 
    int * usersl)
{
    p67_ws_err err;
    PGresult * res;
    int rsize, ix;

    const char * parameters[] = {
        hint == NULL || hint->u_id == NULL ? NULL : (const char *)hint->u_id,
        hint == NULL || hint->u_name == NULL ? NULL : (const char *)hint->u_name,
        hint == NULL || hint->u_pwd_hash == NULL ? NULL : (const char *)hint->u_pwd_hash
    };

    const Oid types[] = {
        BYTEAOID,
        TEXTOID,
        BYTEAOID,
    };

    const int fmts[] = {
        p67_db_PQFMT_BINARY,
        p67_db_PQFMT_BINARY,
        p67_db_PQFMT_BINARY
    };

    const int lengths[] = {
        hint == NULL || hint->u_id == NULL ? 0 : P67_DB_ID_SIZE,
        hint == NULL || hint->u_name == NULL ? 0 : hint->u_name_l,
        hint == NULL || hint->u_pwd_hash == NULL ? 0 : P67_DB_PASS_HASH_SIZE
    };

    const int query_len = 159;
    char query[query_len+1];
    int query_ix = 0;

    query_ix += snprintf(query, query_len, "select u_id, u_name, u_pwd_hash from users where ");
    if(hint != NULL && hint->u_id != NULL)
        query_ix += snprintf(query+query_ix, query_len - query_ix, " u_id = $1 and ");
    if(hint != NULL && hint->u_name != NULL)
        query_ix += snprintf(query+query_ix, query_len - query_ix, " u_name = $2 and ");
    if(hint != NULL && hint->u_pwd_hash != NULL)
        query_ix += snprintf(query+query_ix, query_len - query_ix, " u_pwd_hash = $3 and ");
    query_ix += snprintf(query+query_ix, query_len - query_ix, " 1=1 ");

    query[query_ix] = 0;

    res = PQexecParams(
        ctx->conn,
        query,
        3,
        types,
        parameters,
        lengths,
        fmts,
        p67_db_PQFMT_BINARY);

    if (PQresultStatus(res) != PGRES_TUPLES_OK) {
        p67_db_err_set(ctx->conn);
        PQclear(res);
        return p67_ws_err_pq;
    }

    /* 
        using cached mode since number of rows is low and im low on time.
        in case of scaling this function up or simply refractoring one may want to use
            either:
            1. signle row mode
            2. cursor to fetch N rows at the time
    */

    rsize = PQntuples(res);

    err = 0;

    if(usersl != NULL) {
        *usersl = rsize;
    } else {
        goto end;
    }

    if(users == NULL) {
        goto end;
    }

    if(*usersl == 0) {
        goto end;
    }

    if(((*users) = malloc(sizeof(**users) * *usersl)) == NULL) {
        err = p67_err_eerrno;
        goto end;
    }

    int ord_id = PQfnumber(res, "u_id");
    int ord_name = PQfnumber(res, "u_name");
    int ord_hash = PQfnumber(res, "u_pwd_hash");
    int name_len;
    char * name;

    for(ix = 0; ix < rsize; ix++) {
        users[ix]->pass_cstr = NULL;
        memcpy(users[ix]->u_id, PQgetvalue(res, ix, ord_id), P67_DB_ID_SIZE);
        memcpy(users[ix]->u_pwd_hash, PQgetvalue(res, ix, ord_hash), P67_DB_PASS_HASH_SIZE);

        name = PQgetvalue(res, ix, ord_name);
        name_len = strlen(name);
        if((users[ix]->u_name = malloc(name_len + 1)) == NULL) {
            err = p67_err_eerrno;
            goto end;
        }
        memcpy(users[ix]->u_name, name, name_len);
        users[ix]->u_name[name_len] = 0;
    }

    err = 0;

end:
    PQclear(res);
    return err;
}

p67_ws_err
p67_db_user_validate_pass(
    p67_db_ctx_t * ctx,
    char * username, int usernamel,
    unsigned char * password, int passwordl)
{
    unsigned char hash[P67_DB_PASS_HASH_SIZE];
    p67_ws_err err;
    p67_db_user_hint_t hint;
    int check;

    if((err = p67_db_hash_pass((char *)password, passwordl, hash)) != 0)
        return err;

    hint.u_name = username;
    hint.u_name_l = usernamel;
    hint.u_pwd_hash = hash;
    hint.u_id = NULL;

    if((err = p67_db_user_read(ctx, &hint, NULL, &check)) != 0)
        return err;

    if(check != 1)
        return p67_err_einval;

    return 0;
}

p67_ws_err
p67_db_user_delete(
    p67_db_ctx_t * ctx, const p67_db_user_hint_t * hint)
{
    PGresult * res;

    //if(hint->u_id == NULL && hint->u_name == NULL)
    //    return p67_err_einval;

    const char * parameters[] = {
        hint == NULL ? NULL : (char *)hint->u_id,
        hint == NULL ? NULL : (char *)hint->u_name,
        hint == NULL ? NULL : (char *)hint->u_pwd_hash,
    };

    Oid types[] = {
        BYTEAOID,
        TEXTOID,
        BYTEAOID
    };

    const int fmts[] = {
        p67_db_PQFMT_BINARY,
        p67_db_PQFMT_TEXT,
        p67_db_PQFMT_BINARY
    };

    const int lengths[] = {
        hint == NULL || hint->u_id == NULL ? 0 : P67_DB_ID_SIZE,
        hint == NULL || hint->u_name == NULL ? 0 : hint->u_name_l,
        hint == NULL || hint->u_pwd_hash == NULL ? 0 : P67_DB_PASS_HASH_SIZE
    };

    const int query_len = 159;
    char query[query_len+1];
    int query_ix = 0;

    query_ix += snprintf(query, query_len, "delete from users where ");
    if(hint != NULL && hint->u_id != NULL)
        query_ix += snprintf(query+query_ix, query_len - query_ix, " u_id = $1 and ");
    if(hint != NULL && hint->u_name != NULL)
        query_ix += snprintf(query+query_ix, query_len - query_ix, " u_name = $2 and ");
    if(hint != NULL && hint->u_pwd_hash != NULL)
        query_ix += snprintf(query+query_ix, query_len - query_ix, " u_pwd_hash = $3 and ");
    query_ix += snprintf(query+query_ix, query_len - query_ix, " 1=1 ");

    query[query_ix] = 0;

    res = PQexecParams(
        ctx->conn,
        query,
        3,
        types,
        parameters,
        lengths,
        fmts,
        p67_db_PQFMT_BINARY);

    if (PQresultStatus(res) != PGRES_COMMAND_OK) {
        p67_db_err_set(ctx->conn);
        PQclear(res);
        return p67_ws_err_pq;
    }

    PQclear(res);
    return 0;
}
