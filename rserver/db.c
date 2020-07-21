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

struct p67rs_db_ctx {
    PGconn * conn;
};

#define P67RS_DB_PQFMT_TEXT   0
#define P67RS_DB_PQFMT_BINARY 1

void
p67rs_db_err_set(PGconn * conn);

p67rs_err
p67rs_parse_cs(const char * path, char ** cs, int * len);

void
p67rs_db_err_set(PGconn * conn)
{
    errstr = PQerrorMessage(conn);
}

char *
p67rs_db_err_get(void)
{
    return errstr;
}

/*
    get connection string from dp config
*/
p67rs_err
p67rs_parse_cs(const char * path, char ** cs, int * len)
{
    FILE * fp = NULL;
    fpos_t eix;
    p67rs_err err = p67_err_eerrno;
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
p67rs_db_ctx_free(p67rs_db_ctx_t * ctx)
{
    if(ctx == NULL)
        return;

    if(ctx->conn != NULL)
        PQfinish(ctx->conn);
    
    free(ctx);
}

p67rs_err
p67rs_db_ctx_create_from_dp_config(p67rs_db_ctx_t ** ctx, const char * config_path)
{
    if(ctx == NULL) return p67_err_eerrno;

    char * cs = NULL;
    *ctx = NULL;
    p67rs_err err = (p67rs_err)p67_err_eerrno;

    if((*ctx = calloc(1, sizeof(**ctx))) == NULL)
        return p67_err_eerrno;

    if((err = p67rs_parse_cs(config_path, &cs, NULL)) != 0)
        goto end;

    (*ctx)->conn = PQconnectdb(cs);

    if(PQstatus((*ctx)->conn) != CONNECTION_OK) {
        err = p67rs_err_pq;
        p67rs_db_err_set((*ctx)->conn);
        goto end;
    }

end:
    free(cs);
    if(err != 0) {
        free(*ctx);
    }

    return 0;
}

p67_err
p67rs_db_create_user(
    p67rs_db_ctx_t * ctx, const char * username, const char * password)
{
    unsigned char id[120];
    unsigned char hash[256];
    PGresult * res;
    const unsigned char salt[] = {
        #include "salt.h"
    };

    if(!RAND_bytes(id, sizeof(id)-1))
        return p67_err_essl | p67_err_eerrno;

    if(!PKCS5_PBKDF2_HMAC(
                password, strlen(password), 
                salt, sizeof(salt),
                1000,
                EVP_sha3_256(),
                sizeof(hash), hash))
        return p67_err_essl;
    
    id[sizeof(id)-1] = 0;

    const char * parameters[] = {
        (char *)id,
        username,
        (char *)hash
    };

    Oid types[] = {
        BYTEAOID,
        TEXTOID,
        BYTEAOID
    };

    const int fmts[] = {
        P67RS_DB_PQFMT_BINARY,
        P67RS_DB_PQFMT_TEXT,
        P67RS_DB_PQFMT_BINARY
    };

    const int lengths[] = {
        sizeof(id),
        strlen(username),
        sizeof(hash)
    };

    res = PQexecParams(
        ctx->conn,
        "insert into users (u_id, u_name, u_pwd_hash) values ($1, $2, $3)",
        3,
        types,
        parameters,
        lengths,
        fmts,
        P67RS_DB_PQFMT_BINARY);

    if (PQresultStatus(res) != PGRES_COMMAND_OK) {
        p67rs_db_err_set(ctx->conn);
        PQclear(res);
        return p67rs_err_pq;
    }

    PQclear(res);
    return 0;
}

// p67_err
// p67rs_db_delete_user(
//     const char * name, const char * password)
// {

// }

// p67_err
// p67rs_db_get_user_by_name(
//     const char * name, const char * password)
// {

// }
