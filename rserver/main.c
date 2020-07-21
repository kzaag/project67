#include <postgresql/libpq-fe.h>
#include <postgresql/12/server/catalog/pg_type_d.h>
#include <stdio.h>
#include <signal.h>
#include <p67/p67.h>
#include <string.h>

extern void sleep(int);

p67_err
parse_cs(const char * path, char ** cs, int * len);

static PGconn * conn = NULL;

/*
    get connection string from dp config
*/
p67_err
parse_cs(const char * path, char ** cs, int * len)
{
    FILE * fp = NULL;
    fpos_t eix;
    p67_err err = p67_err_eerrno;
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
cleanup(int sig);

void
cleanup(int sig)
{
    if(conn != NULL)
        PQfinish(conn);
    raise(sig);
}

int 
main(void)
{
    p67_err err;

    char * cs;
    int cslen;

    if((err = parse_cs("/home/vattd/src/repos/p67/rserver/main.conf", &cs, &cslen)) != 0) {
        p67_err_print_err(NULL, err);
    } else {
        printf("%s\n", cs);
        free(cs);
    }

    return 0;

    //const char * cs = "host=127.0.0.1 user=dp password=!aDB7$2$ dbname=rserver";
    PGresult * res;

    signal(SIGINT, cleanup);

    conn = PQconnectdb(cs);

    if(PQstatus(conn) != CONNECTION_OK) {
        fprintf(
            stderr, 
            "connect failed: %s",
            PQerrorMessage(conn));
        PQfinish(conn);
        return 2;
    }

    Oid types[] = {BYTEAOID, TEXTOID, TEXTOID};

    const char * pvals[] = {
        "1",
        "hello user",
        "hash"
    };

    // int lens[] = {
    //     sizeof(1), sizeof("hello user"), sizeof("hash")
    // };

    res = PQexecParams(
            conn, 
            "insert into users (u_id, u_name, u_pwd_hash) values ($1, $2, $3)",
            3,
            types,
            pvals,
            NULL,
            NULL,
            0);

    if (PQresultStatus(res) != PGRES_COMMAND_OK) {
        fprintf(stderr, "insert failed: %s", PQerrorMessage(conn));
    }

    PQclear(res);

    PQfinish(conn);
    conn = NULL;



    return 0;
}