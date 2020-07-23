#include <stdio.h>
#include <stdlib.h>
#include <p67/p67.h>
#include <string.h>
#include <limits.h>

#include "err.h"
#include "db.h"

p67_err
server_cb(p67_conn_t * conn, const char * msg, int msgl, void * args);

struct p67rs_session {
    int sessid;
};

p67_err
server_cb(p67_conn_t * conn, const char * msg, int msgl, void * args)
{
    (void)args;
    const p67_addr_t * addr = p67_conn_get_addr(conn);
    struct p67rs_session * s = (struct p67rs_session *)s;
    printf("%s:%s says: %.*s. session id is: %d\n", addr->hostname, addr->service, msgl, msg, s->sessid);
    return 0;
}

volatile int sessid = 0;


void * create_rs_session(void);
void * create_rs_session(void)
{
    struct p67rs_session * p = malloc(sizeof(struct p67rs_session));
    p->sessid=(sessid++);
    printf("creating session with id = %d\n", p->sessid);
    if(p == NULL) {
        p67_err_print_err("create client session: ", p67_err_eerrno);
        exit(2);
    }
    return p;
}

void free_rs_session(void * s);
void free_rs_session(void * s)
{
    free(s);
}

int 
main(void)
{
    p67_lib_init();
    p67rs_err err = 0;
    p67_conn_pass_t pass = P67_CONN_PASS_INITIALIZER;
    pass.certpath = "p2pcert.cert";
    pass.keypath = "p2pcert";
    pass.local.rdonly = 1;
    pass.remote.rdonly = 1;
    pass.handler = server_cb;
    pass.gen_args = create_rs_session;
    pass.free_args = free_rs_session;
    if((err = p67_addr_set_localhost4_udp(&pass.local, "10000")) != 0)
        goto end;
    if((err = p67_net_start_listen(&pass)) != 0) goto end;

    printf("server launched. press any key to terminate...\n");
    getchar();
    
end:
    p67_lib_free();
    if(err != 0) p67rs_err_print_err("terminating main thread with error/s: ", err);
    return err == 0 ? 0 : 2;
}