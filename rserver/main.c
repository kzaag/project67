#include <stdio.h>
#include <stdlib.h>
#include <p67/p67.h>
#include <string.h>
#include <limits.h>

#include "err.h"
#include "db.h"

#define T_YELLOW "\033[33m"
#define T_WHITE "\033[0m"

p67_err
server_cb(p67_conn_t * conn, const char * msg, int msgl, void * args);

#define P67RS_SESSION_STATE_IDLE 0
#define P67RS_SESSION_STATE_RES  1

struct p67rs_session {
    int sessid;
    p67_async_t state;
};

#define P67RS_PATH_LOGIN 1
#define P67RS_PATH_REGISTER 2

typedef struct p67rs_hdr {
    uint8_t path;
} p67rs_hdr_t;

p67rs_hdr_t * p67rs_get_hdr_from_msg(const char * msg, int msgl);
p67rs_hdr_t * p67rs_get_hdr_from_msg(const char * msg, int msgl)
{
    if((unsigned int)msgl < sizeof(p67rs_hdr_t))
        return NULL;
    return (p67rs_hdr_t *)msg;
}

p67rs_err
p67rs_whandler_login(p67_conn_t * conn, const char * msg, int msgl);
p67rs_err
p67rs_whandler_login(p67_conn_t * conn, const char * msg, int msgl)
{
    p67rs_err err;

    printf(T_YELLOW "login:\n%.*s\n" T_WHITE, msgl-5, msg+5);

    char ack[P67_PUDP_HDR_SZ+2];

    if((err = p67_pudp_generate_ack(
                (unsigned char *)msg, msgl, 
                (const unsigned char *)"ok", 2, 
                ack)) != 0)
        return err;

    if((err = p67_net_must_write_conn(conn, ack, sizeof(ack))) != 0)
        return err;

    return 0;
}

p67rs_err p67rs_whandler_register(const char * msg, int msgl);
p67rs_err
p67rs_whandler_register(const char * msg, int msgl)
{
    printf("register:\n%.*s\n", msgl, msg);
    return 0;
}

p67_err
server_cb(p67_conn_t * conn, const char * const msg, const int msgl, void * args)
{
    const p67_addr_t * addr = p67_conn_get_addr(conn);
    (void)addr;
    struct p67rs_session * s = (struct p67rs_session *)args;
    (void)s;
    p67_proto_hdr_t * proto_hdr;
    p67rs_hdr_t * rs_hdr;
    int offset = 0;

    if((proto_hdr = p67_proto_get_hdr_from_msg(msg, msgl)) == NULL)
        goto err;
 
    switch(proto_hdr->h_val) {
    case P67_PROTO_PUDP_ACK:
        /*
            here will be handled incoming remote respones to requests sent by the rserver
        */
        break;
    case P67_PROTO_PUDP_URG:

        /*
            URG will also have message id inside. we dont need it so just skip it;
        */
        offset += sizeof(p67_pudp_hdr_t);
        if(offset >= msgl) goto err;
        
        if((rs_hdr = p67rs_get_hdr_from_msg(msg+offset, msgl-offset)) == NULL)
            goto err;

        offset += sizeof(*rs_hdr);
        if(offset >= msgl) goto err;

        switch(rs_hdr->path) {
        case P67RS_PATH_LOGIN:
            p67rs_whandler_login(conn, msg, msgl);
            break;
        case P67RS_PATH_REGISTER:
            p67rs_whandler_register(msg, msgl);
            break;
        default:
            goto err;
        }
        
        break;
        //return p67_pudp_handle_msg(conn, msg, msgl, NULL);
    case P67_PROTO_UNDEFINED:
        /*
            handle incoming request
        */
        break;
    case P67_PROTO_STREAM_DATA:
    default:
        goto err;
    }

    return 0;
    
err:
    return 0;
}

volatile int sessid = 0;


void * create_rs_session(void);
void * create_rs_session(void)
{
    struct p67rs_session * p = calloc(1, sizeof(struct p67rs_session));
    if(p == NULL) {
        p67_err_print_err("create client session: ", p67_err_eerrno);
        exit(2);
    }
    p->sessid=(sessid++);
    printf("creating session with id = %d\n", p->sessid);
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
    p67_net_config_val.c_auth = P67_NET_C_AUTH_TRUST_UNKOWN;
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

    getchar();
    
end:
    p67_lib_free();
    if(err != 0) p67rs_err_print_err("terminating main thread with error/s: ", err);
    return err == 0 ? 0 : 2;
}