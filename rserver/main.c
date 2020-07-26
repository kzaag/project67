#include <stdio.h>
#include <stdlib.h>
#include <p67/p67.h>
#include <string.h>
#include <limits.h>

#include "bwt.h"
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

p67rs_err
p67rs_whandler_login(
    p67_conn_t * conn, 
    const unsigned char * const msg, int msgl,
    const unsigned char * payload, int payload_len);
p67rs_err
p67rs_whandler_login(
    p67_conn_t * conn, 
    const unsigned char * const msg, int msgl,
    const unsigned char * payload, int payload_len)
{
    p67rs_err err = 0;
    const unsigned char max_credential_length = 128;
    unsigned char username[max_credential_length+1], password[max_credential_length+1];
    unsigned char tmp[max_credential_length], key[2];
    unsigned char cbufl;
    unsigned char ackmsg[P67_TLV_HEADER_LENGTH+1];
    char ack[sizeof(p67_pudp_ack_hdr_t) + sizeof(ackmsg)];
    int state = 0;

    while(1) {

        cbufl = max_credential_length;

        if((err = p67_tlv_get_next_fragment(&payload, &payload_len, key, tmp, &cbufl)) < 0) {
            err=-err;
            goto end;
        }

        switch(key[0]) {
        case 'u':
            memcpy(username, tmp, cbufl);
            username[cbufl] = 0;
            state++;
            break;
        case 'p':
            memcpy(password, tmp, cbufl);
            password[cbufl] = 0;
            state++;
            break;
        default:
            err = p67_err_etlvf;
            goto end;
        }

        if(state == 2)
            break;
    }

end:
    if(err == 0) {
        if(p67_tlv_add_fragment(
                ackmsg, sizeof(ackmsg), (unsigned char *)"l", (unsigned char *)"1", 1) < 0)
            return p67_err_einval;
    } else {
        if(p67_tlv_add_fragment(
                ackmsg, sizeof(ackmsg), (unsigned char *)"l", (unsigned char *)"0", 1) < 0)
            return p67_err_einval;
    }

    if((err = p67_pudp_generate_ack(
            msg, msgl, 
            ackmsg, sizeof(ackmsg), 
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

p67rs_err
p67rs_handle_message(
    p67_conn_t * conn,
    const unsigned char * const msg, const int msgl,
    const unsigned char * payload, int payloadl);
p67rs_err
p67rs_handle_message(
    p67_conn_t * conn,
    const unsigned char * const msg, const int msgl,
    const unsigned char * payload, int payloadl)
{
    p67rs_err err;
    unsigned char command_key[2], nobytes = payloadl;

    if((err = p67_tlv_get_next_fragment(
                &payload, 
                &payloadl, 
                command_key, 
                NULL, 
                &nobytes)) != 0)
        return err;

    if(nobytes != 0) {
        printf(
            "WARN in handle message, "\
                "expected path specifier to be 0 bytes long. Got: %d.\n",
            nobytes);
    }

    switch(command_key[0]) {
    case 'l':
        return p67rs_whandler_login(conn, msg, msgl, payload, payloadl);
    case 'r':
    default:
        return p67_err_einval;
    }
}

p67_err
server_cb(p67_conn_t * conn, const char * const msg, const int msgl, void * args)
{
    const p67_addr_t * addr = p67_conn_get_addr(conn);
    (void)addr;
    struct p67rs_session * s = (struct p67rs_session *)args;
    (void)s;
    p67rs_err err;
    p67_pudp_all_hdr_t allhdr;

    if((err = p67_pudp_parse_msg_hdr(
                (unsigned char *)msg, msgl, 
                (p67_pudp_hdr_t *)&allhdr, 
                &(int){sizeof(allhdr)})) != 0)
        return err;
 
    switch(allhdr.hdr.hdr_type) {
    case P67_PUDP_HDR_ACK:
        break;
    case P67_PUDP_HDR_DAT:
        break;
    case P67_PUDP_HDR_URG:
        if((err = p67rs_handle_message(
                    conn, 
                    (const unsigned char *)msg, msgl, 
                    (unsigned char *)msg+sizeof(p67_pudp_urg_hdr_t), 
                    msgl-sizeof(p67_pudp_urg_hdr_t))) != 0)
            p67rs_err_print_err("Handle message returned error/s: ", err);
        break;
    default:
        break;
    }

    return 0;
}

volatile int sessid = 0;

void * create_rs_session(void);
void * create_rs_session(void)
{
    struct p67rs_session * p = calloc(1, sizeof(struct p67rs_session));
    if(p == NULL) {
        p67_err_print_err("ERR in create client session: ", p67_err_eerrno);
        exit(2);
    }
    p->sessid=(sessid++);
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