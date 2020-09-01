#include <signal.h>
#include <string.h>

#include <p67/err.h>
#include <p67/net.h>
#include <p67/dml/dml.h>
#include <p67/web/status.h>
#include <p67/web/tlv.h>
#include <p67/hashcntl.h>

#include <client/cli/p2p.h>
#include <client/cli/cmd.h>

typedef int (* p67_cmd_hndl)(
    p67_cmd_ctx_t * ctx, int argc, char ** argv);

struct p67_cmd_entry_handler {
    p67_cmd_hndl handler;
};

typedef struct p67_cmd_entry {
    char * command;
    size_t commandl;
    struct p67_cmd_entry_handler * e_handler;
    char __padd[sizeof(size_t)+sizeof(p67_hashcntl_entry_t *)];
} p67_cmd_entry_t;

p67_cmn_static_assert_size(p67_cmd_entry_t, p67_hashcntl_entry_t);

/*
    if building on architecture which doesnt support same size pointer
    you must properly implement p67_cmd_hndl as value ptr in p67_cmd_entry
p67_cmn_static_assert(
    uchar_ptr_sz, sizeof(unsigned char *) == sizeof(p67_cmd_hndl));
*/


P67_CMN_NO_PROTO_ENTER
void
p67_cmd_free(
P67_CMN_NO_PROTO_EXIT
    p67_hashcntl_entry_t * e)
{
    free(e);
}

P67_CMN_NO_PROTO_ENTER
p67_err
p67_cmd_add(
P67_CMN_NO_PROTO_EXIT
    p67_hashcntl_t * ctx, char * name, p67_cmd_hndl hndl)
{
    int namelen = strlen(name);
    p67_hashcntl_entry_t * entry = malloc(
        sizeof(p67_hashcntl_entry_t) + 
        namelen + 
        sizeof(struct p67_cmd_entry_handler));
    if(!entry)
        return p67_err_eerrno;
    char * key = ((char *)entry) + sizeof(p67_hashcntl_entry_t);
    memcpy(key, name, namelen);
    entry->key = (unsigned char *)key;
    entry->keyl = namelen;
    entry->next = NULL;
    entry->value = (unsigned char *)key+namelen;
    entry->valuel = 0;
    struct p67_cmd_entry_handler * eh = (struct p67_cmd_entry_handler *)entry->value;
    eh->handler = hndl;
    return p67_hashcntl_add(ctx, entry);
}

P67_CMN_NO_PROTO_ENTER
int
p67_cmd_login(
P67_CMN_NO_PROTO_EXIT
    p67_cmd_ctx_t * ctx, int argc, char ** argvs)
{
    p67_err err;
    unsigned char msg[120];
    int len = 120;

    unsigned char * msgp = msg;
    int ix = 0;

    if(p67_pdp_generate_urg_for_msg(NULL, 0, msgp, len, 'l') == NULL)
        return p67_err_einval;

    msgp += P67_PDP_URG_OFFSET;
    ix += P67_PDP_URG_OFFSET;
    
    if(ix >= len)
        return p67_err_enomem;

    const int buffl = 31;
    unsigned char buff[buffl + 1];
    int bl = 0;
    char tmp;

    if(argc < 2) {
        printf("username: ");
        while((tmp = getchar()) != EOF && tmp != '\n') {
            if(bl >= (buffl - 1)) break;
            buff[bl++] = tmp;
        }
    }
    buff[bl++] = 0;

    if((err = p67_tlv_add_fragment(
                msgp, len-ix, (unsigned char *)"u", 
                argc < 2 ? buff : (unsigned char *)argvs[1], 
                argc < 2 ? bl : strlen(argvs[1]) + 1)) < 0)
        return -err;
    ix += err;
    msgp+=err;

    if(argc < 3) {
        printf("password: ");
        bl = 0;
        while((tmp = getchar()) != EOF && tmp != '\n') {
            if(bl >= (buffl - 1)) break;
            buff[bl++] = tmp;
        }
    }
    buff[bl++] = 0;

    if((err = p67_tlv_add_fragment(
                msgp, len-ix, (unsigned char *)"p", 
                argc < 3 ? buff : (unsigned char *)argvs[2], 
                argc < 3 ? bl : strlen(argvs[2]) + 1)) < 0)
        return -err;
    ix += err;
    msgp+=err;

    p67_async_t sig = P67_ASYNC_INTIIALIZER;

    // p67_epoch_t start, end;

    // p67_cmn_time_ms(&start);

    const p67_pckt_t res[80];
    int resl = 80;

    if((err = p67_pdp_write_urg(
            ctx->ws_remote_addr, msg, ix, -1, &sig, (void **)&res, &resl)) != 0)
        return err;

    p67_mutex_wait_for_change(&sig, 0, -1);

    // p67_cmn_time_ms(&end);

    // printf(
    //     "login took %llu ms. PDP status is: %s\n",
    //     end-start,
    //     p67_pdp_evt_str(buff, sizeof(buff), sig));

    if(sig == P67_PDP_EVT_GOT_ACK) {
        char buff[P67_WEB_TLV_STATUS_BUFFL];
        if((err = p67_web_tlv_status_str(res, resl, buff, P67_WEB_TLV_STATUS_BUFFL)) != 0)
            return err;
        p67_log("%s\n", buff);
    } else {
        char c[32];
        p67_log("%s\n", p67_pdp_evt_str(c, sizeof(c), sig));
        return p67_err_eagain;
    }

    return 0;
}

P67_CMN_NO_PROTO_ENTER
p67_err
p67_cmd_process_call_res(
P67_CMN_NO_PROTO_EXIT
    const p67_cmd_ctx_t * const ctx,
    const p67_pckt_t * const msg,
    const int msgl,
    const char * username)
{
    if(!p67_dml_parse_hdr(msg, msgl, NULL)) {
        return p67_err_epdpf;
    }

    const char * hostname, * service;
    const p67_pckt_t * payload = msg + sizeof(p67_pdp_ack_hdr_t);
    int payloadl = msgl - sizeof(p67_pdp_ack_hdr_t);
    const p67_tlv_header_t * tlv_hdr;
    const p67_pckt_t * tlv_value;
    p67_addr_t * addr;
    p67_err err;
    p67_web_status res_status;
    int tlv_status = 0;

    while((err = p67_tlv_next(
            &payload, &payloadl, &tlv_hdr, &tlv_value)) == 0) {
        switch(*tlv_hdr->tlv_key) {
        case 's':
            tlv_value = p67_tlv_get_arr(tlv_hdr, tlv_value, 2);
            if(!tlv_value)
                break;
            res_status = p67_cmn_ntohs(*(p67_web_status*)tlv_value);
            tlv_status |= 1;
            break;
        case 'A':
            hostname = p67_tlv_get_cstr(tlv_hdr, tlv_value);
            if(!hostname)
                break;
            tlv_status |= 2;
            break;
        case 'P':
            service = p67_tlv_get_cstr(tlv_hdr, tlv_value);
            if(!service)
                break;
            tlv_status |= 4;
            break;
        }
    }
    
    if(err != p67_err_eot || !(tlv_status & 1)) {
        return err;
    }

    if(res_status != p67_web_status_ok) {
        char c[P67_WEB_TLV_STATUS_BUFFL];
        p67_web_status_str(res_status, c, P67_WEB_TLV_STATUS_BUFFL);
        printf("%s\n", c);
        return 0;
    }

    if(tlv_status != 7) {
        return p67_err_epdpf;
    }

    if(!(addr = p67_addr_new())) {
        return p67_err_eerrno;
    }

    if((err = p67_addr_set_host_udp(addr, hostname, service)) != 0) {
        p67_addr_free(addr);
        return err;
    }

    if(!p67_p2p_cache_add(addr, (unsigned char *)username, strlen(username))) {
        p67_addr_free(addr);
        return p67_err_einval;
    }
    
    err = p67_p2p_cache_accept_by_name(
        ctx->local_addr, ctx->cred, ctx->p2p_cb_ctx, username);
    
    p67_addr_free(addr);

    return err;
}

P67_CMN_NO_PROTO_ENTER
int 
p67_cmd_call(
P67_CMN_NO_PROTO_EXIT
    p67_cmd_ctx_t * ctx, int argc, char ** argv)
{
    unsigned char * msgp;
    unsigned char msg[P67_DML_SAFE_PAYLOAD_SIZE];
    p67_async_t sig = P67_ASYNC_INTIIALIZER;
    const int msgl = 120;
    int msgix = 0, tmpix = sizeof(msg);
    p67_err err;

    msgp = msg;

    if(argc < 2) {
        printf("must provide target\n");
        return 1;
    }

    if(p67_pdp_generate_urg_for_msg(NULL, 0, msgp, msgl, 'c') == NULL)
        return p67_err_einval;

    msgp += P67_PDP_URG_OFFSET;
    msgix += P67_PDP_URG_OFFSET;
    
    if(msgix >= msgl)
        return p67_err_enomem;

    //printf("calling...\n");

    if((err = p67_tlv_add_fragment(
            msgp, msgl-msgix, (unsigned char *)"U", (unsigned char *)argv[1], strlen(argv[1]) + 1)) < 0)
        return -err;
    msgix += err;
    msgp+=err;

    if((err = p67_tlv_add_fragment(
            msgp, msgl-msgix, (unsigned char *)"m", (unsigned char *)"i love you", 11)) < 0)
        return -err;
    msgix += err;
    msgp+=err;

    if((err = p67_pdp_write_urg(
            ctx->ws_remote_addr, 
            msg, msgix, 60000, &sig, msg, &tmpix)) != 0)
        return err;

    p67_mutex_wait_for_change(&sig, 0, -1);

    msgix = tmpix;

    if(sig == P67_PDP_EVT_GOT_ACK) {
        // char c[P67_WEB_TLV_STATUS_BUFFL];
        // if((err = p67_web_tlv_status_str(msg, msgix, c, sizeof(c))) != 0)
        //     return err;
        // printf("%s\n", c);
        if((err = p67_cmd_process_call_res(ctx, msg, msgix, argv[1])) != 0) {
            p67_err_print_err("Process call returned error/s: ", err);
        }
    } else {
        char c[P67_PDP_EVT_STR_LEN];
        printf("%s\n", p67_pdp_evt_str(c, sizeof(c), sig));
    }

    return 0;
}

P67_CMN_NO_PROTO_ENTER
int p67_cmd_echo(
P67_CMN_NO_PROTO_EXIT
    p67_cmd_ctx_t * ctx, int argc, char ** argv)
{
    int i;
    //printf("%d\n",_argc);
    for(i = 0; i < argc; i++) {
        printf("(%lu) %s\n",strlen(argv[i]), argv[i]);
    }
    return 0;
}

P67_CMN_NO_PROTO_ENTER
int
p67_cmd_exit(
P67_CMN_NO_PROTO_EXIT
    p67_cmd_ctx_t * ctx, int argc, char ** argv)
{
    return raise(SIGINT);
}

P67_CMN_NO_PROTO_ENTER
int
p67_cmd_help(
P67_CMN_NO_PROTO_EXIT
    p67_cmd_ctx_t * ctx, int argc, char ** argv)
{
    printf("?, help, echo, exit, call, login\n");
    return 0;
}

p67_hashcntl_t *
p67_cmd_new(void)
{
    p67_err err;
    p67_hashcntl_t * ret = p67_hashcntl_new(0, p67_cmd_free, NULL);
    if(!ret) return NULL;
    
    if((err = p67_cmd_add(ret, "?", p67_cmd_help)) != 0) return NULL;
    if((err = p67_cmd_add(ret, "help", p67_cmd_help)) != 0) return NULL;
    if((err = p67_cmd_add(ret, "echo", p67_cmd_echo)) != 0) return NULL;
    if((err = p67_cmd_add(ret, "exit", p67_cmd_exit)) != 0) return NULL;
    if((err = p67_cmd_add(ret, "call", p67_cmd_call)) != 0) return NULL;
    if((err = p67_cmd_add(ret, "login", p67_cmd_login)) != 0) return NULL;

    return ret;
}

int
p67_cmd_execute(
    p67_hashcntl_t * commands, p67_cmd_ctx_t * ctx, int argc, char ** argv)
{
    if(argc < 1)
        return -1;
    p67_hashcntl_entry_t * entry;
    entry = p67_hashcntl_lookup(commands, (unsigned char *)argv[0], strlen(argv[0]));
    if(entry) {
        return ((struct p67_cmd_entry_handler *)entry->value)->handler(ctx, argc, argv);
    } else {
        printf("command: \"%s\" not found.\n", argv[0]);
        return -1;
    }
}