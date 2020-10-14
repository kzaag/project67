#include <signal.h>
#include <string.h>
#include <unistd.h>

#include <p67/err.h>
#include <p67/log.h>
#include <p67/net.h>
#include <p67/dml/dml.h>
#include <p67/web/status.h>
#include <p67/web/tlv.h>
#include <p67/hashcntl.h>

#include <client/cli/cmd.h>
#include <client/cli/node.h>
#include <client/cli/call.h>

#define reset_opt() { optind = 1; }

typedef int (* p67_cmd_hndl)(
    p67_cmd_ctx_t * ctx, int argc, char ** argv);

struct p67_cmd_entry_handler {
    p67_cmd_hndl handler;
};

typedef struct p67_cmd_entry {
    char * command;
    size_t commandl;
    struct p67_cmd_entry_handler * e_handler;
    char __padd[P67_HASHCNTL_ENTRY_PADDING_SIZE];
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

static char __cmds[4096];
static int __cmdix = 0;

P67_CMN_NO_PROTO_ENTER
p67_err
p67_cmd_add(
P67_CMN_NO_PROTO_EXIT
    p67_hashcntl_t * ctx, char * name, p67_cmd_hndl hndl)
{
    p67_err err;
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
    err = p67_hashcntl_add(ctx, entry);
    if(err != 0) return err;
    if((sizeof(__cmds) - __cmdix) > strlen(name))
        __cmdix += snprintf(__cmds+__cmdix, sizeof(__cmds)-__cmdix, "%s ", name);
    return err;
}

P67_CMN_NO_PROTO_ENTER
int
p67_cmd_list_nodes(
P67_CMN_NO_PROTO_EXIT
    p67_cmd_ctx_t * ctx, int argc, char ** argvs)
{
    int flags = 0, o;
    reset_opt();    
    while((o = getopt(argc, argvs, "a")) != -1) {
        switch(o) {
        case 'a':
            flags |= P67_EXT_NODE_PRINT_FLAGS_ALL;
            break;
        }
    }
    p67_ext_node_print_all(flags);
    return 0;
}

P67_CMN_NO_PROTO_ENTER
int
p67_cmd_list_conn(
P67_CMN_NO_PROTO_EXIT
    p67_cmd_ctx_t * ctx, int argc, char ** argvs)
{
    p67_conn_print_all();
    return 0;
}

P67_CMN_NO_PROTO_ENTER
int
p67_cmd_remove_conn(
P67_CMN_NO_PROTO_EXIT
    p67_cmd_ctx_t * ctx, int argc, char ** argvs)
{
    if(argc < 2) {
        p67_log("Usage %s [host:port].\n", argvs[0]);
        return -1;
    }

    p67_addr_t * addr = p67_addr_new_parse_str(
        argvs[1], P67_SFD_TP_DGRAM_UDP);
    if(!addr) {
        p67_log("Couldnt create address.\n");
        return -1;
    }

    p67_err err = p67_net_shutdown(addr);
    p67_addr_free(addr);
    if(err) {
        p67_err_print_err("Couldnt shutdown connection: ", err);
        return -2;
    }

    return -err;
}

P67_CMN_NO_PROTO_ENTER
int
p67_cmd_node_op(
P67_CMN_NO_PROTO_EXIT
    p67_cmd_ctx_t * ctx, int argc, char ** argvs)
{
    char * name = NULL, * addrstr = NULL;
    const char * const usage = 
        "Usage: %s [operation] [-n name] [-a address]\n\t"
        "allowed operations:\n"
        "\trm            - remove existing node by -a address or -n name.\n"
        "\tcstart/cstop  - start/stop persistent connect and keepalive,\n"
        "\tup/down       - move node between states NODE/QUEUE ls,\n"
        "\tadd           - add new node using -n name and -a address\n"
        "\tls            - list all nodes\n"
        "\tprint         - print node information\n";
    if(argc < 2) {
        p67_log(usage, argvs[0]);
        goto end;
    }
    char * ops = argvs[1];
    int o, ret;

    if(strcmp(ops, "ls") == 0) {
        p67_ext_node_print_all(0);
        return 0;
    }

    reset_opt();
    while((o = getopt(argc, argvs, "n:a:")) != -1) {
        switch(o) {
        case 'n':
            name = p67_cmn_strdup(optarg);
            break;
        case 'a':
            addrstr = p67_cmn_strdup(optarg);
            break;
        default:
            break;
        }
    }

    ret = -1;
    
    if(!name && !addrstr) {
        p67_log(usage, argvs[0]);
        goto end;
    }

    
    if(strcmp(ops, "add") == 0) {
        p67_addr_t * addr = p67_addr_new_parse_str_udp(addrstr);
        if(!addr) {
            p67_log("Couldnt create address\n");
            goto end;
        }
        if(!p67_ext_node_insert(
                addr, NULL, P67_NODE_STATE_NODE, name)) {
            p67_log("Couldnt insert node\n");
            ret = -1;
            p67_addr_free(addr);
            goto end;
        }
        p67_addr_free(addr);
        ret = 0;
        goto end;
    }

    p67_node_t * n;

    if(name) {
        n = p67_ext_node_find_by_name(name);
    } else if(addrstr) {
        p67_addr_t * addr = p67_addr_new_parse_str_udp(addrstr);
        if(!addr) {
            p67_log("Couldnt parse address\n");
            goto end;
        }
        n = p67_node_lookup(addr);
        p67_addr_free(addr);
    }

    if(!n) {
        p67_log("Couldnt find node\n");
        goto end;
    }

    p67_err err = 0;

    if(strcmp(ops, "rm") == 0) {
        err = p67_ext_node_remove(n->trusted_addr);
    } else if(strcmp(ops, "cstart") == 0) {
        err = p67_ext_node_start_connect(
            n, ctx->local_addr, ctx->cred, ctx->p2p_cb_ctx);
    } else if(strcmp(ops, "cstop") == 0) {
        err = p67_ext_node_stop_connect(n);
    } else if(strcmp(ops, "up") == 0) {
        n->state = P67_NODE_STATE_NODE;
    } else if(strcmp(ops, "down") == 0) {
        n->state = P67_NODE_STATE_QUEUE;
    } else if(strcmp(ops, "print") == 0) {
        p67_ext_node_print(n, P67_EXT_NODE_PRINT_FLAGS_ALL);
    } else {
        p67_log(usage, argvs[0]);
        goto end;
    }

    if(err) {
        p67_err_print_err("Couldnt perform operation on node: ", err);
        goto end;
    }

    ret = 0;

end:
    free(addrstr);
    free(name);
    return ret;
}

P67_CMN_NO_PROTO_ENTER
int
p67_cmd_call_accept(
P67_CMN_NO_PROTO_EXIT
    p67_cmd_ctx_t * ctx, int argc, char ** argvs)
{
    if(argc < 2) {
        p67_log("Usage %s [username]\n", argvs[0]);
        return -p67_err_einval;
    }

    p67_call_entry_t * ce = p67_call_lookup(argvs[1]);
    if(!ce) {
        p67_log("cannot find specified call\n");
        return -1;
    }

    p67_err err = p67_web_tlv_respond_with_status(
        &ce->req, ce->server_addr, p67_web_status_ok);
    if(err) {
        p67_err_print_err("cannot respond to redirect server, reason: ", err);
        return -err;
    }

    err = p67_ext_node_insert_and_connect(
        ce->peer_addr, 
        NULL, 
        ce->username, 
        ctx->local_addr, ctx->cred, ctx->p2p_cb_ctx);

    if(err) {
        p67_err_print_err("cannot insert node, reason: ", err);
        return -err;
    }

    err = p67_call_remove(argvs[1]);
    if(err) {
        p67_err_print_err("cannot remove pending call, reason: ", err);
        return -err;
    }

    return err;
}

// P67_CMN_NO_PROTO_ENTER
// int
// p67_cmd_open_audio(
// P67_CMN_NO_PROTO_EXIT
//     p67_cmd_ctx_t * ctx, int argc, char ** argv)
// {
//     if(argc < 2) {
//         p67_log("must provide target name\n");
//         return 1;
//     }

//     p67_p2p_t * s = p67_p2p_cache_find_by_name(argv[1]);
//     if(!s) {
//         p67_log("didnt find requested user\n");
//         return 1;
//     }

//     p67_err err;

//     s->audio.i = p67_audio_create_i(NULL, NULL);
//     s->audio.o = p67_audio_create_o(NULL, NULL);
//     if((err = p67_qdp_create(&s->audio.qdp))) {
//         p67_err_print_err("qdp create returned error/s: ", err);
//         return -1;
//     }

//     if((err = p67_audio_start_write_qdp(&s->audio.i_sm, s->peer_addr, s->audio.i, 10))) {
//         p67_err_print_err("write qdp returned error/s: ", err);
//         return -1;
//     }
    
//     if((err = p67_audio_start_read_qdp(&s->audio.o_sm, s->audio.qdp, s->audio.o))) {
//         p67_err_print_err("read qdp returned error/s: ", err);
//         return -1;
//     }

//     return err;
// }

P67_CMN_NO_PROTO_ENTER
int
p67_cmd_redir_login(
P67_CMN_NO_PROTO_EXIT
    p67_cmd_ctx_t * ctx, int argc, char ** argvs)
{
    p67_err err;
    unsigned char msg[120];
    char * username = NULL, * password = NULL;
    int len = 120, reg_switch = 0, o, time_switch = 0;

    reset_opt();
    
    while((o = getopt(argc, argvs, "u:p:rt")) != -1) {
        switch(o) {
        case 'u':
            username = strdup(optarg);
            break;
        case 'p':
            password = strdup(optarg);
            break;
        case 'r':
            reg_switch = 1;
            break;
        case 't':
            time_switch = 1;
            break;
        default:
            p67_log(
                "usage: %s [OPTIONS]\n-u\tusername\n-p\tpassword\n-r\tregister and login\n-t\tperformance metrics\n", 
                argvs[0]);
            return -1;
        }
    }
    
    if(!username) {
        p67_log_set_term_char("username:");
        username = (char *)p67_log_read_term(NULL, NULL, 0);
        if(!username) {
            p67_log("Couldnt read username\n");
            p67_log_set_term_char(P67_LOG_TERM_ENC_SGN_STR_DEF);
            goto end;
        }
        username = strdup(username);
        p67_log_set_term_char(P67_LOG_TERM_ENC_SGN_STR_DEF);
    }
    if(!password) {
        p67_log_set_term_char("password:");
        p67_log_echo = 0;
        password = (char *)p67_log_read_term(NULL, NULL, 0);
        p67_log_echo = 1;
        if(!password) {
            p67_log("Couldnt read password\n");
            p67_log_set_term_char(P67_LOG_TERM_ENC_SGN_STR_DEF);
            goto end;
        }
        password = strdup(password);
        p67_log_set_term_char(P67_LOG_TERM_ENC_SGN_STR_DEF);
    }

    unsigned char * msgp = msg;
    int ix = 0;

    if(p67_pdp_generate_urg_for_msg(NULL, 0, msgp, len, 'l') == NULL)
        goto end;

    msgp += P67_PDP_URG_OFFSET;
    ix += P67_PDP_URG_OFFSET;
    
    if(ix >= len)
        goto end;

    if((err = p67_tlv_add_fragment(
                msgp, len-ix, (unsigned char *)"u", 
                (unsigned char *)username, 
                strlen(username) + 1)) < 0)
        goto end;
    ix += err;
    msgp+=err;

    if((err = p67_tlv_add_fragment(
                msgp, len-ix, (unsigned char *)"p", 
                (unsigned char *)password,
                strlen(password) + 1)) < 0)
        goto end;
    ix += err;
    msgp+=err;

    if(reg_switch) {
        if((err = p67_tlv_add_fragment(
                    msgp, len-ix, (unsigned char *)"r", 
                    NULL, 0)) < 0)
        goto end;
        ix += err;
        msgp+=err;
    }

    p67_async_t sig = P67_ASYNC_INTIIALIZER;

    p67_cmn_epoch_t start, end;

    if(time_switch) {
        p67_cmn_epoch_micro(&start);
    }

    const p67_pckt_t res[80];
    int resl = 80;

    if((err = p67_pdp_write_urg(
            ctx->ws_remote_addr, msg, ix, -1, &sig, (void **)&res, &resl)) != 0)
        goto end;

    p67_mutex_wait_for_change(&sig, 0, -1);

    if(time_switch) {
        p67_cmn_epoch_micro(&end);
        p67_log("elapsed: %lu microseconds\n", end-start);
    }

    if(sig == P67_PDP_EVT_GOT_ACK) {
        char buff[P67_WEB_TLV_STATUS_BUFFL];
        if((err = p67_web_tlv_status_str(res, resl, buff, P67_WEB_TLV_STATUS_BUFFL)) != 0)
            goto end;
        p67_log("%s\n", buff);
    } else {
        char c[32];
        p67_log("%s\n", p67_pdp_evt_str(c, sizeof(c), sig));
        goto end;
    }

end:
    free(username);
    free(password);
    return 0;
}

P67_CMN_NO_PROTO_ENTER
int
p67_cmd_sleep(
P67_CMN_NO_PROTO_EXIT
    p67_cmd_ctx_t * ctx, int argc, char ** argvs)
{
    int t = 0;
    p67_err err;
    if(argc < 2 || (t = atoi(argvs[1])) <= 0) {
        return 1;
    }
    if((err = p67_cmn_sleep_s(t)) != 0) {
        p67_err_print_err("sleep: ", err);
        return 2;
    }
    return 0;
}

P67_CMN_NO_PROTO_ENTER
int 
p67_cmd_text_chan(
P67_CMN_NO_PROTO_EXIT
    p67_cmd_ctx_t * ctx, int argc, char ** argv)
{
    const char * const usage = "usage: %s [TARGET_NODE_NAME] [-f]\n";

    if(argc < 2) {
        p67_log(usage);
        return -1;
    }

    char * target_name = argv[1];
    int o, force_flag = 0;
    reset_opt();
    while((o = getopt(argc, argv, "f")) != -1) {
        switch(o) {
        case 'f':
            force_flag = 1;
            break;
        default:
            p67_log(usage);
            return -1;
        }
    }

    p67_addr_t * dst;
    //char * username;

    {
        p67_node_t * node = p67_ext_node_find_by_name(target_name);
        if(!node) {
            printf("didnt find requested user\n");
            return 1;
        }
        if(node->state == P67_NODE_STATE_QUEUE && !force_flag) {
            p67_log("THIS CONNECTION CANT BE TRUSTED\n"
                    "Dont send any relevant data in this channel.\n"
                    "You can use -f (force) flag to ignore this error,\n"
                    "or set node state to NODE once you decide to trust them.\n");
            return -2;
        }
        dst = p67_addr_ref_cpy(node->trusted_addr);
        //username = p67_cmn_strdup(s->peer_username);
    }

    //  1   strlen(target_name[1])   1
    //  >  {peer_username}   \0
    char tc[1+strlen(target_name)+1];
    tc[0] = '>';
    memcpy(tc+1, target_name, sizeof(tc)-1);
    tc[sizeof(tc)-1] = 0;

    p67_log_set_term_char(tc);

    p67_err err;
    const int __buffl = 72;
    unsigned char __buff[__buffl];
    /* 
        have some space allocated on the left side of buffer
        so we can write network header into it 
        without having to copy whole buffer.
    */
    const int noffset = sizeof(p67_pdp_urg_hdr_t);
    const int buffl = __buffl - noffset;
    int cbuffl;
    unsigned char * buff = __buff + noffset;

    while(1) {

        cbuffl = buffl;

        err = p67_log_read_term_in_buf((char *)buff, &cbuffl, 500);
        if(err) {
            if(err != p67_err_etime)
                p67_err_print_err(NULL, err);
            if(p67_thread_sm_stop_requested(ctx->tsm)) {
                p67_log_set_term_char(P67_LOG_TERM_ENC_SGN_STR_DEF);
                return 0;
            }
            continue;
        }

        // do {
        //     write(1, P67_LOG_TERM_ENC_SGN_STR, P67_LOG_TERM_ENC_SGN_STR_LEN);
        // } while((ix = read(0, buff, buffl-1)) <= 1);

        if(!p67_pdp_generate_urg_for_msg(NULL, 0, __buff, noffset, 3)) {
            printf("couldnt generate urg header for message\n");
            return 2;
        }

        if((err = p67_pdp_write_urg(
                dst, 
                __buff, buffl+noffset, 
                1000, NULL, NULL, NULL)) != 0) {
            p67_err_print_err("couldnt write: ", err);
        }
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
    //p67_async_t conn_sig = 0;

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

    err = p67_ext_node_insert_and_connect(
        addr, NULL, username, ctx->local_addr, ctx->cred, ctx->p2p_cb_ctx);

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
    int msgix = 0, tmpix = sizeof(msg), o;
    char * message, * username;
    p67_pdp_urg_hdr_t * u = (p67_pdp_urg_hdr_t *)msg;
    p67_err err;

    msgp = msg;

    if(argc < 2) {
        p67_log("Usage: %s [username] [OPTIONS]\n", argv[0]);
        return 1;
    }

    username = argv[1];

    reset_opt();
    while((o = getopt(argc, argv, "m:")) != -1) {
        switch(o) {
        case 'm':
            message = optarg;
            break;
        }
    }

    if(p67_pdp_generate_urg_for_msg(NULL, 0, msgp, msgl, 'c') == NULL)
        return p67_err_einval;

    msgp += P67_PDP_URG_OFFSET;
    msgix += P67_PDP_URG_OFFSET;
    
    if(msgix >= msgl)
        return p67_err_enomem;

    if((err = p67_tlv_add_fragment(
            msgp, msgl-msgix, 
            (unsigned char *)"U", 
            (unsigned char *)username, 
            strlen(username) + 1)) < 0)
        return -err;
    msgix += err;
    msgp+=err;

    if(message) {
        if((err = p67_tlv_add_fragment(
                msgp, msgl-msgix, 
                (unsigned char *)"m", 
                (unsigned char *)message, 
                strlen(message)+1)) < 0)
            return -err;
        msgix += err;
        msgp+=err;
    }

    if((err = p67_pdp_write_urg(
            ctx->ws_remote_addr, 
            msg, msgix, 60000, &sig, msg, &tmpix)) != 0) {
        return err;
    }

    while(1) {
        p67_mutex_wait_for_change(&sig, 0, 100);
        if(p67_thread_sm_stop_requested(ctx->tsm)) {
            err = p67_pdp_urg_remove(
                ctx->ws_remote_addr, p67_cmn_ntohs(u->urg_mid), NULL, 0, 0);
            if(err) {
                p67_err_print_err("Cancel request returned error/s: ", err);
            }
            return err;
        }
        if(sig) {
            break;
        }
    }
    msgix = tmpix;

    if(sig == P67_PDP_EVT_GOT_ACK) {
        if((err = p67_cmd_process_call_res(ctx, msg, msgix, username)) != 0) {
            p67_err_print_err("Process call returned error/s: ", err);
        }
    } else {
        char c[P67_PDP_EVT_STR_LEN];
        printf("%s\n", p67_pdp_evt_str(c, sizeof(c), sig));
    }

    return 0;
}

P67_CMN_NO_PROTO_ENTER
int 
p67_cmd_echo(
P67_CMN_NO_PROTO_EXIT
    p67_cmd_ctx_t * ctx, int argc, char ** argv)
{
    int i;
    //printf("%d\n",_argc);
    for(i = 0; i < argc; i++) {
        printf("%d: (%lu) %s\n", i, strlen(argv[i]), argv[i]);
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
    printf("%s\n", __cmds);
    return 0;
}

P67_CMN_NO_PROTO_ENTER
int
p67_cmd_list_pending_calls(
P67_CMN_NO_PROTO_EXIT
    p67_cmd_ctx_t * ctx, int argc, char ** argv)
{
    p67_call_print_all();
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
    if((err = p67_cmd_add(ret, "login", p67_cmd_redir_login)) != 0) return NULL;
    if((err = p67_cmd_add(ret, "text", p67_cmd_text_chan)) != 0) return NULL;
    if((err = p67_cmd_add(ret, "sleep", p67_cmd_sleep)) != 0) return NULL;
    //if((err = p67_cmd_add(ret, "term", p67_cmd_terminate_by_name)) != 0) return NULL;
    //if((err = p67_cmd_add(ret, "audio", p67_cmd_open_audio)) != 0) return NULL;
    if((err = p67_cmd_add(ret, "lscon", p67_cmd_list_conn)) != 0) return NULL;
    if((err = p67_cmd_add(ret, "lsnode", p67_cmd_list_nodes)) != 0) return NULL;
    if((err = p67_cmd_add(ret, "lscall", p67_cmd_list_pending_calls)) != 0) return NULL;
    if((err = p67_cmd_add(ret, "node", p67_cmd_node_op)) != 0) return NULL;
    if((err = p67_cmd_add(ret, "rmcon", p67_cmd_remove_conn)) != 0) return NULL;
    if((err = p67_cmd_add(ret, "accept", p67_cmd_call_accept)) != 0) return NULL;

    return ret;
}

int
p67_cmd_execute(
    p67_hashcntl_t * commands, p67_cmd_ctx_t * ctx, int argc, char ** argv)
{
    if(argc < 1)
        return -1;
    p67_hashcntl_entry_t * entry;
    int ret;
    entry = p67_hashcntl_lookup(commands, (unsigned char *)argv[0], strlen(argv[0]));
    if(entry) {
        ret = ((struct p67_cmd_entry_handler *)entry->value)->handler(ctx, argc, argv);
        //p67_thread_sm_stop_notify(ctx->tsm);
        //return ret;
    } else {
        printf("command: \"%s\" not found.\n", argv[0]);
        ret = -1;
    }

    return ret;
}
