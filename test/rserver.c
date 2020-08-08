#include <p67/p67.h>
#include <stdlib.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>

#define T_YELLOW "\033[33m"
#define T_WHITE "\033[0m"

p67_err
print_status(const p67_tlv_header_t * header, const unsigned char * value)
{
    uint16_t err;

    if(header->key[0] != 's' || header->vlength != sizeof(err)) {
        printf("Unkown status format\n");
        return 0;
    }

    err = p67_cmn_ntohs(*(uint16_t *)value);

    printf("response status: %u.\n", err);

    return 0;
}

p67_err
process_message(p67_conn_t * conn, const char * const msg, const int msgl, void * args)
{
    // const p67_addr_t * addr = p67_conn_get_addr(conn);
    // p67_err err;
    // const p67_dml_hdr_store_t * hdr;

    // if((hdr = p67_dml_parse_hdr((unsigned char *)msg, msgl, NULL)) == NULL)
    //     return err;

    // const unsigned char * msgp = (unsigned char *)(msg + sizeof(*hdr));
    // const unsigned char * value;
    // const p67_tlv_header_t * header;
    // int msgpl = msgl-sizeof(*hdr);
    // uint8_t ix;

    // if(hdr->cmn.cmn_utp != 0)
    //     p67_dml_pretty_print(msg, msgl);

    // switch(hdr->cmn.cmn_stp) {
    // case P67_DML_STP_PDP_ACK:
    //     while((err = p67_tlv_next(&msgp, &msgpl, &header, &value)) == 0) {
        
    //         switch(header->key[0]) {
    //         case 's':
    //             print_status(header, value);
    //             break;
    //         case 'b':
    //             printf("---- begin BWT token: (%d bytes) ----\n", header->vlength);
    //             for(ix = 0; ix < header->vlength; ix++) {
    //                 printf("%02x", value[ix] & 0xff);
    //                 if(ix > 0 && (ix % 14) == 0)
    //                     printf("\n");
    //             }
    //             printf("\n----- end BWT token -----\n");
    //             break;
    //         }
    //     }     
        
    //     if(err == p67_err_eot) {
    //         err = 0;
    //         break;
    //     }
    //     err = p67_err_etlvf;
    // default:
    //     err = p67_err_epdpf;
    //     return 0;
    // }

    // if(err != 0)
    //     p67_err_print_err("process message: ", err);

    return p67_dml_handle_msg(conn, msg, msgl, NULL);
}
int
login(p67_conn_pass_t * pass, int argc, char ** argvs)
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

    // if((err = p67_tlv_add_fragment(msgp, len-ix, "l", NULL, 0)) < 0)
    //     return -err;
    // ix += err;
    // msgp+=err;

    char buff[32];
    int bl = 0;
    char tmp;

    if(argc < 2) {
        printf("username: ");
        while((tmp = getchar()) != EOF && tmp != '\n') {
            if(bl >= (sizeof(buff) - 1)) break;
        buff[bl++] = tmp;
        }
    }

    if(bl < 1) return p67_err_einval;

    if((err = p67_tlv_add_fragment(msgp, len-ix, "u\0", argc > 1 ? argvs[1] : buff, bl)) < 0)
        return -err;
    ix += err;
    msgp+=err;

    if(argc < 3) {
        printf("password: ");
        bl = 0;
        while((tmp = getchar()) != EOF && tmp != '\n') {
            if(bl >= (sizeof(buff) - 1)) break;
            buff[bl++] = tmp;
        }
    }

    if(bl < 1) return p67_err_einval;

    if((err = p67_tlv_add_fragment(msgp, len-ix, "p\0", argc > 2 ? argvs[2] : buff, bl)) < 0)
        return -err;
    ix += err;
    msgp+=err;

    p67_async_t sig = P67_ASYNC_INTIIALIZER;

    // p67_epoch_t start, end;

    // p67_cmn_time_ms(&start);

    char * res;
    const unsigned char * resptr;
    int resl;

    if((err = p67_pdp_write_urg(&pass->remote, msg, ix, -1, &sig, (void **)&res, &resl)) != 0)
        return err;

    p67_mutex_wait_for_change(&sig, 0, -1);

    // p67_cmn_time_ms(&end);

    // printf(
    //     "login took %llu ms. PDP status is: %s\n",
    //     end-start,
    //     p67_pdp_evt_str(buff, sizeof(buff), sig));

    if(sig == P67_PDP_EVT_GOT_ACK) {
        //p67_dml_pretty_print(res, resl);
        const p67_tlv_header_t * tlv_hdr;
        const unsigned char * value;
        resptr = res;
        resptr += sizeof(p67_pdp_ack_hdr_t);
        resl -= sizeof(p67_pdp_ack_hdr_t);
        if((err = p67_tlv_next(
                &resptr, &resl, 
                &tlv_hdr, &value)) != 0)
            return err;
        if(tlv_hdr->key[0] != 's' || tlv_hdr->vlength != 2)
            return p67_err_etlvf;
        if((err = p67_tlv_pretty_print_fragment(tlv_hdr, value)) != 0)
            return err;
        uint16_t werr = p67_cmn_ntohs(*(uint16_t *)value);
        if(werr != 0)
            return p67_err_eagain;
    } else {
        char c[32];
        printf("%s\n", p67_pdp_evt_str(c, sizeof(c), sig));
        return p67_err_eagain;
    }


    return 0;
}

int 
call(p67_conn_pass_t * pass, int argc, char ** argv)
{
    p67_err err;
    unsigned char msg[120];
    int len = 120;

    unsigned char * msgp = msg;
    int ix = 0;

    if(argc < 2) {
        printf("must provide target\n");
        return 1;
    }

    if(p67_pdp_generate_urg_for_msg(NULL, 0, msgp, len, 'c') == NULL)
        return p67_err_einval;

    msgp += P67_PDP_URG_OFFSET;
    ix += P67_PDP_URG_OFFSET;
    
    if(ix >= len)
        return p67_err_enomem;

    printf("calling...\n");

    if((err = p67_tlv_add_fragment(msgp, len-ix, "N", argv[1], strlen(argv[1]))) < 0)
        return -err;
    ix += err;
    msgp+=err;

    if((err = p67_tlv_add_fragment(
            msgp, len-ix, "h", "some hint", sizeof("some hint")-1)) < 0)
        return -err;
    ix += err;
    msgp+=err;

    p67_async_t sig = P67_ASYNC_INTIIALIZER;

    // p67_epoch_t start, end;

    // p67_cmn_time_ms(&start);

    const unsigned char * res, * resptr;
    int resl;

    if((err = p67_pdp_write_urg(
            &pass->remote, msg, ix, -1, &sig, (void **)&res, &resl)) != 0)
        return err;

    p67_mutex_wait_for_change(&sig, 0, 20000);

    //p67_cmn_time_ms(&end);

    if(sig == P67_PDP_EVT_GOT_ACK) {
        //p67_dml_pretty_print(res, resl);
        const p67_tlv_header_t * tlv_hdr;
        const unsigned char * value;
        resptr = res;
        resptr += sizeof(p67_pdp_ack_hdr_t);
        resl -= sizeof(p67_pdp_ack_hdr_t);
        if((err = p67_tlv_next(
                &resptr, &resl, 
                &tlv_hdr, &value)) != 0)
            return err;
        if(tlv_hdr->key[0] != 's' || tlv_hdr->vlength != 2)
            return p67_err_etlvf;
        if((err = p67_tlv_pretty_print_fragment(tlv_hdr, value)) != 0)
            return err;
        uint16_t werr = p67_cmn_ntohs(*(uint16_t *)value);
        if(werr != 0)
            return p67_err_eagain;
    } else {
        char c[32];
        printf("%s\n", p67_pdp_evt_str(c, sizeof(c), sig));
    }

    return 0;
}

void
finish(int sig)
{
    p67_lib_free();
    raise(sig);
}

int echo(p67_conn_pass_t * ctx, int argc, char ** argv)
{
    int i;
    //printf("%d\n",_argc);
    for(i = 0; i < argc; i++) {
        printf("(%lu) %s\n",strlen(argv[i]), argv[i]);
    }
}

int c_exit(p67_conn_pass_t * ctx, int argc, char ** argv)
{
    raise(SIGINT);
}

void
free_command(p67_hashcntl_entry_t * e)
{
    free(e);
}

typedef int (* command_hndl)(p67_conn_pass_t * ctx, int argc, char ** argv);

p67_err
add_command(p67_hashcntl_t * ctx, char * name, command_hndl hndl)
{
    int namelen = strlen(name);
    p67_hashcntl_entry_t * entry = malloc(sizeof(p67_hashcntl_entry_t) + namelen);
    if(!entry)
        return p67_err_eerrno;
    char * key = ((char *)entry) + sizeof(p67_hashcntl_entry_t);
    memcpy(key, name, namelen);
    entry->key = key;
    entry->keyl = namelen;
    entry->next = NULL;
    entry->value = (char *)hndl;
    entry->valuel = 0;
    return p67_hashcntl_add(ctx, entry);
}

struct command_entry {
    char * command;
    size_t commandl;
    command_hndl handler;
    char __padd[sizeof(size_t)+sizeof(p67_hashcntl_entry_t *)];
};

p67_cmn_static_assert(
    sizeof(struct command_entry) == sizeof(p67_hashcntl_entry_t));
/*
    this is neccesary to use function pointers directly in hash entries.
    if building on cpu arch whch doesnt support it,
    then you must replace all assignments and reads from entries.
*/
p67_cmn_static_assert(sizeof(unsigned char *) == sizeof(command_hndl));

int
main(int argc, char ** argv)
{
    p67_conn_pass_t pass = P67_CONN_PASS_INITIALIZER;
    p67_err err;
    const char * keypath = "p2pcert";
    const char * certpath = "p2pcert.cert";
    const char * remote_ip = IP4_LO1;
    pass.local.rdonly = 1;
    pass.remote.rdonly = 1;
    pass.certpath = (char *)certpath;
    pass.keypath = (char *)keypath;
    pass.handler = process_message;
    p67_pdp_keepalive_ctx_t kctx = {
        .th = P67_THREAD_SM_INITIALIZER,
        .pass = &pass
    };
    
    signal(SIGINT, finish);

    if(argc < 3) {
        printf("Usage: ./%s [source port] [dest port]\n", argv[0]);
        return 2;
    }

    p67_lib_init();

    if((err = p67_addr_set_localhost4_udp(&pass.local, argv[1])) != 0)
        goto end;

    if((err = p67_addr_set_host_udp(&pass.remote, remote_ip, argv[2])))
        goto end;

    if((err = p67_net_start_persist_connect(&pass)) != 0) goto end;

    if((err = p67_pdp_start_keepalive_loop(&kctx)) != 0) goto end;

    p67_hashcntl_t * commands = p67_hashcntl_new(0, free_command, NULL);
    if(!commands) {
        err = p67_err_eerrno;
        goto end;
    }
    if((err = add_command(commands, "echo", echo)) != 0) goto end;
    if((err = add_command(commands, "exit", c_exit)) != 0) goto end;
    if((err = add_command(commands, "call", call)) != 0) goto end;
    if((err = add_command(commands, "login", login)) != 0) goto end;

    while(login(&pass, 0, NULL));

    char n[120];
    char ** _argv, * argvbuf;
    int _argc, argvbufix = 0;
    size_t nl, i, j, lv, _argvl = 0, argvbufl = 0;
    int offset;
    char tmp;
    int rd;
    p67_hashcntl_entry_t * entry;

    while(1) {
       
        nl = 0;

        printf("> ");

        while((tmp = getchar()) != EOF && tmp != '\n') {
            if(nl >= (sizeof(n) - 1))
                break;
            n[nl++] = tmp;
        }

        if(nl < 1)
            continue;
        
        rd = 0;
        _argc = 0;

        for(i = 0; i < nl; i++) {
            if(rd && ((n[i] == ' ') || (i == nl - 1))) {
                _argc++;
                rd = 0;
            } else if(n[i] != ' ') {
                rd = 1;
                if(i == nl - 1)
                    i--;
            } else {
                rd = 0;
            }
        }

        _argvl = sizeof(void *)*_argc;
        _argv = malloc(_argvl);
        argvbufl = nl + _argc;
        argvbuf = malloc(argvbufl);
        
        if(!_argv || !argvbuf) {
            err = p67_err_eerrno;
            goto end;
        }

        argvbufix = 0;
        rd = 0;
        j = 0;

        for(i = 0; i < nl; i++) {
            if(rd && ((n[i] == ' ') || (i == nl - 1))) {
                if(n[i] == ' ') offset = 1;
                else offset = 0;
                _argv[j++] = argvbuf+argvbufix;
                memcpy(argvbuf+argvbufix, n+lv, i + 1 - offset - lv);
                argvbufix+= i + 1 - offset - lv;
                argvbuf[argvbufix++] = '\0';
                rd = 0;
            } else if(n[i] != ' ') {
                if(!rd) {
                    rd = 1;
                    lv = i;
                }
                if(i == nl - 1)
                    i--;
            } else {
                rd = 0;
            }
        }

        entry = p67_hashcntl_lookup(commands, _argv[0], strlen(_argv[0]));
        if(entry) {
            ((command_hndl)entry->value)(&pass, _argc, _argv);
        } else {
            printf("command: \"%s\" not found.\n", _argv[0]);
        }

        free(_argv);
        free(argvbuf);

        // if((err = call(&pass)) != 0) {
        //     p67_err_print_err("call: ", err);
        // }
    }

end:
    if(err != 0) p67_err_print_err("Main: ", err);
    p67_lib_free();
    if(err == 0) return 0; else return 2;
}

// struct p67rs_session {
//     int sessid;
//     p67_async_t state;
// };

// volatile int sessid = 0;

// void * create_rs_session(void * args);
// void * create_rs_session(void * args)
// {
//     (void)args;
    
//     struct p67rs_session * p = calloc(1, sizeof(struct p67rs_session));
//     if(p == NULL) {
//         p67_err_print_err("ERR in create client session: ", p67_err_eerrno);
//         exit(2);
//     }
//     p->sessid=(sessid++);
//     return p;
// }

// void free_rs_session(void * s);
// void free_rs_session(void * s)
// {
//     free(s);
// }

